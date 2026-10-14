/**
 * dsh-sandbox-cache-redirect — Host installer plugin for the V6.2 bwrap runner.
 *
 * What this plugin does at activation (and nothing else):
 *   1. Preflight the host: Linux, /usr/bin/python3 and /usr/bin/bwrap present,
 *      bwrap >= 0.12.0 (CVE-2026-87766 fix floor from the V6.2 manual §3.2).
 *   2. Verify the SHA-256 of the bundled runner source byte-for-byte.
 *   3. Install the runner to the trusted versioned location
 *      $HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad with the
 *      manual §5 semantics: exclusive create, mode 0500, no symlink following;
 *      an existing file is reused only when it is a same-content, user-owned,
 *      not group/world-writable regular file — never overwritten.
 *   4. Re-verify the installed file (digest + mode) and audit the trust chain
 *      (every ancestor directory owned by root or the current user, never
 *      group/world-writable; symlinks are reported).
 *
 * The bundle patch (cordis.patch.yml) separately points the sandbox provider's
 * runnerCommand at that trusted path. If any check above fails, this plugin
 * throws during load: the runnerCommand then names a missing/uncertified file,
 * the runner fails closed, and no command ever runs unconfined because of us.
 *
 * Trust model (V6.2 manual §3.1): this plugin runs inside the trusted Host
 * process; the shipped tarball is installed into the profile's node_modules,
 * outside every managed workspace. The runner is the only confined-exec
 * boundary object; it strictly matches the DSH 0.2.1-alpha.2 bwrap profile
 * templates and rejects anything unknown.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Pinned identity of the bundled runner (V6.2 manual §5). */
const RUNNER_SHA256 = "0ef04d1a72ad9aa31a00e212246e8fb6765ed1948b74c654af8ce5e99b579216";
/** Versioned runner file name; bump the digest tag instead of overwriting. */
const RUNNER_FILE_NAME = "dsh-bwrap-redirect-v6-0ef04d1a72ad";
const PYTHON = "/usr/bin/python3";
const BWRAP = "/usr/bin/bwrap";
/** bwrap security floor: upstream >= 0.12.0 with the CVE-2026-87766 fix. */
const BWRAP_MIN_VERSION = [0, 12, 0];

function sha256(data) {
	return createHash("sha256").update(data).digest("hex");
}

function fail(message) {
	throw new Error(`dsh-sandbox-cache-redirect: ${message}`);
}

/** Resolve the trusted runner path exactly as the bundle patch's !!js does. */
export function runnerTargetPath(env = process.env) {
	const home = env.HOME;
	if (!home || !path.isAbsolute(home)) fail("HOME is unset or not absolute; cannot anchor the trusted runner path");
	return path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
}

function assertExecutable(file) {
	try {
		fs.accessSync(file, fs.constants.X_OK);
	} catch {
		fail(`required executable missing or not executable: ${file}`);
	}
}

/** Parse `bubblewrap X.Y.Z` and require the security floor. */
function assertBwrapVersion() {
	const out = spawnSync(BWRAP, ["--version"], { encoding: "utf8", timeout: 10000 });
	if (out.error || out.status !== 0) fail(`cannot run ${BWRAP} --version: ${out.error?.message ?? out.stderr?.trim()}`);
	const match = /(\d+)\.(\d+)\.(\d+)/.exec(out.stdout ?? "");
	if (!match) fail(`unparseable bwrap version output: ${JSON.stringify(out.stdout)}`);
	const found = match.slice(1).map(Number);
	const min = BWRAP_MIN_VERSION;
	for (let i = 0; i < 3; i++) {
		if (found[i] > min[i]) return found.join(".");
		if (found[i] < min[i]) fail(`bwrap ${found.join(".")} is below the security floor ${min.join(".")} (CVE-2026-87766)`);
	}
	return found.join(".");
}

/**
 * Install with the V6.2 manual §5 semantics. Never overwrites an existing
 * file; reuses it only when identity and permission bits prove equivalent.
 */
function installRunner(sourceBytes, target) {
	fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
	let fd;
	try {
		fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o500);
	} catch (error) {
		if (error.code !== "EEXIST") fail(`cannot create ${target}: ${error.message}`);
		const st = fs.lstatSync(target);
		if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o022) !== 0) {
			fail(`unsafe existing runner at ${target}; refusing to reuse (mode ${(st.mode & 0o777).toString(8)}, uid ${st.uid})`);
		}
		if (sha256(fs.readFileSync(target)) !== RUNNER_SHA256) {
			fail(`existing runner at ${target} has different content; choose a new versioned path instead of overwriting`);
		}
		return "reused";
	}
	try {
		fs.writeFileSync(fd, sourceBytes);
		fs.fchmodSync(fd, 0o500);
	} finally {
		fs.closeSync(fd);
	}
	return "installed";
}

/** Post-install proof: regular file, pinned digest, no group/other write. */
function verifyInstalled(target) {
	const st = fs.lstatSync(target);
	if (!st.isFile()) fail(`installed runner is not a regular file: ${target}`);
	if ((st.mode & 0o022) !== 0) fail(`installed runner is group/world-writable: ${target}`);
	const digest = sha256(fs.readFileSync(target));
	if (digest !== RUNNER_SHA256) fail(`installed runner digest mismatch: ${digest}`);
	return { mode: (st.mode & 0o777).toString(8), digest };
}

/**
 * Automated approximation of the manual's `namei -l` trust audit: every
 * ancestor of the resolved target must be a root- or user-owned directory
 * without group/other write permission.
 */
function auditTrustChain(target, logger) {
	const nominalParent = path.dirname(target);
	const realParent = fs.realpathSync(nominalParent);
	if (realParent !== nominalParent) logger.warn(`runner parent resolves through a symlink: ${nominalParent} -> ${realParent}`);
	let current = realParent;
	while (true) {
		const st = fs.lstatSync(current);
		if (!st.isDirectory()) fail(`trust chain component is not a directory: ${current}`);
		if ((st.mode & 0o022) !== 0) fail(`trust chain component is group/world-writable: ${current}`);
		if (st.uid !== 0 && st.uid !== process.geteuid()) fail(`trust chain component owned by untrusted uid ${st.uid}: ${current}`);
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
	}
}

export function apply(ctx) {
	const logger = ctx.logger;
	if (process.platform !== "linux") {
		fail(`this bundle supports Linux only (platform is ${process.platform}); disable it instead of running unconfined`);
	}
	assertExecutable(PYTHON);
	assertExecutable(BWRAP);
	const bwrapVersion = assertBwrapVersion();

	const sourcePath = fileURLToPath(new URL("./runner/dsh-bwrap-redirect", import.meta.url));
	const sourceBytes = fs.readFileSync(sourcePath);
	const sourceDigest = sha256(sourceBytes);
	if (sourceDigest !== RUNNER_SHA256) {
		fail(`bundled runner digest mismatch: ${sourceDigest} (expected ${RUNNER_SHA256}); the package is corrupted — do not proceed`);
	}

	const target = runnerTargetPath();
	const action = installRunner(sourceBytes, target);
	const { mode, digest } = verifyInstalled(target);
	auditTrustChain(target, logger);

	logger.info("bwrap %s cleared the security floor; runner %s (%s, mode %s, sha256 %s…)", bwrapVersion, action, target, mode, digest.slice(0, 12));
	logger.info("sandbox runnerCommand is pinned to this runner; workspace-write commands get workspace-local uv/pip/npm/Go caches (V6.2)");
}
