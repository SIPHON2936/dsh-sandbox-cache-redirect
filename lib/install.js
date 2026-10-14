/**
 * Binary identity queries and the atomic runner installer.
 *
 * Install semantics (V6.2 manual §5, hardened):
 *   - staging file in the final audited directory, O_RDWR|O_CREAT|O_EXCL|
 *     O_NOFOLLOW, mode 0600; write, fsync, positioned read-back digest from
 *     offset 0, fchmod 0500, fsync again;
 *   - publish with link(staging, target) — EEXIST fails, never overwrites;
 *   - an existing target is reused only when it is a same-digest, user-owned,
 *     mode-0500, single-link regular file, opened O_RDONLY|O_NOFOLLOW and
 *     re-statted on the same fd;
 *   - failure cleanup removes only this run's staging file, and only when its
 *     dev/ino still match what we created.
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fail } from "./trust.js";

export function sha256(data) {
	return createHash("sha256").update(data).digest("hex");
}

const SPAWN_OPTIONS = { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 10000 };

function spawnChecked(argv, what) {
	const out = spawnSync(argv[0], argv.slice(1), SPAWN_OPTIONS);
	if (out.error) fail(`${what} query failed to spawn: ${out.error.message}`);
	if (out.signal) fail(`${what} query terminated by signal ${out.signal}`);
	if (out.status !== 0) fail(`${what} query exited ${out.status}: ${String(out.stderr).trim()}`);
	return out.stdout;
}

/** python3 -IS flag sanity plus the stdlib location (a protected tree). Runs only after the binary audit. */
export function queryPythonInfo(resolvedPython) {
	const stdout = spawnChecked(
		[resolvedPython, "-IS", "-c", "import json,sys,sysconfig;print(json.dumps([sys.flags.isolated,sys.flags.no_site,sys.version.split()[0],sysconfig.get_path('stdlib')]))"],
		"python3 -IS",
	);
	let parsed;
	try {
		parsed = JSON.parse(stdout);
	} catch {
		fail(`python3 -IS query returned unparseable output: ${JSON.stringify(stdout)}`);
	}
	const [isolated, noSite, version, stdlib] = parsed;
	if (isolated !== 1 || noSite !== 1) fail(`python3 -IS flags abnormal (isolated=${isolated}, no_site=${noSite})`);
	if (typeof stdlib !== "string" || !path.isAbsolute(stdlib)) fail(`python3 stdlib path abnormal: ${stdlib}`);
	return { version, stdlib };
}

/** bwrap version gate: upstream >= 0.12.0 carries the CVE-2026-87766 fix. Runs only after the setuid/identity audit. */
export function queryBwrapVersion(resolvedBwrap) {
	const stdout = spawnChecked([resolvedBwrap, "--version"], "bwrap --version");
	const match = /(\d+)\.(\d+)\.(\d+)/.exec(stdout);
	if (!match) fail(`unparseable bwrap version output: ${JSON.stringify(stdout)}`);
	const found = match.slice(1).map(Number);
	const minimum = [0, 12, 0];
	for (let i = 0; i < 3; i++) {
		if (found[i] > minimum[i]) return found.join(".");
		if (found[i] < minimum[i]) fail(`bwrap ${found.join(".")} is below the security floor ${minimum.join(".")} (CVE-2026-87766)`);
	}
	return found.join(".");
}

const RUNNER_MODE = 0o500;

/** Verify an already-published runner and return its identity, or fail with the reason it cannot be used. */
export function verifyPublishedRunner(target, expectedSha256) {
	const lst = fs.lstatSync(target);
	if (!lst.isFile()) fail(`runner is not a regular file: ${target}`);
	if (lst.uid !== process.getuid()) fail(`runner owned by uid ${lst.uid}, expected ${process.getuid()}: ${target}`);
	if ((lst.mode & 0o777) !== RUNNER_MODE) fail(`runner mode is ${(lst.mode & 0o777).toString(8)}, expected 500: ${target}`);
	const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	try {
		const fst = fs.fstatSync(fd);
		if (fst.dev !== lst.dev || fst.ino !== lst.ino) fail(`runner changed while being verified: ${target}`);
		if (!fst.isFile()) fail(`runner is not a regular file: ${target}`);
		if (fst.nlink !== 1) fail(`runner has ${fst.nlink} names (nlink>1): ${target}`);
		const data = fs.readFileSync(fd);
		const digest = sha256(data);
		if (digest !== expectedSha256) fail(`runner digest mismatch at ${target}: ${digest} (expected ${expectedSha256}); refusing to overwrite — choose a new versioned path`);
		return { dev: fst.dev, ino: fst.ino, uid: fst.uid, mode: RUNNER_MODE, nlink: 1, digest };
	} finally {
		fs.closeSync(fd);
	}
}

/** Per-call re-verification: the published runner must still be the same intact inode with the same bytes. */
export function reverifyRunnerIdentity(target, identity) {
	const lst = fs.lstatSync(target);
	if (!lst.isFile()) fail(`runner is no longer a regular file: ${target}`);
	const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	try {
		const fst = fs.fstatSync(fd);
		if (fst.dev !== identity.dev || fst.ino !== identity.ino) fail(`runner inode changed since activation: ${target}`);
		if (!fst.isFile() || fst.uid !== identity.uid || (fst.mode & 0o777) !== RUNNER_MODE || fst.nlink !== 1) {
			fail(`runner identity drifted (mode/uid/nlink): ${target}`);
		}
		if (sha256(fs.readFileSync(fd)) !== identity.digest) fail(`runner content changed since activation: ${target}`);
	} finally {
		fs.closeSync(fd);
	}
}

/** Per-call binary check: resolution, inode and privilege bits must not have changed since activation. */
export function reverifyBinary(binary, label) {
	let resolved;
	try {
		resolved = fs.realpathSync(binary.nominal);
	} catch (error) {
		fail(`cannot re-resolve ${label} ${binary.nominal}: ${error.message}`);
	}
	if (resolved !== binary.resolved) fail(`${label} resolution changed: ${binary.nominal} -> ${resolved} (was ${binary.resolved})`);
	const st = fs.lstatSync(resolved);
	if (st.dev !== binary.dev || st.ino !== binary.ino) fail(`${label} was replaced since activation: ${resolved}`);
	if ((st.mode & 0o6000) !== 0) fail(`${label} gained setuid/setgid bits since activation: ${resolved}`);
	if ((st.mode & 0o022) !== 0) fail(`${label} became group/world-writable since activation: ${resolved}`);
}

/**
 * Install the runner atomically, or reuse a verified existing one.
 * Returns the runner identity recorded in the provider state.
 */
export function installOrReuseRunner({ sourceBytes, target, expectedSha256 }) {
	const existing = fs.lstatSync(target, { throwIfNoEntry: false });
	if (existing !== undefined) {
		const identity = verifyPublishedRunner(target, expectedSha256);
		return { action: "reused", identity };
	}
	const directory = path.dirname(target);
	const staging = path.join(directory, `.dsh-bwrap-redirect.staging-${process.pid}-${randomBytes(8).toString("hex")}`);
	let staged = null;
	try {
		const fd = fs.openSync(staging, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
		try {
			fs.writeFileSync(fd, sourceBytes);
			fs.fsyncSync(fd);
			const readBack = Buffer.alloc(sourceBytes.length);
			const read = fs.readSync(fd, readBack, 0, readBack.length, 0);
			if (read !== readBack.length || sha256(readBack) !== expectedSha256) fail("staging read-back digest mismatch");
			fs.fchmodSync(fd, RUNNER_MODE);
			fs.fsyncSync(fd);
			const fst = fs.fstatSync(fd);
			staged = { dev: fst.dev, ino: fst.ino };
		} finally {
			fs.closeSync(fd);
		}
		try {
			fs.linkSync(staging, target);
		} catch (error) {
			if (error.code === "EEXIST") fail(`runner appeared concurrently at ${target}; refusing to overwrite`);
			fail(`cannot publish runner to ${target}: ${error.message}`);
		}
		fs.unlinkSync(staging);
		staged = null;
		const identity = verifyPublishedRunner(target, expectedSha256);
		return { action: "installed", identity };
	} finally {
		if (staged !== null) {
			try {
				const st = fs.lstatSync(staging);
				if (st.dev === staged.dev && st.ino === staged.ino) fs.unlinkSync(staging);
			} catch { /* staging already gone or replaced by someone else — leave it for manual inspection */ }
		}
	}
}
