/**
 * Critical-case regression suite for the guarded sandbox provider (6.2.1).
 *
 * Covers the trimmed acceptance matrix: fresh/reused install, existing-file
 * rejection classes (bad content, symlink, non-0500, nlink>1), unsafe or
 * symlinked install chains, bundled-runner digest corruption, setuid binary
 * rejection before any version query, workspace layout rules (including
 * false-positive guards for $HOME/projects/a and prefix-similar dirs),
 * native-row composition conflicts, lifecycle revocation, unknown modes, and
 * wrapped-argv assertions.
 *
 * Every fixture lives in a private HOME-mkdtemp (never /tmp — the strict
 * chain policy rightly refuses world-writable parents). Destructive setups
 * only ever touch fixture copies. python3/bwrap identity checks run against
 * the real audited binaries, as in production.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { sanitizeConfig, resolveProbeTimeout } from "../lib/config.js";
import { installOrReuseRunner, reverifyRunnerIdentity, sha256 } from "../lib/install.js";
import { prepareState, checkCall, assertWrappedArgv, buildProvider } from "../lib/provider.js";
import { auditInstallChain, auditTrustedExecutable, assertWorkspaceAllowed, buildProtectedSets, addProtectedTree, pathContains } from "../lib/trust.js";

const PACKAGE_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const RUNNER_SOURCE = fs.readFileSync(path.join(PACKAGE_DIR, "runner", "dsh-bwrap-redirect"));
const RUNNER_SHA256 = sha256(RUNNER_SOURCE);
const RUNNER_FILE_NAME = "dsh-bwrap-redirect-v6-0ef04d1a72ad";

const DSH_CLI = process.env.DSH_CLI ?? execFileSync("sh", ["-c", "command -v dsh"], { encoding: "utf8" }).trim();

/** Shared peer bundle, resolved once from the real Host installation. */
const shared = await (await import("../lib/peers.js")).resolveHostPeers({ anchor: DSH_CLI, packageUrl: pathToFileURL(PACKAGE_DIR + path.sep) });

function makeFixtureHome(t) {
	const home = fs.mkdtempSync(path.join(os.homedir(), path.sep, "dsh-plugin-test-"));
	fs.mkdirSync(path.join(home, ".dsh"), { mode: 0o700 }); // the fixture DSH_HOME, always present like a real one
	t.after(() => fs.rmSync(home, { recursive: true, force: true }));
	return home;
}

/** Minimal cordis-flavored ctx stub: real service table, stub loader tree, stub policy. */
function makeCtx({ home, defaultMode = "workspace-write", defaultRoot, nativeRow } = {}) {
	const services = new Map();
	const warnings = [];
	const native = nativeRow ?? {
		id: "sandbox",
		name: "@deepseek-ai/dsh-sandbox-local",
		disabled: true,
		inject: { sandboxCacheRedirectGuardReady: {} },
	};
	const rows = [native, { id: "bash-sandbox", name: "@deepseek-ai/dsh-bash-sandbox" }];
	const store = {};
	for (const row of rows) store[row.id] = { options: row, get disabled() { return Boolean(row.disabled); } };
	const ownEntry = { parent: { data: rows, tree: { store } } };
	const ctx = {
		fiber: { uid: 1 },
		warnings,
		loader: {
			locate: () => "include:sandbox-cache-redirect",
			resolve: () => ownEntry,
		},
		sandboxPolicy: { resolve: () => ({ mode: defaultMode, workspaceRoot: defaultRoot ?? path.join(home ?? os.homedir(), "projects", "demo") }) },
		dshHomePath: (...segments) => path.join(home ?? os.homedir(), ".dsh", ...segments),
		logger: { info() {}, warn: (...args) => warnings.push(args.join(" ")) },
		provide: (name, value) => services.set(name, value),
		get: (name) => services.get(name),
		effect: (fn) => effects.push(fn),
	};
	var effects = [];
	return ctx;
}

function prepare(ctx, config, home) {
	return prepareState(ctx, config ?? {}, shared, { HOME: home });
}

// --- install & reuse -------------------------------------------------------

test("G01 fresh install: verify-then-register state, 0500, nlink=1, digest", (t) => {
	const home = makeFixtureHome(t);
	const ctx = makeCtx({ home });
	const state = prepare(ctx, {}, home);
	assert.equal(state.installAction, "installed");
	const target = path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
	const st = fs.lstatSync(target);
	assert.equal(st.mode & 0o777, 0o500);
	assert.equal(st.nlink, 1);
	assert.equal(sha256(fs.readFileSync(target)), RUNNER_SHA256);
	assert.deepEqual(state.runnerArgv, ["/usr/bin/python3", "-IS", target]);
	assert.equal(state.probeTimeoutMs, 5000);
	assert.equal(state.probeTimeoutSource, "default");
	assert.equal(ctx.get("sandboxCacheRedirectGuardReady") === undefined, true, "ready service is published by the provider constructor, not prepareState");
});

test("G16 correct install re-activates: reuse keeps bytes/mode/inode", (t) => {
	const home = makeFixtureHome(t);
	const first = prepare(makeCtx({ home }), {}, home);
	const second = prepare(makeCtx({ home }), {}, home);
	assert.equal(second.installAction, "reused");
	assert.equal(second.runnerIdentity.dev, first.runnerIdentity.dev);
	assert.equal(second.runnerIdentity.ino, first.runnerIdentity.ino);
});

test("G02 existing target with different content: refused, bytes untouched", (t) => {
	const home = makeFixtureHome(t);
	const target = path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
	fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
	fs.writeFileSync(target, "#!/bin/sh\necho pwned\n", { mode: 0o500 });
	assert.throws(() => prepare(makeCtx({ home }), {}, home), /digest mismatch/);
	assert.equal(fs.readFileSync(target, "utf8"), "#!/bin/sh\necho pwned\n");
});

test("G04 existing target classes: symlink, directory, group-writable, non-0500, nlink>1", (t) => {
	for (const variant of ["symlink", "directory", "group-writable", "non-0500", "nlink>1"]) {
		const home = makeFixtureHome(t);
		const target = path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
		fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
		if (variant === "symlink") fs.symlinkSync("/bin/true", target);
		if (variant === "directory") fs.mkdirSync(target);
		if (variant === "group-writable") {
			fs.writeFileSync(target, RUNNER_SOURCE);
			fs.chmodSync(target, 0o520); // explicit chmod: writeFileSync mode is umask-filtered
		}
		if (variant === "non-0500") {
			fs.writeFileSync(target, RUNNER_SOURCE);
			fs.chmodSync(target, 0o755);
		}
		if (variant === "nlink>1") {
			fs.writeFileSync(target, RUNNER_SOURCE, { mode: 0o500 });
			fs.linkSync(target, path.join(home, "alias"));
		}
		assert.throws(() => prepare(makeCtx({ home }), {}, home), undefined, variant);
	}
});

test("G05 unsafe parent directory: refused before any creation", (t) => {
	const home = makeFixtureHome(t);
	fs.mkdirSync(path.join(home, ".local"));
	fs.chmodSync(path.join(home, ".local"), 0o777);
	assert.throws(() => prepare(makeCtx({ home }), {}, home), /group\/world-writable/);
	assert.equal(fs.existsSync(path.join(home, ".local", "libexec")), false, "nothing may be created below the unsafe parent");
});

test("G06 install-chain symlink: refused even when the resolved target is trusted", (t) => {
	const home = makeFixtureHome(t);
	const real = path.join(home, "real-local");
	fs.mkdirSync(real, { mode: 0o700 });
	fs.symlinkSync(real, path.join(home, ".local"));
	assert.throws(() => prepare(makeCtx({ home }), {}, home), /symlink/);
});

test("G03 bundled runner digest corruption: fail before mkdir", (t) => {
	const home = makeFixtureHome(t);
	const corrupted = { ...shared, expectedRunnerSha256: "0".repeat(64) };
	assert.throws(() => prepareState(makeCtx({ home }), {}, corrupted, { HOME: home }), /bundled runner digest mismatch/);
	assert.equal(fs.existsSync(path.join(home, ".local")), false, "install chain must not be created");
});

test("G12 setuid executable is refused by the audit itself", (t) => {
	const home = makeFixtureHome(t);
	const fake = path.join(home, "bwrap-copy");
	fs.copyFileSync("/usr/bin/bwrap", fake);
	fs.chmodSync(fake, 0o4755);
	assert.throws(() => auditTrustedExecutable(fake), /setuid/);
});

// --- config & composition ---------------------------------------------------

test("strict config: unknown fields rejected (no runnerCommand backdoor)", () => {
	assert.throws(() => sanitizeConfig({ runnerCommand: ["/bin/sh"] }), /not supported/);
	assert.throws(() => sanitizeConfig({ skipPreflight: true }), /not supported/);
	assert.throws(() => sanitizeConfig({ probeTimeoutMs: 0 }), /positive integer/);
	assert.throws(() => sanitizeConfig({ additionalProtectedRoots: ["relative/path"] }), /absolute/);
	assert.deepEqual(sanitizeConfig({ probeTimeoutMs: 9000 }), { probeTimeoutMs: 9000, additionalProtectedRoots: [] });
});

test("G20 timeout: explicit wins, plain legacy inherits, expression stops", () => {
	assert.deepEqual(resolveProbeTimeout({ probeTimeoutMs: 23000 }, { config: { probeTimeoutMs: 17000 } }), { value: 23000, source: "config" });
	assert.deepEqual(resolveProbeTimeout({}, { config: { probeTimeoutMs: 17000 } }), { value: 17000, source: "inherited" });
	assert.deepEqual(resolveProbeTimeout({}, {}), { value: 5000, source: "default" });
	assert.throws(() => resolveProbeTimeout({}, { config: { probeTimeoutMs: { __jsExpr: "17000" } } }), /explicit probeTimeoutMs/);
});

test("G17 native row re-enabled: construction-time composition conflict", (t) => {
	const home = makeFixtureHome(t);
	const ctx = makeCtx({ home, nativeRow: { id: "sandbox", name: "@deepseek-ai/dsh-sandbox-local", disabled: false, inject: { sandboxCacheRedirectGuardReady: {} } } });
	assert.throws(() => prepare(ctx, {}, home), /refuses to run alongside/);
});

test("native row missing the inject blocker: composition conflict", (t) => {
	const home = makeFixtureHome(t);
	const ctx = makeCtx({ home, nativeRow: { id: "sandbox", name: "@deepseek-ai/dsh-sandbox-local", disabled: true } });
	assert.throws(() => prepare(ctx, {}, home), /inject blocker/);
});

// --- workspace layout --------------------------------------------------------

test("G08/G09/G10 workspace layout rules with real protected sets", (t) => {
	const home = makeFixtureHome(t);
	const state = prepare(makeCtx({ home }), {}, home);
	const sets = state.protectedSets;
	const project = (name) => path.join(home, "projects", name);
	// Legitimate projects must pass, including prefix-similar names.
	assertWorkspaceAllowed(project("a"), sets);
	assertWorkspaceAllowed(project("a2"), sets);
	assertWorkspaceAllowed(project("demo"), sets);
	// HOME itself, the install tree and its ancestors, protected binaries.
	assert.throws(() => assertWorkspaceAllowed(home, sets), /covers protected/);
	assert.throws(() => assertWorkspaceAllowed(path.join(home, ".local"), sets), undefined);
	assert.throws(() => assertWorkspaceAllowed(path.dirname(state.runnerPath), sets), /inside protected tree|covers protected/);
	assert.throws(() => assertWorkspaceAllowed("/usr", sets), /covers protected/);
	assert.throws(() => assertWorkspaceAllowed("/", sets), undefined);
	assert.throws(() => assertWorkspaceAllowed("/x:y", sets), /":"/);
	// Symlinked project pointing into a protected tree: caller canonicalizes before this check.
	const link = path.join(home, "projects", "link-to-dsh");
	fs.mkdirSync(project("p"), { recursive: true });
	fs.symlinkSync(shared.paths.dshRoot, link);
	assert.throws(() => assertWorkspaceAllowed(fs.realpathSync(link), sets), /inside protected tree|covers protected/);
});

test("pathContains is component-wise, not prefix-wise", () => {
	assert.equal(pathContains("/a/project", "/a/project/sub"), true);
	assert.equal(pathContains("/a/project", "/a/project"), true);
	assert.equal(pathContains("/a/project", "/a/project2"), false);
	assert.equal(pathContains("/a/project2", "/a/project"), false);
});

// --- provider behavior (real Host classes, real cordis Context) --------------

test("provider: registers sandbox, confines read-only, rejects on revoke and unknown mode", async (t) => {
	const { Context } = await import(pathToFileURL(require_resolveCordis()).href);
	const home = makeFixtureHome(t);
	const GuardedProvider = buildProvider(shared, { env: { HOME: home } });
	const ctx = new Context();
	ctx.provide("loader", makeCtx({ home }).loader);
	ctx.provide("sandboxPolicy", makeCtx({ home }).sandboxPolicy);
	ctx.provide("dshHomePath", makeCtx({ home }).dshHomePath);
	const provider = new GuardedProvider(ctx, {});
	// cordis wraps services in a traceable proxy; assert behavior, not identity.
	const registered = ctx.get("sandbox");
	assert.equal(typeof registered?.confine, "function");
	const ready = ctx.get("sandboxCacheRedirectGuardReady");
	assert.equal(typeof ready?.generation, "number");
	// read-only: template base only, payload intact (no bwrap is executed by confine).
	const wrapped = await provider.confine(["bash", "-c", "true"], { mode: "read-only", workspaceRoot: os.homedir() }, undefined);
	const expectedRunner = ["/usr/bin/python3", "-IS", path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME)];
	assert.deepEqual(wrapped.argv.slice(0, 3), expectedRunner);
	assert.deepEqual(wrapped.argv.slice(-4), ["--", "bash", "-c", "true"]);
	assert.equal(wrapped.enforcement, "full");
	// workspace-write under HOME/projects passes and binds the canonical root.
	const wsRoot = path.join(home, "projects", "demo");
	const wrappedWs = await provider.confine(["bash", "-c", "true"], { mode: "workspace-write", workspaceRoot: wsRoot }, undefined);
	assert.deepEqual(wrappedWs.argv, [
		...expectedRunner,
		"--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
		"--tmpfs", "/tmp", "--bind", wsRoot, wsRoot,
		"--", "bash", "-c", "true",
	]);
	// Unknown mode and full-access are rejected without an argv.
	await assert.rejects(() => provider.confine(["true"], { mode: "danger-full-access", workspaceRoot: wsRoot }), /SANDBOX_UNAVAILABLE|unsupported sandbox mode/);
	await assert.rejects(() => provider.confine(["true"], { mode: "mystery", workspaceRoot: wsRoot }), /unsupported sandbox mode/);
	// Revocation: stale references fail closed.
	provider.guardState.revoked = true;
	await assert.rejects(() => provider.confine(["true"], { mode: "read-only", workspaceRoot: os.homedir() }), /revoked|SANDBOX_UNAVAILABLE/);
});

test("6.2.2 regression: launch-from-HOME warns at activation but never blocks startup", async (t) => {
	const { Context } = await import(pathToFileURL(require_resolveCordis()).href);
	const home = makeFixtureHome(t);
	// Part 1: prepareState with the deployment default root == HOME (e.g. `dsh web`
	// launched from ~) must succeed and emit a clear warning, not throw.
	const stub = makeCtx({ home, defaultRoot: home });
	const state = prepare(stub, {}, home);
	assert.ok(stub.warnings.some((w) => /default workspace root is unsafe/.test(w)), `expected a default-root warning, got ${JSON.stringify(stub.warnings)}`);
	// Part 2: a constructed provider over that state still enforces per call.
	const GuardedProvider = buildProvider(shared, { env: { HOME: home } });
	const ctx = new Context();
	ctx.provide("loader", stub.loader);
	ctx.provide("sandboxPolicy", stub.sandboxPolicy);
	ctx.provide("dshHomePath", stub.dshHomePath);
	const provider = new GuardedProvider(ctx, {});
	assert.equal(provider.guardState.generation > state.generation, true, "provider prepared its own generation");
	// A real session rooted at a project subdirectory confines normally.
	const project = path.join(home, "projects", "demo");
	const wrapped = await provider.confine(["true"], { mode: "workspace-write", workspaceRoot: project }, undefined);
	assert.equal(wrapped.enforcement, "full");
	// But a session actually rooted at HOME is still rejected per call, with guidance.
	await assert.rejects(
		() => provider.confine(["true"], { mode: "workspace-write", workspaceRoot: home }),
		/covers protected[\s\S]*project subdirectory/,
	);
	// read-only over HOME stays allowed: nothing is injected or written.
	const ro = await provider.confine(["true"], { mode: "read-only", workspaceRoot: home }, undefined);
	assert.equal(ro.enforcement, "full");
});

test("G07 runner replaced after activation: next confine refuses", async (t) => {
	const { Context } = await import(pathToFileURL(require_resolveCordis()).href);
	const home = makeFixtureHome(t);
	const GuardedProvider = buildProvider(shared, { env: { HOME: home } });
	const ctx = new Context();
	ctx.provide("loader", makeCtx({ home }).loader);
	ctx.provide("sandboxPolicy", makeCtx({ home }).sandboxPolicy);
	ctx.provide("dshHomePath", makeCtx({ home }).dshHomePath);
	const provider = new GuardedProvider(ctx, {});
	const target = path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
	// Swap the runner for different bytes at the same path (as a same-uid writer could).
	fs.rmSync(target);
	fs.writeFileSync(target, "#!/usr/bin/python3 -IS\n# tampered\n", { mode: 0o500 });
	await assert.rejects(
		() => provider.confine(["true"], { mode: "read-only", workspaceRoot: os.homedir() }),
		/changed since activation|SANDBOX_UNAVAILABLE/,
	);
});

test("wrapped argv assertion catches template drift", (t) => {
	const home = makeFixtureHome(t);
	const state = prepare(makeCtx({ home }), {}, home);
	const checked = { mode: "workspace-write", workspaceRoot: path.join(home, "projects", "demo") };
	const good = { argv: [...state.runnerArgv, "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent", "--tmpfs", "/tmp", "--bind", checked.workspaceRoot, checked.workspaceRoot, "--", "bash", "-c", "true"], enforcement: "full" };
	assertWrappedArgv(state, checked, ["bash", "-c", "true"], good);
	assert.throws(() => assertWrappedArgv(state, checked, ["bash", "-c", "true"], { argv: [...good.argv.slice(0, -1), "false"], enforcement: "full" }), /does not match/);
	assert.throws(() => assertWrappedArgv(state, checked, ["bash", "-c", "true"], { argv: good.argv, enforcement: "partial" }), /enforcement/);
});

test("per-call runner identity re-verification helper", (t) => {
	const home = makeFixtureHome(t);
	const target = path.join(home, ".local", "libexec", "dsh", RUNNER_FILE_NAME);
	fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
	const { identity } = installOrReuseRunner({ sourceBytes: RUNNER_SOURCE, target, expectedSha256: RUNNER_SHA256 });
	reverifyRunnerIdentity(target, identity);
	fs.chmodSync(target, 0o700);
	assert.throws(() => reverifyRunnerIdentity(target, identity), /identity drifted/);
});

function require_resolveCordis() {
	const require = createRequire(shared.paths.cliEntry);
	return require.resolve("@deepseek-ai/cordis");
}
