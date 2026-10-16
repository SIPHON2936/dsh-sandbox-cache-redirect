/**
 * CacheRedirectProvider behavior tests against the REAL Host classes with
 * controlled probes (acceptance matrix M-level: G06–G09, G13, G15, G16,
 * G24, G33, G34, G36), plus one tolerant real-chain selection test.
 *
 * Controlled probes are the documented M-level mechanism; real Landlock and
 * real target sessions are covered separately (P/T levels). Fixtures live
 * in private HOME-mkdtemp trees and never touch the real DSH_HOME.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { dispose, makeCtx, makeFixtureHome, makeProvider, makeWorkspace, shared, withEnv } from "./helper.mjs";

const PAYLOAD = ["/bin/echo", "hello"];

function bwrapNativeArgv(canonicalRoot, mode = "workspace-write") {
	const profile = ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent"];
	if (mode === "workspace-write") profile.push("--tmpfs", "/tmp", "--bind", canonicalRoot, canonicalRoot);
	return ["bwrap", ...profile, "--", ...PAYLOAD];
}

function confineWs(provider, workspaceRoot, mode = "workspace-write", signal) {
	return provider.confine([...PAYLOAD], { mode, workspaceRoot }, signal);
}

test("registration: native chain configured, no guard-ready service, honest log, lifecycle effects", async (t) => {
	const home = makeFixtureHome(t);
	const { provider, ctx } = await makeProvider(t, { home });
	assert.equal(provider.runnerCommand, undefined, "runnerCommand stays empty so the native chain selects the backend");
	assert.equal(provider.probeTimeoutMs, 5000);
	assert.equal(ctx.get("sandboxCacheRedirectGuardReady"), undefined, "no guard-ready service exists in V7");
	assert.equal(ctx.effects.length, 2, "parent ACL cleanup + our revocation");
	assert.ok(ctx.infos.some((line) => line.includes("cache-redirect provider loaded") && line.includes("native chain selects the backend per call")), "registration log makes no premature enhancement claim");
	assert.ok(!ctx.warnings.some((line) => line.includes("CACHE_REDIRECT_CONFIG")), "valid config logs no config warning");
});

test("G01 bwrap branch: nine setenv groups, prefix/mounts/payload preserved, metadata passthrough", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const result = await confineWs(provider, ws);
	const canonicalRoot = fs.realpathSync.native(ws);
	const native = bwrapNativeArgv(canonicalRoot);
	const sepIdx = result.argv.indexOf("--");
	assert.deepEqual(result.argv.slice(sepIdx), native.slice(native.indexOf("--")), "separator and payload preserved");
	assert.deepEqual(result.argv.slice(0, 4), native.slice(0, 4), "native prefix head preserved");
	const setenv = [];
	for (let i = 0; i < sepIdx; i++) if (result.argv[i] === "--setenv") setenv.push([result.argv[i + 1], result.argv[i + 2]]);
	assert.equal(setenv.length, 9);
	assert.deepEqual(setenv.find(([k]) => k === "GOPATH"), ["GOPATH", `${canonicalRoot}/.dsh-state/go`]);
	assert.equal(result.enforcement, "full");
	assert.deepEqual(result.denialSignatures, ["read-only file system"]);
});

test("G06 Landlock fallback: native result passes through with zero injection and one downgrade warning per instance", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => false;
	provider.internals.probeLandlock = () => "full";
	const first = await confineWs(provider, ws);
	assert.equal(first.argv.includes("--setenv"), false, "no bwrap options under Landlock");
	assert.equal(first.argv[first.argv.length - PAYLOAD.length - 1], "--");
	assert.deepEqual(first.argv.slice(-PAYLOAD.length), PAYLOAD);
	const second = await confineWs(provider, ws);
	assert.equal(second.argv.includes("--setenv"), false);
	const downgrade = ctx.warnings.filter((line) => line.includes('cache redirection inactive') && line.includes('"landlock"'));
	assert.equal(downgrade.length, 1, "one downgrade warning per provider instance");
	const { provider: secondProvider, ctx: secondCtx } = await makeProvider(t, { home });
	secondProvider.internals.probeBwrap = () => false;
	secondProvider.internals.probeLandlock = () => "full";
	await confineWs(secondProvider, ws);
	assert.equal(secondCtx.warnings.filter((line) => line.includes("cache redirection inactive")).length, 1, "a reloaded instance may warn again");
});

test("G07 both backends unusable: the native SandboxUnavailableError propagates with identity", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => false;
	provider.internals.probeLandlock = () => "unusable";
	await assert.rejects(confineWs(provider, ws), (error) => {
		assert.equal(error instanceof shared.SandboxUnavailableError, true);
		assert.equal(error.code, "SANDBOX_UNAVAILABLE");
		assert.match(error.message, /workspace-write/);
		return true;
	});
});

test("G08 selectedRunner shape changes are contract errors, never mistaken for a Landlock skip", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	await confineWs(provider, ws);
	// Shapes that survive the native wrap reach our contract check:
	for (const bogus of [{ runner: "bwrap" }, { runner: "bwrap", enforcement: "weird" }, { runner: "landlock" }]) {
		provider.selectedRunner = bogus;
		await assert.rejects(confineWs(provider, ws), /selectedRunner has an incompatible shape/);
	}
	// Shapes that break the native wrap itself still refuse (native error
	// identity) — and never degrade into a silent Landlock-style passthrough:
	for (const bogus of [{}, { enforcement: "full" }]) {
		provider.selectedRunner = bogus;
		await assert.rejects(confineWs(provider, ws));
	}
	provider.selectedRunner = undefined;
});

test("G09 read-only passes through untouched; unknown and danger-full-access modes are refused", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const ro = await confineWs(provider, ws, "read-only");
	assert.equal(ro.argv.includes("--setenv"), false, "read-only never gains environment options");
	const canonicalRoot = fs.realpathSync.native(ws);
	assert.deepEqual(ro.argv, bwrapNativeArgv(canonicalRoot, "read-only"));
	await assert.rejects(confineWs(provider, ws, "danger-full-access"), /unsupported sandbox mode.*danger-full-access bypass belongs to the DSH consumer/);
	await assert.rejects(confineWs(provider, ws, "bogus-mode"), /unsupported sandbox mode/);
});

test("G13 Host-visible case aliases are unset and canonical keys set; the Host env is never mutated", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const canonicalRoot = fs.realpathSync.native(ws);
	withEnv(t, { UV_CACHE_DIR: "/host/uv", uv_cache_dir: "/alias/uv", Npm_Config_Cache: "/alias/npm" });
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const result = await confineWs(provider, ws);
	const sep = result.argv.indexOf("--");
	const injection = result.argv.slice(0, sep);
	const unset = [];
	for (let i = 0; i < injection.length; i++) if (injection[i] === "--unsetenv") unset.push(injection[i + 1]);
	assert.deepEqual(unset.sort(), ["Npm_Config_Cache", "uv_cache_dir"], "only Host-visible aliases are unset");
	assert.equal(injection.includes("UV_CACHE_DIR"), true);
	assert.equal(injection[injection.indexOf("UV_CACHE_DIR") + 1], `${canonicalRoot}/.dsh-cache/uv`);
	assert.equal(process.env.UV_CACHE_DIR, "/host/uv", "Host environment unchanged");
	assert.equal(process.env.uv_cache_dir, "/alias/uv", "Host environment unchanged");
});

test("G13 without any inherited key the setenv still lands (no dependence on Host inheritance)", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const NINE = ["UV_CACHE_DIR", "PIP_CACHE_DIR", "npm_config_cache", "GOCACHE", "UV_PYTHON_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_PYTHON_BIN_DIR", "GOMODCACHE", "GOPATH"];
	withEnv(t, Object.fromEntries(NINE.map((k) => [k, undefined])));
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const result = await confineWs(provider, ws);
	const setenvCount = result.argv.filter((v) => v === "--setenv").length;
	assert.equal(setenvCount, 9);
	assert.equal(result.argv.includes("--unsetenv"), false);
});

test("G15 concurrent calls and different roots never cross roots or share argv arrays", async (t) => {
	const home = makeFixtureHome(t);
	const wsA = makeWorkspace(t, home, "projects/a");
	const wsB = makeWorkspace(t, home, "projects/b");
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const [ra, rb] = await Promise.all([confineWs(provider, wsA), confineWs(provider, wsB)]);
	const rootA = fs.realpathSync.native(wsA);
	const rootB = fs.realpathSync.native(wsB);
	assert.ok(ra.argv.includes(`${rootA}/.dsh-cache/uv`));
	assert.ok(!ra.argv.includes(`${rootB}/.dsh-cache/uv`));
	assert.ok(rb.argv.includes(`${rootB}/.dsh-cache/uv`));
	assert.notEqual(ra.argv, rb.argv, "each call returns its own argv array");
	ra.argv[0] = "tampered";
	assert.equal(rb.argv[0], "bwrap");
	const again = await confineWs(provider, wsA);
	assert.ok(again.argv.includes(`${rootA}/.dsh-state/go`));
});

test("G16 revoked instances refuse; revocation during an in-flight confine also refuses", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	await confineWs(provider, ws);
	dispose(ctx);
	await assert.rejects(confineWs(provider, ws), /has been revoked/);

	const second = await makeProvider(t, { home });
	second.provider.internals.probeBwrap = () => true;
	const inflight = second.provider.confine([...PAYLOAD], { mode: "workspace-write", workspaceRoot: ws });
	dispose(second.ctx);
	await assert.rejects(inflight, /revoked while confine was in flight/);
});

test("G16 cancellation keeps the abort reason identity", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const controller = new AbortController();
	controller.abort();
	await assert.rejects(confineWs(provider, ws, "workspace-write", controller.signal), (error) => {
		assert.equal(error.name, "AbortError");
		return true;
	});
});

test("G24 a layout-legal colon root skips the whole enhancement with one warning; native result returned", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home, "proj:ect");
	const canonicalRoot = fs.realpathSync.native(ws);
	const { provider, ctx } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	const first = await confineWs(provider, ws);
	assert.equal(first.argv.includes("--setenv"), false, "the enhancement is skipped as a whole");
	assert.deepEqual(first.argv, bwrapNativeArgv(canonicalRoot), "the native bwrap confinement stands");
	const second = await confineWs(provider, ws);
	assert.equal(second.argv.includes("--setenv"), false);
	const colonWarnings = ctx.warnings.filter((line) => line.includes("cache redirection skipped") && line.includes("GOPATH"));
	assert.equal(colonWarnings.length, 1, "one skip warning per instance");
});

test("G33 no bwrap on PATH: construction succeeds with an observation, native Landlock fallback still works", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home, fixturePath: path.join(home, "bin") });
	assert.equal(provider.cacheRedirectState.layoutErrors.length, 0, "a missing bwrap is not a layout error");
	assert.ok(ctx.infos.some((line) => line.includes("no bwrap candidate found on PATH")));
	provider.internals.probeBwrap = () => false;
	provider.internals.probeLandlock = () => "full";
	const result = await confineWs(provider, ws);
	assert.equal(result.argv.includes("--setenv"), false);
});

test("G34 non-Linux: no Linux layout collection, no root gates, native platform result passes through", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home, platform: "darwin", config: { bogusField: true } });
	assert.equal(provider.cacheRedirectState.layoutErrors.length, 0);
	assert.equal(provider.cacheRedirectState.sets.trees.length, 0, "no Linux protection sets are collected");
	assert.ok(ctx.warnings.some((line) => line.includes("platform darwin is not supported")));
	provider.internals.platform = "darwin";
	provider.internals.probeSeatbelt = () => true;
	const result = await confineWs(provider, ws);
	assert.equal(result.argv.includes("--setenv"), false, "no Linux options on other platforms");
	assert.equal(result.argv[0], "sandbox-exec");
	// Even the config error does not gate a non-Linux call: the enhancement is simply absent.
	assert.equal(result.enforcement, "full");
});

// --- G36 M-level: config/layout error states gate calls, recovery by rebuild ---

test("G36 bad additionalProtectedRoots entries keep the provider registered; only workspace-write refuses", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home, config: { additionalProtectedRoots: [path.join(home, "missing-root")] } });
	assert.ok(ctx.warnings.some((line) => line.includes("CACHE_REDIRECT_CONFIG") && line.includes("additionalProtectedRoots[0]")), "construction logs the field/index diagnostic");
	provider.internals.probeBwrap = () => true;
	const ro = await confineWs(provider, ws, "read-only");
	assert.equal(ro.argv.includes("--setenv"), false, "read-only still follows the native chain");
	await assert.rejects(confineWs(provider, ws), /CACHE_REDIRECT_CONFIG.*additionalProtectedRoots\[0\].*disable this bundle to restore the native provider/);

	const fixed = await makeProvider(t, { home, config: {} });
	fixed.provider.internals.probeBwrap = () => true;
	const ok = await confineWs(fixed.provider, ws);
	assert.equal(ok.argv.includes("--setenv"), true, "a rebuilt instance with fixed config enhances again");
});

test("G36 unknown keys, bad timeout and uninterpretable inheritance refuse workspace-write only", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const unknown = await makeProvider(t, { home, config: { runnerCommand: ["/evil"] } });
	unknown.provider.internals.probeBwrap = () => true;
	await assert.rejects(confineWs(unknown.provider, ws), /CACHE_REDIRECT_CONFIG.*runnerCommand/);

	const badTimeout = await makeProvider(t, { home, config: { probeTimeoutMs: "fast" } });
	assert.equal(badTimeout.provider.probeTimeoutMs, 5000, "the parent still gets a valid SDK default for read-only probes");
	badTimeout.provider.internals.probeBwrap = () => true;
	const ro = await confineWs(badTimeout.provider, ws, "read-only");
	assert.equal(ro.argv.includes("--setenv"), false);
	await assert.rejects(confineWs(badTimeout.provider, ws), /CACHE_REDIRECT_CONFIG.*probeTimeoutMs/);

	const garbage = await makeProvider(t, {
		home,
		nativeRow: { id: "sandbox", name: "@deepseek-ai/dsh-sandbox-local", disabled: true, config: { probeTimeoutMs: "!!js 5000" } },
	});
	assert.equal(garbage.provider.probeTimeoutMs, 5000);
	await assert.rejects(confineWs(garbage.provider, ws), /probeTimeoutMs/);
});

test("G36 valid explicit timeout, inherited timeout and additional roots take effect without errors", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home, "projects/demo");
	const extra = makeWorkspace(t, home, "data/keep");
	const explicit = await makeProvider(t, { home, config: { probeTimeoutMs: 1234, additionalProtectedRoots: [extra] } });
	assert.equal(explicit.provider.probeTimeoutMs, 1234);
	assert.equal(explicit.ctx.warnings.filter((line) => line.includes("CACHE_REDIRECT_CONFIG")).length, 0);
	explicit.provider.internals.probeBwrap = () => true;
	const ok = await confineWs(explicit.provider, ws);
	assert.equal(ok.argv.includes("--setenv"), true);
	fs.mkdirSync(path.join(extra, "inner"), { recursive: true });
	await assert.rejects(confineWs(explicit.provider, path.join(extra, "inner")), /inside protected tree/);

	const inherited = await makeProvider(t, {
		home,
		nativeRow: { id: "sandbox", name: "@deepseek-ai/dsh-sandbox-local", disabled: true, config: { probeTimeoutMs: 4321 } },
	});
	assert.equal(inherited.provider.probeTimeoutMs, 4321);
});

test("G36 layout errors (unresolvable expected path) gate workspace-write only", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const Class = await (await import("../lib/provider.js")).buildProvider(shared, { env: { HOME: home, PATH: path.join(home, "bin") }, platform: "linux" });
	const ctx = makeCtx({ home });
	ctx.dshHomePath = () => path.join(home, ".dsh-missing");
	const provider = new Class(ctx, {});
	t.after(() => dispose(ctx));
	assert.ok(ctx.warnings.some((line) => line.includes("CACHE_REDIRECT_LAYOUT")));
	provider.internals.probeBwrap = () => true;
	const ro = await confineWs(provider, ws, "read-only");
	assert.equal(ro.argv.includes("--setenv"), false);
	await assert.rejects(confineWs(provider, ws), /CACHE_REDIRECT_LAYOUT/);
});

test("dangerous roots are refused per call while ordinary projects pass on the same instance", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home, "projects/demo");
	const { provider } = await makeProvider(t, { home });
	provider.internals.probeBwrap = () => true;
	await assert.rejects(confineWs(provider, "/"), /refusing workspace root/);
	await assert.rejects(confineWs(provider, home), /covers protected/);
	await assert.rejects(confineWs(provider, path.join(home, ".dsh")), /inside protected tree|covers protected/);
	await assert.rejects(confineWs(provider, path.join(home, "missing-ws")), /cannot be resolved/);
	const ok = await confineWs(provider, ws);
	assert.equal(ok.argv.includes("--setenv"), true);
});

test("real native chain (no probe overrides): bwrap injects, other backends pass through honestly", async (t) => {
	const home = makeFixtureHome(t);
	const ws = makeWorkspace(t, home);
	const { provider, ctx } = await makeProvider(t, { home });
	let result;
	try {
		result = await confineWs(provider, ws);
	} catch (error) {
		if (error instanceof shared.SandboxUnavailableError) {
			t.skip("no usable sandbox backend in this environment");
			return;
		}
		throw error;
	}
	const runner = provider.selectedRunner.runner;
	if (runner === "bwrap") {
		assert.equal(result.argv.filter((v) => v === "--setenv").length, 9, "real bwrap chain injects the nine variables");
	} else {
		assert.equal(result.argv.includes("--setenv"), false, `real ${runner} chain passes through without injection`);
		assert.ok(ctx.warnings.some((line) => line.includes("cache redirection inactive")));
	}
});
