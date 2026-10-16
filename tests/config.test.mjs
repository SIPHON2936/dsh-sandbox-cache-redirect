/**
 * Business config validation units (§3.1): analyzeConfig records precise
 * field/index errors without throwing; resolveProbeTimeout implements the
 * explicit > inherited > SDK-default ladder with error records instead of
 * guesses. These complement the provider-level G36 cases, which prove the
 * same errors gate calls on a constructed instance.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { analyzeConfig, resolveProbeTimeout, SDK_DEFAULT_PROBE_TIMEOUT_MS } from "../lib/config.js";

test("analyzeConfig: valid empty and populated configs produce no errors", () => {
	assert.deepEqual(analyzeConfig({}), { errors: [], additionalRootEntries: [] });
	const analyzed = analyzeConfig({ probeTimeoutMs: 2500, additionalProtectedRoots: ["/data/one", "/data/two"] });
	assert.deepEqual(analyzed.errors, []);
	assert.deepEqual(analyzed.additionalRootEntries, [{ index: 0, path: "/data/one" }, { index: 1, path: "/data/two" }]);
});

test("analyzeConfig: unknown fields are recorded by name (legacy runner keys have no effect)", () => {
	const { errors } = analyzeConfig({ runnerCommand: ["/x"], runnerFailureSignatures: ["y"], backend: "none", internals: {} });
	assert.deepEqual(errors.map((e) => e.field).sort(), ["backend", "internals", "runnerCommand", "runnerFailureSignatures"]);
	assert.match(errors[0].reason, /unknown config field/);
});

test("analyzeConfig: malformed additionalProtectedRoots entries keep their original indices", () => {
	const { errors, additionalRootEntries } = analyzeConfig({ additionalProtectedRoots: ["/ok", 42, "relative/path", "/also-ok"] });
	assert.deepEqual(errors.map((e) => `${e.field}[${e.index}]`), ["additionalProtectedRoots[1]", "additionalProtectedRoots[2]"]);
	assert.deepEqual(additionalRootEntries, [{ index: 0, path: "/ok" }, { index: 3, path: "/also-ok" }]);
	const notArray = analyzeConfig({ additionalProtectedRoots: "/data" });
	assert.equal(notArray.errors.length, 1);
	assert.equal(notArray.errors[0].field, "additionalProtectedRoots");
});

test("analyzeConfig: non-object config is a recorded error, not a throw", () => {
	for (const value of [null, 42, "/string", ["/array"]]) {
		const { errors } = analyzeConfig(value);
		assert.equal(errors.length, 1);
		assert.equal(errors[0].field, "(row config)");
	}
});

test("resolveProbeTimeout: explicit positive integer wins", () => {
	assert.deepEqual(resolveProbeTimeout(1234, undefined), { value: 1234, source: "config" });
	assert.deepEqual(resolveProbeTimeout(1234, { config: { probeTimeoutMs: 4321 } }), { value: 1234, source: "config" });
});

test("resolveProbeTimeout: invalid explicit values record an error and fall back to the SDK default", () => {
	for (const value of [0, -1, 2.5, "fast", null, [], {}]) {
		const resolved = resolveProbeTimeout(value, undefined);
		assert.equal(resolved.value, SDK_DEFAULT_PROBE_TIMEOUT_MS);
		assert.equal(resolved.source, "default");
		assert.equal(resolved.error.field, "probeTimeoutMs");
	}
});

test("resolveProbeTimeout: a plain positive integer on the native row is inherited", () => {
	assert.deepEqual(resolveProbeTimeout(undefined, { config: { probeTimeoutMs: 4321 } }), { value: 4321, source: "inherited" });
});

test("resolveProbeTimeout: uninterpretable inherited values record an error instead of guessing", () => {
	for (const legacy of ["!!js 5000", 0, -3, 2.5, [], {}]) {
		const resolved = resolveProbeTimeout(undefined, { config: { probeTimeoutMs: legacy } });
		assert.equal(resolved.value, SDK_DEFAULT_PROBE_TIMEOUT_MS);
		assert.equal(resolved.source, "default");
		assert.match(resolved.error.reason, /cannot be safely interpreted/);
	}
});

test("resolveProbeTimeout: nothing configured uses the verified SDK default", () => {
	assert.deepEqual(resolveProbeTimeout(undefined, undefined), { value: SDK_DEFAULT_PROBE_TIMEOUT_MS, source: "default" });
	assert.deepEqual(resolveProbeTimeout(undefined, { config: {} }), { value: SDK_DEFAULT_PROBE_TIMEOUT_MS, source: "default" });
});
