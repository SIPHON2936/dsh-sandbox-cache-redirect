/**
 * rewriteBwrap pure-function contract tests (acceptance matrix G01–G05,
 * plus the case-alias and redundant-invariant rules of §4.2/§5).
 *
 * The wrapped fixtures mirror the native bwrap result shape; mount/profile
 * arguments may vary freely — the contract only pins the payload suffix and
 * the independent "--" separator located from the tail.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { DIRECTORY_ENV, rewriteBwrap } from "../lib/rewrite.js";

const ROOT = "/home/demo/projects/proj";
const PAYLOAD = ["/bin/bash", "-lc", "echo hi"];

function makeWrapped({ prefix = [], payload = PAYLOAD, enforcement = "full", extra = {} } = {}) {
	const argv = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent", "--tmpfs", "/tmp", "--bind", ROOT, ROOT, ...prefix, "--", ...payload];
	return {
		argv,
		enforcement,
		denialSignatures: ["read-only file system"],
		runnerFailureRules: [{ fatalSignatures: ["bwrap: "] }],
		...extra,
	};
}

test("G01 nine setenv groups inserted before the separator; prefix and payload preserved elementwise", () => {
	const wrapped = makeWrapped();
	const originalArgv = [...wrapped.argv];
	const result = rewriteBwrap(wrapped, [...PAYLOAD], ROOT, {});
	const sep = result.argv.indexOf("--");
	const injection = result.argv.slice(0, sep).filter((value, index) => result.argv[index] === "--setenv");
	// Nine --setenv entries, each followed by the workspace-joined value.
	const setenv = [];
	for (let i = 0; i < sep; i++) {
		if (result.argv[i] === "--setenv") setenv.push([result.argv[i + 1], result.argv[i + 2]]);
	}
	assert.equal(setenv.length, 9);
	for (const [key, relative] of Object.entries(DIRECTORY_ENV)) {
		assert.deepEqual(setenv.find(([name]) => name === key), [key, `${ROOT}/${relative}`]);
	}
	// Prefix (everything before the injection point) and payload keep order.
	const sepIdx = originalArgv.length - PAYLOAD.length - 1;
	assert.deepEqual(result.argv.slice(0, 4), originalArgv.slice(0, 4)); // untouched head
	assert.deepEqual(result.argv.slice(sep), originalArgv.slice(sepIdx)); // separator + payload
	assert.equal(injection.length, 9);
});

test("G02 adjusted native profile arguments stay elementwise intact", () => {
	const wrapped = makeWrapped({ prefix: ["--new-extra", "value with spaces"] });
	const result = rewriteBwrap(wrapped, [...PAYLOAD], ROOT, {});
	const sepIdx = makeWrapped({ prefix: ["--new-extra", "value with spaces"] }).argv.length - PAYLOAD.length - 1;
	const head = makeWrapped({ prefix: ["--new-extra", "value with spaces"] }).argv.slice(0, sepIdx);
	assert.deepEqual(result.argv.slice(0, head.length), head);
});

test("G03 payload containing --, spaces, Chinese and quotes survives verbatim (tail-length location)", () => {
	const payload = ["/bin/echo", "--", "a b", "中文", "\"quoted\"", "--setenv"];
	const wrapped = makeWrapped({ payload });
	const result = rewriteBwrap(wrapped, [...payload], ROOT, {});
	assert.deepEqual(result.argv.slice(-payload.length), payload);
	assert.equal(result.argv[result.argv.length - payload.length - 1], "--");
});

test("G04 missing separator, altered payload, malformed results are diagnostic contract errors", () => {
	const noSep = makeWrapped();
	noSep.argv[noSep.argv.length - PAYLOAD.length - 1] = "---";
	assert.throws(() => rewriteBwrap(noSep, [...PAYLOAD], ROOT, {}), /CACHE_REDIRECT_CONTRACT.*suffix\/separator/);

	const altered = makeWrapped();
	altered.argv[altered.argv.length - 1] = "tampered";
	assert.throws(() => rewriteBwrap(altered, [...PAYLOAD], ROOT, {}), /CACHE_REDIRECT_CONTRACT/);

	assert.throws(() => rewriteBwrap({ argv: ["bwrap", 42] }, [...PAYLOAD], ROOT, {}), /no string argv/);
	assert.throws(() => rewriteBwrap(makeWrapped({ enforcement: "weird" }), [...PAYLOAD], ROOT, {}), /metadata is incompatible/);
	assert.throws(() => rewriteBwrap(makeWrapped(), [], ROOT, {}), /nonempty string array/);
	assert.throws(() => rewriteBwrap(makeWrapped(), ["/bin/echo", 7], ROOT, {}), /nonempty string array/);
});

test("G05 metadata and unknown extra fields pass through by reference; inputs are not mutated", () => {
	const extra = { futureField: { nested: true } };
	const wrapped = makeWrapped({ enforcement: "partial", extra });
	const argvRef = wrapped.argv;
	const rulesRef = wrapped.runnerFailureRules;
	const result = rewriteBwrap(wrapped, [...PAYLOAD], ROOT, {});
	assert.equal(result.enforcement, "partial");
	assert.equal(result.denialSignatures, wrapped.denialSignatures);
	assert.equal(result.runnerFailureRules, rulesRef);
	assert.equal(result.futureField, extra.futureField);
	assert.notEqual(result.argv, argvRef, "rewritten argv is a new array");
	assert.equal(wrapped.argv, argvRef, "native argv array is not replaced");
	assert.equal(result.argv.includes("--setenv"), true);
	assert.equal(argvRef.includes("--setenv"), false, "native argv content not mutated");
});

test("case aliases in the visible Host env are unset before the canonical setenv; Host env is only read", () => {
	const visible = { UV_CACHE_DIR: "/host/value", uv_cache_dir: "/alias/value", Npm_Config_Cache: "/alias/npm", PATH: "/usr/bin" };
	const result = rewriteBwrap(makeWrapped(), [...PAYLOAD], ROOT, visible);
	const sep = result.argv.indexOf("--");
	const injection = result.argv.slice(0, sep);
	const unset = [];
	for (let i = 0; i < injection.length; i++) if (injection[i] === "--unsetenv") unset.push(injection[i + 1]);
	assert.deepEqual(unset.sort(), ["Npm_Config_Cache", "uv_cache_dir"]);
	// The canonical keys are set exactly once each, to workspace values.
	for (const [key, relative] of Object.entries(DIRECTORY_ENV)) {
		const at = injection.indexOf(key);
		assert.equal(injection[at - 1], "--setenv");
		assert.equal(injection[at + 1], `${ROOT}/${relative}`);
	}
	assert.equal(visible.UV_CACHE_DIR, "/host/value", "the visible env map is not mutated");
});

test("setenv does not depend on the key pre-existing in the Host env", () => {
	const result = rewriteBwrap(makeWrapped(), [...PAYLOAD], ROOT, {});
	for (const key of Object.keys(DIRECTORY_ENV)) assert.equal(result.argv.includes(key), true);
	assert.equal(result.argv.includes("--unsetenv"), false);
});

test("redundant invariants: colon/NUL/relative/slash roots and non-string roots are contract errors", () => {
	for (const root of ["/with:colon", "relative/path", "/", "/nul\0byte", 42]) {
		assert.throws(() => rewriteBwrap(makeWrapped(), [...PAYLOAD], root, {}), /CACHE_REDIRECT_CONTRACT/);
	}
});
