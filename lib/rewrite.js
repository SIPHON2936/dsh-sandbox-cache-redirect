/**
 * bwrap argv rewriting: the nine cache/runtime environment variables,
 * payload-suffix local contract, immutable insertion, metadata passthrough.
 *
 * This is a pure function module. The caller (lib/provider.js) owns backend
 * determination, workspace admission, and cancellation/revocation checks.
 * The colon check inside rewriteBwrap is a redundant invariant that catches
 * wiring mistakes; the provider skips colon roots BEFORE calling here, so a
 * colon root must never arrive through the normal path.
 *
 * Contract (DSH 0.2.1-alpha.2 native chain, verified against the installed
 * Host): the native confine result's argv ends with an independent "--"
 * followed by the exact payload, so the separator sits at
 * argv.length - payload.length - 1. Mount/profile arguments may change
 * without tripping this assertion; a changed payload encoding or separator
 * structure must fail diagnostically, never fall back to unsandboxed
 * execution.
 */
import path from "node:path";

export const DIRECTORY_ENV = Object.freeze({
	UV_CACHE_DIR: ".dsh-cache/uv",
	PIP_CACHE_DIR: ".dsh-cache/pip",
	npm_config_cache: ".dsh-cache/npm",
	GOCACHE: ".dsh-cache/go-build",
	UV_PYTHON_CACHE_DIR: ".dsh-cache/uv-python",
	UV_PYTHON_INSTALL_DIR: ".dsh-state/uv/python",
	UV_PYTHON_BIN_DIR: ".dsh-state/uv/bin",
	GOMODCACHE: ".dsh-cache/go-mod",
	GOPATH: ".dsh-state/go",
});

function contract(message) {
	const error = new Error("CACHE_REDIRECT_CONTRACT: " + message);
	error.code = "CACHE_REDIRECT_CONTRACT";
	throw error;
}

export function rewriteBwrap(wrapped, payloadSnapshot, canonicalRoot,
                             visibleEnv = process.env) {
	if (!Array.isArray(payloadSnapshot) || payloadSnapshot.length === 0 ||
	    payloadSnapshot.some(value => typeof value !== "string")) {
		contract("payload must be a nonempty string array");
	}
	if (!wrapped || !Array.isArray(wrapped.argv) ||
	    wrapped.argv.some(value => typeof value !== "string")) {
		contract("native result has no string argv");
	}
	if (!["full", "partial"].includes(wrapped.enforcement) ||
	    !Array.isArray(wrapped.denialSignatures) ||
	    !Array.isArray(wrapped.runnerFailureRules)) {
		contract("native confinement metadata is incompatible");
	}
	const sepIdx = wrapped.argv.length - payloadSnapshot.length - 1;
	if (sepIdx < 1 || wrapped.argv[sepIdx] !== "--" ||
	    payloadSnapshot.some((value, i) => wrapped.argv[sepIdx + 1 + i] !== value)) {
		contract("native payload suffix/separator changed");
	}
	if (typeof canonicalRoot !== "string" || !path.isAbsolute(canonicalRoot) ||
	    canonicalRoot === "/" || canonicalRoot.includes(":") ||
	    canonicalRoot.includes("\0")) {
		contract("caller did not supply a supported checked root");
	}
	const injection = [];
	const names = Object.keys(visibleEnv);
	for (const [key, relative] of Object.entries(DIRECTORY_ENV)) {
		for (const name of names) {
			if (name !== key && name.toLowerCase() === key.toLowerCase()) {
				injection.push("--unsetenv", name);
			}
		}
		injection.push("--setenv", key, path.join(canonicalRoot, relative));
	}
	return {
		...wrapped,
		argv: [...wrapped.argv.slice(0, sepIdx), ...injection,
		       ...wrapped.argv.slice(sepIdx)],
	};
}
