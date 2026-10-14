/**
 * Strict row-config handling and composition checks.
 *
 * The guarded row's config accepts ONLY an optional positive-integer
 * probeTimeoutMs and an optional array of absolute additionalProtectedRoots.
 * runnerCommand and every other field are rejected — higher-priority patch
 * layers must never silently re-point the runner (no backdoor fields).
 *
 * Composition checks locate this row in the real include tree (never a
 * hardcoded id), then require: exactly one native sandbox row in the same
 * tree, effectively disabled, still carrying the guard-ready inject blocker;
 * the confined bash row present and enabled. probeTimeoutMs inherits a plain
 * positive integer from the disabled native row's config; an unresolved
 * expression there stops construction rather than guessing.
 */
import fs from "node:fs";
import path from "node:path";
import { auditDualPath, fail } from "./trust.js";

export const ALLOWED_CONFIG_KEYS = new Set(["probeTimeoutMs", "additionalProtectedRoots"]);
export const GUARD_READY_SERVICE = "sandboxCacheRedirectGuardReady";
export const NATIVE_SANDBOX_NAME = "@deepseek-ai/dsh-sandbox-local";
export const BASH_SANDBOX_NAME = "@deepseek-ai/dsh-bash-sandbox";

/** Reject unknown fields and structurally validate the two supported ones. */
export function sanitizeConfig(config) {
	if (config == null || typeof config !== "object") fail("row config must be an object");
	for (const key of Object.keys(config)) {
		if (!ALLOWED_CONFIG_KEYS.has(key)) {
			fail(`config field "${key}" is not supported; the runner command is fixed and not configurable`);
		}
	}
	const { probeTimeoutMs, additionalProtectedRoots = [] } = config;
	if (probeTimeoutMs !== undefined && (!Number.isInteger(probeTimeoutMs) || probeTimeoutMs <= 0)) {
		fail(`probeTimeoutMs must be a positive integer: ${probeTimeoutMs}`);
	}
	if (!Array.isArray(additionalProtectedRoots)) fail("additionalProtectedRoots must be an array of absolute directory paths");
	for (const root of additionalProtectedRoots) {
		if (typeof root !== "string" || !path.isAbsolute(root)) fail(`additionalProtectedRoots entries must be absolute paths: ${root}`);
		if (!fs.existsSync(root)) fail(`additionalProtectedRoots entry does not exist: ${root}`);
	}
	return { probeTimeoutMs, additionalProtectedRoots };
}

/** Locate our own entry inside the real include tree and return the same-tree entry list context. */
export function checkComposition(ctx) {
	const loader = ctx.loader;
	const ownId = loader.locate(ctx.fiber);
	if (!ownId) fail("cannot locate this plugin's loader entry");
	const ownEntry = loader.resolve(ownId);
	const group = ownEntry?.parent;
	const tree = group?.tree;
	if (!group || !tree) fail(`cannot resolve the composed tree for entry ${ownId}`);
	const rows = group.data ?? [];
	const nativeRows = rows.filter((options) => options?.name === NATIVE_SANDBOX_NAME);
	if (nativeRows.length !== 1) fail(`expected exactly one native sandbox row (${NATIVE_SANDBOX_NAME}) in the composed tree, found ${nativeRows.length}`);
	const nativeOptions = nativeRows[0];
	const nativeEntry = tree.store?.[nativeOptions.id];
	const nativeDisabled = nativeEntry ? nativeEntry.disabled : Boolean(nativeOptions.disabled);
	if (!nativeDisabled) {
		fail(`the native sandbox row "${nativeOptions.id}" is enabled; the guarded provider refuses to run alongside an unverified provider — composition conflict`);
	}
	if (!nativeOptions.inject || !Object.hasOwn(nativeOptions.inject, GUARD_READY_SERVICE)) {
		fail(`the native sandbox row "${nativeOptions.id}" lost the ${GUARD_READY_SERVICE} inject blocker; composition conflict`);
	}
	const bashRows = rows.filter((options) => options?.name === BASH_SANDBOX_NAME);
	if (bashRows.length === 0) fail(`the confined bash row (${BASH_SANDBOX_NAME}) is missing; unsupported composition`);
	const bashEntry = tree.store?.[bashRows[0].id];
	if (bashEntry && bashEntry.disabled) fail(`the confined bash row (${BASH_SANDBOX_NAME}) is disabled; unsupported composition`);
	return { ownId, nativeOptions };
}

/**
 * probeTimeoutMs: explicit row config wins; otherwise inherit a plain positive
 * integer from the disabled native row's config; otherwise the 5000 default.
 * An expression or non-integer legacy value stops construction — no guessing.
 */
export function resolveProbeTimeout(sanitized, nativeOptions) {
	if (sanitized.probeTimeoutMs !== undefined) return { value: sanitized.probeTimeoutMs, source: "config" };
	const legacy = nativeOptions?.config?.probeTimeoutMs;
	if (legacy === undefined || legacy === null) return { value: 5000, source: "default" };
	if (typeof legacy === "number" && Number.isInteger(legacy) && legacy > 0) return { value: legacy, source: "inherited" };
	fail("the disabled native sandbox row's probeTimeoutMs is not a plain positive integer; set an explicit probeTimeoutMs on the guarded row");
}

/** Dual-audit every additional protected root the operator supplied. */
export function auditAdditionalRoots(roots) {
	return roots.map((root) => auditDualPath(root, { finalKind: "directory" }));
}
