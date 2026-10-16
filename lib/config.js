/**
 * Business config validation for the V7 provider row (non-throwing).
 *
 * Cordis validates the row's runtime.Config BEFORE construction, so the
 * provider declares a WIDE receiving schema (z.any() per known field) that
 * preserves raw values and unknown keys; this module then performs the real
 * business checks and returns ERROR RECORDS instead of throwing. The
 * provider keeps registering with any of these errors present: read-only
 * calls follow the native chain, and only Linux workspace-write calls are
 * refused per call with the remediation path (fix the row and reload, or
 * disable the bundle to restore the native provider).
 *
 * The wide receiving layer never means invalid config executes: unknown
 * fields are not passed to the parent constructor, the two known fields are
 * white-list validated here, and the effective parent-constructor arguments
 * (runnerCommand=[], runnerFailureSignatures=[], a positive timeout) are
 * always valid.
 */
import path from "node:path";

export const ALLOWED_CONFIG_KEYS = new Set(["probeTimeoutMs", "additionalProtectedRoots"]);
export const NATIVE_SANDBOX_NAME = "@deepseek-ai/dsh-sandbox-local";
/** Verified against the installed SDK (LocalSandboxProvider.Config default). */
export const SDK_DEFAULT_PROBE_TIMEOUT_MS = 5000;

function describe(value) {
	if (typeof value === "string") return JSON.stringify(value);
	if (value === null) return "null";
	if (Array.isArray(value)) return `an array (${value.length} entries)`;
	return `${typeof value} ${JSON.stringify(String(value))}`;
}

/**
 * Validate the two supported fields' shapes and flag unknown keys.
 * Returns { errors: [{ field, index?, reason }], additionalRootEntries:
 * [{ index, path }] } — the valid absolute-string entries, with their
 * original indices; existence/directory/resolution failures of those
 * entries are reported by collectLayout with the same indices.
 */
export function analyzeConfig(config) {
	const errors = [];
	const additionalRootEntries = [];
	if (config == null || typeof config !== "object" || Array.isArray(config)) {
		errors.push({ field: "(row config)", reason: "row config must be an object" });
		return { errors, additionalRootEntries };
	}
	for (const key of Object.keys(config)) {
		if (!ALLOWED_CONFIG_KEYS.has(key)) {
			errors.push({
				field: key,
				reason: "unknown config field is not used by this provider; remove it — runnerCommand, runnerFailureSignatures, backend, internals and other legacy keys have no effect here",
			});
		}
	}
	const rawRoots = config.additionalProtectedRoots;
	if (rawRoots !== undefined) {
		if (!Array.isArray(rawRoots)) {
			errors.push({ field: "additionalProtectedRoots", reason: `must be an array of absolute directory paths, got ${describe(rawRoots)}` });
		} else {
			rawRoots.forEach((root, index) => {
				if (typeof root !== "string") {
					errors.push({ field: "additionalProtectedRoots", index, reason: `entry must be a string (absolute directory path), got ${describe(root)}` });
				} else if (!path.isAbsolute(root)) {
					errors.push({ field: "additionalProtectedRoots", index, reason: `entry must be an absolute path: ${JSON.stringify(root)}` });
				} else {
					additionalRootEntries.push({ index, path: root });
				}
			});
		}
	}
	return { errors, additionalRootEntries };
}

/**
 * probeTimeoutMs resolution (never throws):
 *   - explicit value set: a positive integer wins ("config"); anything else
 *     records an error and the SDK default is used for the parent constructor
 *     so native read-only calls keep a working probe timeout.
 *   - unset: inherit a plain positive integer from the same-tree native
 *     row's config ("inherited"); an uninterpretable value there (expression
 *     residue, non-integer, non-positive) records an error instead of
 *     guessing; nothing configured uses the verified SDK default.
 */
export function resolveProbeTimeout(explicit, nativeOptions) {
	if (explicit !== undefined) {
		if (Number.isInteger(explicit) && explicit > 0) return { value: explicit, source: "config" };
		return {
			value: SDK_DEFAULT_PROBE_TIMEOUT_MS,
			source: "default",
			error: {
				field: "probeTimeoutMs",
				reason: `must be a positive integer, got ${describe(explicit)}; the SDK default ${SDK_DEFAULT_PROBE_TIMEOUT_MS} is used so native read-only calls keep working`,
			},
		};
	}
	const legacy = nativeOptions?.config?.probeTimeoutMs;
	if (legacy === undefined || legacy === null) return { value: SDK_DEFAULT_PROBE_TIMEOUT_MS, source: "default" };
	if (typeof legacy === "number" && Number.isInteger(legacy) && legacy > 0) return { value: legacy, source: "inherited" };
	return {
		value: SDK_DEFAULT_PROBE_TIMEOUT_MS,
		source: "default",
		error: {
			field: "probeTimeoutMs",
			reason: `the same-tree native sandbox row's probeTimeoutMs (${describe(legacy)}) cannot be safely interpreted — expressions and non-integer values are not inherited; set an explicit positive integer on this row`,
		},
	};
}

/**
 * Locate the same-tree native sandbox row for timeout inheritance. Purely
 * diagnostic: any tree-walk failure yields no inheritance (the SDK default
 * applies), never a construction failure. Returns { ownId, nativeOptions,
 * note? }.
 */
export function locateSameTreeRows(ctx) {
	try {
		const ownId = ctx.loader?.locate?.(ctx.fiber);
		if (!ownId) return { ownId: undefined, nativeOptions: undefined, note: "cannot locate this plugin's loader entry; timeout inheritance skipped" };
		const ownEntry = ctx.loader.resolve(ownId);
		const rows = ownEntry?.parent?.data ?? [];
		const nativeOptions = rows.find((options) => options?.name === NATIVE_SANDBOX_NAME);
		return { ownId, nativeOptions };
	} catch (error) {
		return { ownId: undefined, nativeOptions: undefined, note: `could not walk the loader tree for same-tree config inheritance: ${error.message}` };
	}
}
