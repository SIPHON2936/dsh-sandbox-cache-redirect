/**
 * CacheRedirectProvider: a LocalSandboxProvider subclass that injects the
 * nine cache/runtime environment options into the native bwrap argv for
 * Linux workspace-write calls (V7 pluggable scheme).
 *
 * Design contract (construction):
 *   1. prepareEnhancement() runs BEFORE super() and never throws for
 *      expected enhancement errors: config field errors, unknown keys,
 *      timeout resolution errors and Linux layout collection failures are
 *      RECORDED in instance state. Only Linux workspace-write calls refuse
 *      while they exist; read-only calls follow the native chain.
 *   2. super(ctx, { runnerCommand: [], runnerFailureSignatures: [],
 *      probeTimeoutMs }) registers ctx.sandbox and leaves backend selection
 *      (bwrap → Landlock on Linux) entirely to the native chain.
 *   3. Instance state is frozen at construction; ctx.effect revokes it on
 *      dispose. No YAML edits, no shared-method rewrites, no file installs.
 *
 * Per-call order (confine, §4.1):
 *   signal/revocation/mode → payload snapshot → (Linux workspace-write only:
 *   config/layout error gates, session-root resolution, layout admission) →
 *   super.confine() with fresh copies (native exceptions propagate with
 *   identity; cancellation reasons keep their identity) → read-only and
 *   non-Linux pass the native result through → selectedRunner shape contract
 *   → non-bwrap backends pass through with a once-per-instance downgrade
 *   warning → colon roots skip the whole enhancement with a warning →
 *   rewriteBwrap() inserts the nine options immutably; metadata passes
 *   through by reference.
 *
 * Fail closed: unknown modes, dangerous roots, incompatible native return
 * structures and revoked instances refuse the CURRENT call with the Host's
 * own SandboxUnavailableError — the original argv is never returned.
 */
import { analyzeConfig, locateSameTreeRows, resolveProbeTimeout } from "./config.js";
import { assertWorkspaceAllowed, buildProtectedSets, collectLayout, resolveSessionRoot } from "./layout.js";
import { rewriteBwrap } from "./rewrite.js";

function describeSelected(selected) {
	if (selected === undefined) return "undefined";
	if (selected === "unavailable") return '"unavailable"';
	try {
		return JSON.stringify(selected);
	} catch {
		return String(selected);
	}
}

function fieldLabel(error) {
	return error.index === undefined ? error.field : `${error.field}[${error.index}]`;
}

/**
 * Pre-super preparation. Must not throw for expected enhancement errors —
 * everything expected is recorded. `env`/`platform` are injectable so tests
 * can use private fixtures and platform simulation without mutating the
 * process.
 */
export function prepareEnhancement(ctx, config, shared, env, platform) {
	const observations = [];
	const located = locateSameTreeRows(ctx);
	if (located.note) observations.push(located.note);

	const analyzed = analyzeConfig(config);
	const configErrors = [...analyzed.errors];

	const timeout = resolveProbeTimeout(config?.probeTimeoutMs, located.nativeOptions);
	if (timeout.error) configErrors.push(timeout.error);

	let sets = buildProtectedSets();
	let layoutErrors = [];
	let bwrapCandidates = [];
	if (platform === "linux") {
		let dshHome;
		try {
			dshHome = ctx.dshHomePath();
		} catch (error) {
			dshHome = "/__dsh_home_unavailable__";
			layoutErrors.push({ path: "(dshHomePath)", reason: `cannot resolve the DSH home path: ${error.message}` });
		}
		const layout = collectLayout({
			env,
			dshHome,
			paths: shared.paths,
			additionalRoots: analyzed.additionalRootEntries,
		});
		sets = layout.sets;
		layoutErrors = [...layoutErrors, ...layout.layoutErrors];
		bwrapCandidates = layout.bwrapCandidates;
		observations.push(...layout.observations);
		for (const entryError of layout.additionalRootErrors) {
			configErrors.push({ field: "additionalProtectedRoots", index: entryError.index, reason: entryError.reason });
		}
	}

	return {
		ownId: located.ownId,
		platform,
		configErrors,
		layoutErrors,
		sets,
		bwrapCandidates,
		observations,
		effectiveProbeTimeoutMs: timeout.value,
		probeTimeoutSource: timeout.source,
		logger: ctx.logger,
	};
}

export function buildProvider(shared, { env, platform } = {}) {
	const { LocalSandboxProvider, SandboxUnavailableError, z } = shared;
	const runtimeEnv = env ?? process.env;
	const runtimePlatform = platform ?? process.platform;

	return class CacheRedirectProvider extends LocalSandboxProvider {
		static inject = ["loader", "sandboxPolicy", "dshHomePath"];
		/**
		 * Wide receiving layer: preserves raw values and unknown keys so the
		 * business checks above can record precise errors instead of Cordis
		 * rejecting the row before construction. The receiving schema is NOT
		 * the business type contract — see README for the effective types
		 * (probeTimeoutMs: positive integer; additionalProtectedRoots:
		 * resolvable absolute directory array). Unknown fields are never
		 * forwarded to the parent constructor.
		 */
		static Config = z.object({
			probeTimeoutMs: z.any(),
			additionalProtectedRoots: z.any(),
		});

		constructor(ctx, config) {
			const preparation = prepareEnhancement(ctx, config ?? {}, shared, runtimeEnv, runtimePlatform);
			super(ctx, {
				runnerCommand: [],
				runnerFailureSignatures: [],
				probeTimeoutMs: preparation.effectiveProbeTimeoutMs,
			});
			const state = { ...preparation, revoked: false, warned: new Set() };
			this.cacheRedirectState = state;
			ctx.effect(() => () => {
				state.revoked = true;
			});
			const logger = ctx.logger;
			logger.info(
				"sandbox cache-redirect provider loaded (entry %s; DSH %s, dsh-sandbox-local %s, probeTimeoutMs %s from %s); the native chain selects the backend per call — cache redirection applies to Linux workspace-write bwrap calls only",
				state.ownId ?? "unknown",
				shared.versions.dsh,
				shared.versions.sandboxLocal,
				state.effectiveProbeTimeoutMs,
				state.probeTimeoutSource,
			);
			for (const observation of state.observations) logger.info("cache-redirect layout: %s", observation);
			for (const error of state.configErrors) {
				logger.warn(
					"CACHE_REDIRECT_CONFIG: entry %s, field %s: %s — fix this row's config and reload/restart, or disable this bundle to restore the native provider (read-only calls are unaffected; Linux workspace-write calls are refused)",
					state.ownId ?? "unknown",
					fieldLabel(error),
					error.reason,
				);
			}
			for (const error of state.layoutErrors) {
				logger.warn(
					"CACHE_REDIRECT_LAYOUT: entry %s, path %s: %s — fix the deployment path and restart, or disable this bundle to restore the native provider (read-only calls are unaffected; Linux workspace-write calls are refused)",
					state.ownId ?? "unknown",
					error.path,
					error.reason,
				);
			}
			if (state.platform !== "linux") {
				logger.warn("cache-redirect: platform %s is not supported for cache redirection; native sandbox results pass through unchanged", state.platform);
			}
		}

		async confine(argv, policy, signal) {
			const state = this.cacheRedirectState;
			const mode = policy?.mode ?? "unknown";
			const refuse = (message) => {
				throw new SandboxUnavailableError(mode, message);
			};
			const warnOnce = (key, message) => {
				if (state.warned.has(key)) return;
				state.warned.add(key);
				state.logger.warn(message);
			};

			// --- admission (steps 1-2): our own checks, wrapped with remediation ---
			let payloadSnapshot;
			let checkedPolicy;
			let canonicalRoot;
			try {
				signal?.throwIfAborted();
				if (!state || state.revoked) refuse("this cache-redirect provider instance has been revoked; start a new session or reload the profile");
				if (mode !== "read-only" && mode !== "workspace-write") {
					refuse(`unsupported sandbox mode for a direct provider call: ${mode} — the danger-full-access bypass belongs to the DSH consumer, not to this provider`);
				}
				if (!Array.isArray(argv) || argv.length === 0 || argv.some((value) => typeof value !== "string")) {
					refuse("CACHE_REDIRECT_CONTRACT: payload must be a nonempty string array");
				}
				payloadSnapshot = [...argv];
				if (state.platform === "linux" && mode === "workspace-write") {
					if (state.configErrors.length > 0) {
						const first = state.configErrors[0];
						refuse(`CACHE_REDIRECT_CONFIG: field ${fieldLabel(first)}: ${first.reason} — fix this row's config and reload/restart, or disable this bundle to restore the native provider`);
					}
					if (state.layoutErrors.length > 0) {
						const first = state.layoutErrors[0];
						refuse(`CACHE_REDIRECT_LAYOUT: ${first.path}: ${first.reason} — fix the deployment path and restart, or disable this bundle to restore the native provider`);
					}
					canonicalRoot = resolveSessionRoot(policy.workspaceRoot);
					assertWorkspaceAllowed(canonicalRoot, state.sets);
					checkedPolicy = { ...policy, workspaceRoot: canonicalRoot };
				} else {
					checkedPolicy = { ...policy };
				}
			} catch (error) {
				if (signal?.aborted) signal.throwIfAborted();
				if (error instanceof SandboxUnavailableError) throw error;
				refuse(`${error.message} — choose a project directory as the session workspace root, or disable this bundle to restore the native provider`);
			}

			// --- native wrap (step 3): exceptions and cancellation keep identity ---
			const wrapped = await super.confine([...payloadSnapshot], checkedPolicy, signal);

			// --- post-wrap contract (steps 3-8) ---
			try {
				signal?.throwIfAborted();
				if (state.revoked) refuse("provider was revoked while confine was in flight; start a new session");
				if (state.platform !== "linux" || mode === "read-only") return wrapped;
				const selected = this.selectedRunner;
				const shapeValid = selected !== undefined && selected !== "unavailable" && typeof selected === "object" && typeof selected.runner === "string" && (selected.enforcement === "full" || selected.enforcement === "partial");
				if (!shapeValid) {
					refuse(`CACHE_REDIRECT_CONTRACT: selectedRunner has an incompatible shape after a successful native confine (${describeSelected(selected)}); the Host SDK changed — disable this bundle to restore the native provider and re-run compatibility acceptance`);
				}
				if (selected.runner !== "bwrap") {
					warnOnce(
						`backend-${selected.runner}`,
						`cache redirection inactive: the native chain selected backend "${selected.runner}" (enforcement: ${selected.enforcement}), which this plugin does not enhance; native confinement is unchanged`,
					);
					return wrapped;
				}
				if (canonicalRoot.includes(":")) {
					warnOnce(
						"colon-root",
						`cache redirection skipped for workspace root ${JSON.stringify(canonicalRoot)} (backend: bwrap, enforcement: ${selected.enforcement}): a colon cannot be expressed in the Unix GOPATH list syntax, so the whole nine-variable enhancement is skipped; native confinement is unchanged`,
					);
					return wrapped;
				}
				return rewriteBwrap(wrapped, payloadSnapshot, canonicalRoot, process.env);
			} catch (error) {
				if (signal?.aborted) signal.throwIfAborted();
				if (error instanceof SandboxUnavailableError) throw error;
				const detail = error?.code === "CACHE_REDIRECT_CONTRACT" ? error.message : `CACHE_REDIRECT_CONTRACT: ${error.message}`;
				refuse(`${detail} — disabling this bundle restores the native provider`);
			}
		}
	};
}
