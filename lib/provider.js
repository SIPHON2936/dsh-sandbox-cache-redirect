/**
 * GuardedProvider: a LocalSandboxProvider subclass that verifies BEFORE it
 * registers, and re-verifies on every confined call.
 *
 * Construction order (fail-closed):
 *   1. prepareState(): platform/identity gates, composition checks, binary
 *      audits (before any subprocess), version queries, protected-set
 *      assembly, bundled-runner digest, install-chain audit-then-create,
 *      atomic install/reuse, timeout resolution, default-workspace layout.
 *      Any failure throws here — ctx.sandbox is never registered, and the
 *      confined bash executor (which requires ctx.sandbox) stays unavailable
 *      instead of executing an uncertified runner.
 *   2. super(ctx, { runnerCommand: [python, -IS, installedRunner], ... })
 *      registers ctx.sandbox with the pinned runner argv.
 *   3. Publish the guard-ready service (the disabled native row requires it
 *      as an inject blocker) and register lifecycle revocation.
 *
 * Every confine() re-checks liveness, runner inode+bytes, python/bwrap
 * identity, the recorded resolution snapshots of every DUAL tree (final
 * realpath + each symlink hop), mode, and the actual session workspace root
 * against the protected sets, delegates to the native confine for argv
 * generation, then asserts the wrapped argv matches the pinned runner and
 * the locked profile template before returning it.
 */
import fs from "node:fs";
import path from "node:path";
import {
	installOrReuseRunner,
	queryBwrapVersion,
	queryPythonInfo,
	reverifyBinary,
	reverifyRunnerIdentity,
	sha256,
} from "./install.js";
import {
	auditAdditionalRoots,
	checkComposition,
	resolveProbeTimeout,
	sanitizeConfig,
} from "./config.js";
import {
	addProtectedNode,
	addProtectedTree,
	assertWorkspaceAllowed,
	auditDualPath,
	auditInstallChain,
	auditTrustedExecutable,
	buildProtectedSets,
	createMissingComponents,
	fail,
	pathContains,
	reverifyInstallChain,
	reverifyDualPath,
} from "./trust.js";

const BWRAP_PROFILE_BASE = ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent"];
const RUNNER_FAILURE_SIGNATURES = ["dsh-bwrap-redirect:", "bwrap:"];

let generationCounter = 0;

function expectedProfileArgs(mode, canonicalRoot) {
	const args = [...BWRAP_PROFILE_BASE];
	if (mode === "workspace-write") args.push("--tmpfs", "/tmp", "--bind", canonicalRoot, canonicalRoot);
	return args;
}

/**
 * All checks that must pass before the native constructor may register
 * ctx.sandbox. `env` is injectable so tests can use private HOME fixtures
 * without mutating the real process environment.
 */
export function prepareState(ctx, config, shared, env = process.env) {
	// 1. Platform and identity gates.
	if (process.platform !== "linux") fail(`Linux only (platform is ${process.platform}); disable this bundle instead of running unconfined`);
	if (process.getuid() !== process.geteuid()) fail("real and effective UID differ; refusing a setuid launch environment");

	// 2. Strict row config and composition checks (before touching the filesystem).
	const sanitized = sanitizeConfig(config);
	const { ownId, nativeOptions } = checkComposition(ctx);

	// 3. HOME and the runner install path; HOME's own chain follows the strict no-symlink policy.
	const home = env.HOME;
	if (!home || !path.isAbsolute(home)) fail("HOME is unset or not absolute; cannot anchor the trusted runner path");
	const homeChain = auditInstallChain(home);
	if (homeChain.firstMissing !== homeChain.components.length) fail(`HOME does not fully exist as a trusted directory: ${home}`);
	const installDir = path.join(home, ".local", "libexec", "dsh");
	const runnerPath = path.join(installDir, shared.runnerFileName);

	// 4. Audit python3/bwrap binaries BEFORE any subprocess runs (setuid bit included).
	const python = auditTrustedExecutable("/usr/bin/python3");
	const bwrap = auditTrustedExecutable("/usr/bin/bwrap");

	// 5. Version queries against the audited, resolved binaries.
	const pythonInfo = queryPythonInfo(python.resolved);
	const bwrapVersion = queryBwrapVersion(bwrap.resolved);

	// 6. Protected sets: trees (both-direction overlap) and resolution nodes (cover rule).
	// The runner install tree is recorded in its nominal form: the strict
	// no-symlink chain audit below (step 8) plus the per-call re-audit prove
	// nominal === resolved for it. Its tree rule alone rejects any workspace
	// root that is an ancestor of (covers) or inside it.
	const protectedSets = buildProtectedSets();
	addProtectedTree(protectedSets, { nominal: installDir, resolved: installDir });
	for (const binary of [python, bwrap]) {
		addProtectedNode(protectedSets, binary.nominal);
		addProtectedNode(protectedSets, binary.resolved);
		for (const node of binary.chainNodes) addProtectedNode(protectedSets, node);
	}
	addProtectedNode(protectedSets, shared.paths.cliEntry);
	addProtectedNode(protectedSets, shared.paths.nodeExecutable);
	// Note: the Node installation is deliberately NOT a protected tree — the
	// already-running Host cannot be re-written on disk in any way that
	// matters, and containerized CI mounts (e.g. GHA's 0777 /__t tool cache)
	// would fail an audit that protects nothing.
	// DUAL trees are recorded whole: their full resolution snapshots (final
	// realpath + every symlink hop) are re-verified on every confined call.
	const dualTrees = [];
	for (const treePath of [
		ctx.dshHomePath(),
		shared.paths.dshRoot,
		pythonInfo.stdlib,
		shared.paths.packageDir,
	]) {
		const tree = auditDualPath(treePath, { finalKind: "directory" });
		dualTrees.push(tree);
		addProtectedTree(protectedSets, tree);
	}
	const extraTrees = auditAdditionalRoots(sanitized.additionalProtectedRoots);
	for (const tree of extraTrees) {
		dualTrees.push(tree);
		addProtectedTree(protectedSets, tree);
	}

	// 7. Bundled runner digest — before creating anything.
	const bundledRunnerPath = path.join(shared.paths.packageDir, "runner", "dsh-bwrap-redirect");
	const sourceBytes = fs.readFileSync(bundledRunnerPath);
	if (sha256(sourceBytes) !== shared.expectedRunnerSha256) {
		fail(`bundled runner digest mismatch: ${sha256(sourceBytes)} (expected ${shared.expectedRunnerSha256}); the package is corrupted — do not proceed`);
	}

	// 8. Install chain: audit every existing component first, then create missing levels one by one.
	const chain = auditInstallChain(installDir);
	createMissingComponents(chain.components, chain.firstMissing);

	// 9. Atomic install or verified reuse.
	const { action, identity } = installOrReuseRunner({ sourceBytes, target: runnerPath, expectedSha256: shared.expectedRunnerSha256 });
	reverifyInstallChain(installDir);

	// 10. probeTimeoutMs with recorded source.
	const timeout = resolveProbeTimeout(sanitized, nativeOptions);

	// 11. The deployment default root is the Host's launch cwd. For the web
	// profile every session picks its own workspace, so an unsafe default only
	// matters when a session actually uses it — and checkCall re-checks the
	// real session root on every confined call, which stays a hard rejection.
	// Warn here; reject there. (Headless uses cwd as the session root, so its
	// misuse is equally fail-closed — just reported per command.)
	const defaultPolicy = ctx.sandboxPolicy.resolve();
	if (defaultPolicy?.mode === "workspace-write") {
		const defaultRoot = shared.canonicalPath(defaultPolicy.workspaceRoot);
		try {
			assertWorkspaceAllowed(defaultRoot, protectedSets);
			for (const tree of extraTrees) {
				for (const form of [tree.nominal, tree.resolved]) {
					if (pathContains(form, defaultRoot) || pathContains(defaultRoot, form)) {
						fail(`additionalProtectedRoots entry ${form} overlaps the default workspace root ${defaultRoot}`);
					}
				}
			}
		} catch (error) {
			ctx.logger.warn(
				"deployment default workspace root is unsafe: %s — sessions rooted there will be refused per command; choose a project subdirectory as the session workspace",
				error.message,
			);
		}
	}

	// 12. Instance state.
	return {
		generation: ++generationCounter,
		revoked: false,
		ownId,
		runnerPath,
		runnerArgv: ["/usr/bin/python3", "-IS", runnerPath],
		runnerIdentity: identity,
		installDir,
		installAction: action,
		python,
		bwrap,
		pythonInfo,
		bwrapVersion,
		protectedSets,
		dualTrees,
		probeTimeoutMs: timeout.value,
		probeTimeoutSource: timeout.source,
		additionalProtectedRoots: sanitized.additionalProtectedRoots,
		versions: shared.versions,
	};
}

/** Per-call gate. Returns the checked policy carrying the canonical root. */
export function checkCall(state, policy, shared) {
	if (!state || state.revoked) fail("this guarded provider instance has been revoked");
	const mode = policy?.mode;
	if (mode !== "read-only" && mode !== "workspace-write") {
		fail(`unsupported sandbox mode for the guarded provider: ${mode} (full-access bypass belongs to the DSH executor, not this provider)`);
	}
	reverifyInstallChain(state.installDir);
	reverifyRunnerIdentity(state.runnerPath, state.runnerIdentity);
	reverifyBinary(state.python, "python3");
	reverifyBinary(state.bwrap, "bwrap");
	for (const tree of state.dualTrees) reverifyDualPath(tree);
	const canonicalRoot = shared.canonicalPath(policy.workspaceRoot);
	if (mode === "workspace-write") {
		try {
			assertWorkspaceAllowed(canonicalRoot, state.protectedSets);
		} catch (error) {
			fail(`${error.message} — choose a project subdirectory as the session workspace root`);
		}
	}
	return { ...policy, workspaceRoot: canonicalRoot };
}

/** The wrapped argv must be exactly: pinned runner argv + locked template + "--" + the original payload. */
export function assertWrappedArgv(state, checkedPolicy, argv, wrapped) {
	if (!wrapped || !Array.isArray(wrapped.argv)) fail("native confine returned no argv");
	const expected = [...state.runnerArgv, ...expectedProfileArgs(checkedPolicy.mode, checkedPolicy.workspaceRoot), "--", ...argv];
	if (wrapped.argv.length !== expected.length || !expected.every((value, index) => wrapped.argv[index] === value)) {
		fail("wrapped argv does not match the pinned runner and the locked bwrap profile template (DSH upgraded? re-run acceptance)");
	}
	if (wrapped.enforcement !== "full") fail(`wrapped argv reports "${wrapped.enforcement}" enforcement instead of full`);
}

export function buildProvider(shared, { env } = {}) {
	const { LocalSandboxProvider, SandboxUnavailableError, z } = shared;

	return class GuardedProvider extends LocalSandboxProvider {
		static inject = ["loader", "sandboxPolicy", "dshHomePath"];
		static Config = z.object({
			probeTimeoutMs: z.natural(),
			additionalProtectedRoots: z.array(z.string()),
		});

		constructor(ctx, config) {
			const state = prepareState(ctx, config, shared, env ?? process.env);
			super(ctx, {
				runnerCommand: state.runnerArgv,
				runnerFailureSignatures: RUNNER_FAILURE_SIGNATURES,
				probeTimeoutMs: state.probeTimeoutMs,
			});
			this.guardState = state;
			ctx.effect(() => () => {
				state.revoked = true;
			});
			ctx.provide("sandboxCacheRedirectGuardReady", Object.freeze({ generation: state.generation }));
			ctx.logger.info(
				"guarded sandbox provider registered (entry %s, generation %s): runner %s (%s, sha256 %s…), bwrap %s, probeTimeoutMs %s (%s)",
				state.ownId,
				state.generation,
				state.runnerPath,
				state.installAction,
				state.runnerIdentity.digest.slice(0, 12),
				state.bwrapVersion,
				state.probeTimeoutMs,
				state.probeTimeoutSource,
			);
		}

		async confine(argv, policy, signal) {
			const mode = policy?.mode ?? "unknown";
			try {
				signal?.throwIfAborted();
				const state = this.guardState;
				const checkedPolicy = checkCall(state, policy, shared);
				const wrapped = await super.confine(argv, checkedPolicy, signal);
				signal?.throwIfAborted();
				if (state.revoked) fail("provider was revoked while confine was in flight");
				assertWrappedArgv(state, checkedPolicy, argv, wrapped);
				return wrapped;
			} catch (error) {
				if (signal?.aborted) signal.throwIfAborted();
				if (error instanceof SandboxUnavailableError) throw error;
				throw new SandboxUnavailableError(mode, error.message);
			}
		}
	};
}
