/**
 * Deployment layout collection and per-call workspace admission (V7 scheme).
 *
 * This module replaces the 6.x trust-chain audits. It deliberately performs
 * NO binary identity audit (owner/mode/setuid/digests): the plugin relies on
 * the Host's own PATH resolution and functional probes, per the V7 contract.
 * Its one job is keeping the agent-writable workspace separated from the
 * Host code/configuration domains:
 *
 *   - ONE-TIME, read-only collection before the provider registers (Linux
 *     only): HOME, DSH_HOME, the actual Host/plugin/Node paths, and any
 *     existing bwrap candidates on PATH. Key directories (DSH_HOME, Host
 *     install root, plugin package dir) become protection TREES that reject
 *     bidirectional overlap with the workspace root; the resolved binaries
 *     and every directory/link node on the collected paths become protection
 *     NODES that reject a workspace root covering them. HOME itself is only
 *     a node — never a whole tree — so $HOME/projects/<x> stays legal.
 *   - Resolution walks follow kernel path_resolution(7) semantics: raw
 *     components consumed one at a time, symlink targets spliced in place
 *     (relative targets resolve against the link's own directory), ".."
 *     applied to the actually-resolved directory, and terminal links to
 *     "."/"./"/""/ correctly yielding the containing directory. The result
 *     is cross-checked against realpath(3) (fs.realpathSync.native); any
 *     divergence fails collection for that path.
 *   - Per call, only the CURRENT workspace root is resolved (realpath(3))
 *     and compared against the recorded sets — no re-walking of trees, no
 *     file digests, no per-call audits.
 *
 * Expected-path collection failures are recorded as layout errors (the
 * provider keeps registering and rejects only Linux workspace-write calls);
 * a missing bwrap candidate set is NOT an error — backend availability is
 * the native chain's business (Landlock fallback stays possible).
 *
 * Premise: configuration competitors are stopped and the Host/install
 * layout is trusted and stable for the instance lifetime. Rebuild the Host
 * after upgrades, moves, or PATH changes.
 */
import fs from "node:fs";
import path from "node:path";

export function fail(message) {
	throw new Error(`dsh-sandbox-cache-redirect: ${message}`);
}

/** Component-wise containment: true when `child` equals `parent` or sits inside it. Both must be absolute. */
export function pathContains(parent, child) {
	const relative = path.relative(parent, child);
	return relative === "" || (relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative));
}

const MAX_SYMLINK_HOPS = 40;

function rawComponents(p) {
	return p.split("/").filter((c) => c !== "" && c !== ".");
}

function lstatOrFail(target) {
	try {
		return fs.lstatSync(target);
	} catch (error) {
		fail(`cannot lstat ${target}: ${error.message}`);
	}
}

/**
 * Resolve `nominal` the way the kernel would, recording every traversed
 * directory and symlink node. Returns { nominal, resolved, chainNodes, hops,
 * finalKind, finalStat }. `chainNodes` preserves first-seen order; `hops`
 * records { link, target: raw readlink } in resolution order.
 *
 * Terminal-link correctness: when a trailing symlink's target contributes
 * no components (".", "./", "/") or finishes inside a directory, the
 * resolved path is that directory — never the link spelling itself — so
 * realpath(3) agrees and legitimate aliases are not misrejected.
 */
export function walkResolution(nominal, { finalKind = "any" } = {}) {
	if (typeof nominal !== "string" || !path.isAbsolute(nominal)) fail(`path must be absolute: ${nominal}`);
	const chainNodes = [];
	const seenNodes = new Set();
	const noteNode = (node) => {
		if (!seenNodes.has(node)) {
			seenNodes.add(node);
			chainNodes.push(node);
		}
	};
	const hops = [];
	let hopCount = 0;
	let current = "/"; // invariant: always a fully resolved real directory
	let resolvedPath = "/";
	let finalStat = lstatOrFail("/");
	const queue = rawComponents(nominal);
	while (queue.length > 0) {
		const component = queue.shift();
		if (component === "..") {
			// current is fully resolved, so dirname is the true kernel parent.
			current = path.dirname(current);
			if (queue.length === 0) {
				resolvedPath = current;
				finalStat = lstatOrFail(current);
			}
			continue;
		}
		const candidate = current === "/" ? `/${component}` : `${current}/${component}`;
		const st = lstatOrFail(candidate);
		if (st.isSymbolicLink()) {
			noteNode(candidate);
			if (++hopCount > MAX_SYMLINK_HOPS) fail(`too many symlink hops resolving ${nominal} (loop?)`);
			const raw = fs.readlinkSync(candidate);
			hops.push({ link: candidate, target: raw });
			if (path.isAbsolute(raw)) current = "/";
			// Splice the target's RAW components ahead of the unconsumed rest;
			// ".." inside them applies to the actually-resolved directory.
			queue.unshift(...rawComponents(raw));
			if (queue.length === 0) {
				// The link IS the final step: it resolves to the directory it
				// points at ("."/"./"/"/" contribute nothing), which is the
				// current fully-resolved directory.
				resolvedPath = current;
				finalStat = lstatOrFail(current);
			}
			continue;
		}
		resolvedPath = candidate;
		if (queue.length > 0 && !st.isDirectory()) fail(`path component is not a directory: ${candidate}`);
		if (st.isDirectory()) {
			noteNode(candidate);
			current = candidate;
		}
		if (queue.length === 0) finalStat = st;
	}
	let nativeResolved;
	try {
		nativeResolved = fs.realpathSync.native(nominal);
	} catch (error) {
		fail(`cannot resolve ${nominal} (broken link or loop): ${error.message}`);
	}
	if (nativeResolved !== resolvedPath) {
		fail(`resolver/kernel divergence for ${nominal}: walked to ${resolvedPath}, kernel realpath is ${nativeResolved}`);
	}
	if (finalKind === "directory" && !finalStat.isDirectory()) fail(`resolved path is not a directory: ${resolvedPath}`);
	if (finalKind === "file" && !finalStat.isFile()) fail(`resolved path is not a regular file: ${resolvedPath}`);
	return { nominal, resolved: resolvedPath, chainNodes, hops, finalKind, finalStat };
}

/** Protected sets: trees reject BOTH ancestor and descendant overlap; nodes reject a workspace root covering them. */
export function buildProtectedSets() {
	return { trees: [], nodes: new Set() };
}

function addProtectedTree(sets, walk) {
	sets.trees.push({ nominal: walk.nominal, resolved: walk.resolved });
	for (const node of walk.chainNodes) sets.nodes.add(node);
	sets.nodes.add(walk.nominal);
	sets.nodes.add(walk.resolved);
}

function addProtectedNodes(sets, walk) {
	for (const node of walk.chainNodes) sets.nodes.add(node);
	sets.nodes.add(walk.nominal);
	sets.nodes.add(walk.resolved);
}

/** All existing bwrap candidates on PATH, in PATH order (duplicates removed). */
export function findBwrapCandidates(env) {
	const pathValue = env.PATH ?? "";
	const candidates = [];
	const seen = new Set();
	for (const directory of pathValue.split(":")) {
		if (directory === "") continue;
		const candidate = path.join(directory, "bwrap");
		if (seen.has(candidate)) continue;
		seen.add(candidate);
		try {
			fs.lstatSync(candidate);
			candidates.push(candidate);
		} catch {
			// Absent or unreadable candidate: not a layout error. Backend
			// availability stays the native chain's decision.
		}
	}
	return candidates;
}

/**
 * One-time read-only layout collection (call BEFORE registering; Linux only).
 *
 * @param options.env - environment map (HOME, PATH); injectable for tests.
 * @param options.dshHome - resolved DSH home (ctx.dshHomePath()).
 * @param options.paths - { dshRoot, packageDir, nodeExecutable } from peers.
 * @param options.additionalRoots - validated extra roots as [{ index, path }]
 *   (index is the entry's position in the row config, for error reporting).
 * @returns { sets, layoutErrors, additionalRootErrors, bwrapCandidates, observations }
 *   layoutErrors: [{ path, reason }] for EXPECTED built-in paths that failed
 *   collection; the provider rejects Linux workspace-write while any exist.
 *   additionalRootErrors: [{ index, path, reason }] for operator-supplied
 *   roots that failed collection; the provider reports them as config field
 *   errors with the original entry index.
 *   observations: non-blocking notes (e.g. bwrap candidates seen) that never
 *   affect registration or admission.
 */
export function collectLayout({ env, dshHome, paths, additionalRoots = [] }) {
	const sets = buildProtectedSets();
	const layoutErrors = [];
	const additionalRootErrors = [];
	const observations = [];
	const collect = (nominal, kind, apply) => {
		try {
			apply(walkResolution(nominal, { finalKind: kind }));
		} catch (error) {
			layoutErrors.push({ path: nominal, reason: error.message });
		}
	};

	// HOME: nodes only — never a tree — so ordinary $HOME subprojects stay
	// legal while "=HOME" and HOME-covering roots are refused.
	const home = env.HOME;
	if (typeof home !== "string" || !path.isAbsolute(home)) {
		layoutErrors.push({ path: String(home), reason: "HOME is unset or not absolute; cannot anchor the deployment layout" });
	} else {
		collect(home, "directory", (walk) => addProtectedNodes(sets, walk));
	}

	// Key directories as protection trees (bidirectional overlap).
	collect(dshHome, "directory", (walk) => addProtectedTree(sets, walk));
	collect(paths.dshRoot, "directory", (walk) => addProtectedTree(sets, walk));
	collect(paths.packageDir, "directory", (walk) => addProtectedTree(sets, walk));

	// The Node executable and every existing bwrap candidate: file nodes
	// (cover rule). No identity audit — PATH and the install are trusted.
	collect(paths.nodeExecutable, "file", (walk) => addProtectedNodes(sets, walk));
	const bwrapCandidates = findBwrapCandidates(env);
	for (const candidate of bwrapCandidates) {
		collect(candidate, "any", (walk) => addProtectedNodes(sets, walk));
	}
	if (bwrapCandidates.length === 0) {
		observations.push("no bwrap candidate found on PATH; backend availability is left to the native chain (Landlock fallback stays possible)");
	} else {
		observations.push(`bwrap candidates on PATH: ${bwrapCandidates.join(", ")}`);
	}

	// Operator-supplied extra roots: validated strings, each a protection
	// tree. They only ever WIDEN protection; they cannot shrink the built-in
	// set, and they add no writable mounts.
	for (const { index, path: root } of additionalRoots) {
		try {
			addProtectedTree(sets, walkResolution(root, { finalKind: "directory" }));
		} catch (error) {
			additionalRootErrors.push({ index, path: root, reason: error.message });
		}
	}

	return { sets, layoutErrors, additionalRootErrors, bwrapCandidates, observations };
}

/**
 * Resolve the per-call workspace root (Linux workspace-write only). The root
 * must be an existing absolute directory that realpath(3) can resolve; the
 * canonical spelling is what the native provider bind-mounts, so it is also
 * what layout admission compares.
 */
export function resolveSessionRoot(rawRoot) {
	if (typeof rawRoot !== "string" || !path.isAbsolute(rawRoot)) {
		fail(`workspace root must be an absolute path: ${rawRoot}`);
	}
	let canonical;
	try {
		canonical = fs.realpathSync.native(rawRoot);
	} catch (error) {
		fail(`workspace root cannot be resolved: ${rawRoot}: ${error.message}`);
	}
	let st;
	try {
		st = fs.statSync(canonical);
	} catch (error) {
		fail(`workspace root cannot be stat'ed: ${canonical}: ${error.message}`);
	}
	if (!st.isDirectory()) fail(`workspace root is not a directory: ${canonical}`);
	return canonical;
}

/**
 * Reject an unsupported or unsafe workspace-write root. `root` must already
 * be the canonical session root. A colon root is NOT rejected here: the
 * provider skips the whole enhancement for it after backend selection (the
 * native confinement stands), per the V7 GOPATH contract.
 */
export function assertWorkspaceAllowed(root, sets) {
	if (root === "/") fail('refusing workspace root "/"');
	for (const tree of sets.trees) {
		for (const form of [tree.nominal, tree.resolved]) {
			if (!form) continue;
			if (pathContains(form, root)) fail(`workspace root ${root} is inside protected tree ${form}`);
			if (pathContains(root, form)) fail(`workspace root ${root} covers protected tree ${form}`);
		}
	}
	for (const node of sets.nodes) {
		if (pathContains(root, node)) fail(`workspace root ${root} covers protected path ${node}`);
	}
}
