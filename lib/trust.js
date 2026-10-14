/**
 * Trust-chain path auditing primitives for the guarded sandbox provider.
 *
 * Two audit policies live here:
 *   - STRICT (install chain): every existing component must be a real
 *     directory — symlinks are refused — owned by root or the current user,
 *     and never group/other-writable. Used for the runner install chain
 *     ($HOME/.local/libexec/dsh), where no symlink is legitimate.
 *   - DUAL (trusted dependencies): nominal-path parents are audited, ordinary
 *     symlinks are tolerated, and the fully resolved chain is then audited
 *     strictly. Used for python3/bwrap/Node/DSH/plugin trees, where symlinks
 *     (e.g. /usr/bin/python3) are normal.
 *
 * These checks run on a trusted host with configuration competitors stopped;
 * they do not defend against a same-uid malicious host process racing paths.
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

/** Absolute components of `target` from the filesystem root to the path itself, inclusive. */
export function pathComponents(target) {
	if (!path.isAbsolute(target)) fail(`path must be absolute: ${target}`);
	const parts = [];
	let current = path.normalize(target);
	while (true) {
		parts.push(current);
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
	}
	return parts.reverse();
}

function lstatOrFail(target) {
	try {
		return fs.lstatSync(target);
	} catch (error) {
		fail(`cannot lstat ${target}: ${error.message}`);
	}
}

function assertTrustedDirectory(target, st) {
	if ((st.mode & 0o022) !== 0) fail(`directory is group/world-writable: ${target}`);
	if (st.uid !== 0 && st.uid !== process.geteuid()) fail(`directory owned by untrusted uid ${st.uid}: ${target}`);
}

/**
 * STRICT policy: audit every existing component of `directory`; return the
 * index of the first missing component (components.length when all exist).
 * Any symlink, non-directory, untrusted owner, or writable directory fails
 * before the caller creates anything.
 */
export function auditInstallChain(directory) {
	const components = pathComponents(directory);
	for (let i = 0; i < components.length; i++) {
		let st;
		try {
			st = fs.lstatSync(components[i]);
		} catch (error) {
			if (error.code === "ENOENT") return { components, firstMissing: i };
			fail(`cannot lstat install chain component ${components[i]}: ${error.message}`);
		}
		if (st.isSymbolicLink()) fail(`install chain component is a symlink: ${components[i]}`);
		if (!st.isDirectory()) fail(`install chain component is not a directory: ${components[i]}`);
		assertTrustedDirectory(components[i], st);
	}
	return { components, firstMissing: components.length };
}

/** Create the missing components reported by auditInstallChain, one level at a time, re-checking each creation. */
export function createMissingComponents(components, firstMissing) {
	for (let i = firstMissing; i < components.length; i++) {
		fs.mkdirSync(components[i], { mode: 0o700 });
		const st = lstatOrFail(components[i]);
		if (st.isSymbolicLink() || !st.isDirectory()) fail(`created install chain component became invalid: ${components[i]}`);
		assertTrustedDirectory(components[i], st);
	}
}

/** Re-audit an established install chain (per-call): every component must still be a real trusted directory. */
export function reverifyInstallChain(directory) {
	for (const component of pathComponents(directory)) {
		const st = lstatOrFail(component);
		if (st.isSymbolicLink()) fail(`install chain component became a symlink: ${component}`);
		if (!st.isDirectory()) fail(`install chain component is no longer a directory: ${component}`);
		assertTrustedDirectory(component, st);
	}
}

/**
 * DUAL policy for a trusted dependency path (file or directory). Audits the
 * nominal path's parents, tolerates ordinary symlinks, then strictly audits
 * the fully resolved chain. Returns both spellings plus the directory nodes
 * that participated in resolution (for protected-node comparison).
 */
export function auditDualPath(nominal, { finalKind = "any" } = {}) {
	if (!path.isAbsolute(nominal)) fail(`path must be absolute: ${nominal}`);
	const nominalComponents = pathComponents(nominal);
	const chainNodes = [];
	for (let i = 0; i < nominalComponents.length - 1; i++) {
		const st = lstatOrFail(nominalComponents[i]);
		if (!st.isSymbolicLink()) assertTrustedDirectory(nominalComponents[i], st);
		chainNodes.push(nominalComponents[i]);
	}
	const nominalFinal = lstatOrFail(nominal);
	if (!nominalFinal.isSymbolicLink()) {
		if (finalKind === "directory" && !nominalFinal.isDirectory()) fail(`not a directory: ${nominal}`);
		if (finalKind === "file" && !nominalFinal.isFile()) fail(`not a regular file: ${nominal}`);
		if (finalKind === "directory" && nominalFinal.isDirectory()) assertTrustedDirectory(nominal, nominalFinal);
	}
	let resolved;
	try {
		resolved = fs.realpathSync(nominal);
	} catch (error) {
		fail(`cannot resolve ${nominal} (broken link or loop): ${error.message}`);
	}
	const resolvedComponents = pathComponents(resolved);
	for (let i = 0; i < resolvedComponents.length - 1; i++) {
		const st = lstatOrFail(resolvedComponents[i]);
		if (st.isSymbolicLink()) fail(`resolved chain unexpectedly contains a symlink: ${resolvedComponents[i]}`);
		assertTrustedDirectory(resolvedComponents[i], st);
		chainNodes.push(resolvedComponents[i]);
	}
	const resolvedFinal = lstatOrFail(resolved);
	if (finalKind === "directory") {
		if (!resolvedFinal.isDirectory()) fail(`resolved path is not a directory: ${resolved}`);
		assertTrustedDirectory(resolved, resolvedFinal);
	}
	if (finalKind === "file" && !resolvedFinal.isFile()) fail(`resolved path is not a regular file: ${resolved}`);
	return { nominal, resolved, chainNodes, finalStat: resolvedFinal };
}

/** DUAL policy for a trusted executable: regular, non-setuid/setgid, non-writable, trusted owner, executable. */
export function auditTrustedExecutable(nominal) {
	const audited = auditDualPath(nominal, { finalKind: "file" });
	const st = audited.finalStat;
	if ((st.mode & 0o4000) !== 0) fail(`executable is setuid: ${audited.resolved}`);
	if ((st.mode & 0o2000) !== 0) fail(`executable is setgid: ${audited.resolved}`);
	if ((st.mode & 0o022) !== 0) fail(`executable is group/world-writable: ${audited.resolved}`);
	if (st.uid !== 0 && st.uid !== process.geteuid()) fail(`executable owned by untrusted uid ${st.uid}: ${audited.resolved}`);
	if ((st.mode & 0o111) === 0) fail(`not executable: ${audited.resolved}`);
	return {
		nominal: audited.nominal,
		resolved: audited.resolved,
		chainNodes: audited.chainNodes,
		dev: st.dev,
		ino: st.ino,
		uid: st.uid,
		mode: st.mode & 0o7777,
	};
}

/**
 * Protected sets: trees reject BOTH ancestor and descendant overlap with the
 * workspace root; nodes reject a workspace root that covers them (ancestor
 * or equal). HOME participates only as a chain node of the runner install
 * path — never as a whole protected tree — so $HOME/projects/foo stays legal.
 */
export function buildProtectedSets() {
	return { trees: [], nodes: new Set() };
}

export function addProtectedTree(sets, tree) {
	sets.trees.push({ nominal: tree.nominal, resolved: tree.resolved });
	for (const node of tree.chainNodes ?? []) sets.nodes.add(node);
	sets.nodes.add(tree.nominal);
	sets.nodes.add(tree.resolved);
}

export function addProtectedNode(sets, node) {
	sets.nodes.add(node);
}

/** Reject an unsupported or unsafe workspace-write root. `root` must already be the canonical root. */
export function assertWorkspaceAllowed(root, sets) {
	if (typeof root !== "string" || !path.isAbsolute(root)) fail(`workspace root must be an absolute path: ${root}`);
	if (root === "/") fail('refusing workspace root "/"');
	if (root.includes(":")) fail(`refusing workspace root containing ":": ${root}`);
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
