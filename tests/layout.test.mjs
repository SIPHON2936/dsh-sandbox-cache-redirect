/**
 * Layout collection and kernel-semantics resolution tests (G11/G12, §6).
 *
 * walkResolution must agree with realpath(3) on aliases, relative targets,
 * multi-hop chains, ".." combinations, and terminal links to "."/"./"/"/"
 * (the 6.x parser misrejected the last class). collectLayout builds the
 * protection sets without any trust audit: trees reject bidirectional
 * overlap, nodes reject covering roots, and HOME stays a node so ordinary
 * $HOME subprojects remain legal.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { makeFixtureHome, makeWorkspace } from "./helper.mjs";
import { assertWorkspaceAllowed, collectLayout, pathContains, resolveSessionRoot, walkResolution } from "../lib/layout.js";

function real(p) {
	return fs.realpathSync.native(p);
}

// --- G12: kernel-faithful resolution ---------------------------------------

test("G12 plain directory: resolved equals realpath, chain nodes recorded, no hops", (t) => {
	const home = makeFixtureHome(t);
	const dir = makeWorkspace(t, home);
	const walk = walkResolution(dir, { finalKind: "directory" });
	assert.equal(walk.resolved, real(dir));
	assert.deepEqual(walk.hops, []);
	assert.ok(walk.chainNodes.includes(dir));
	assert.ok(walk.chainNodes.includes(home));
});

test("G12 directory alias: final link resolves to the real target, link node recorded", (t) => {
	const home = makeFixtureHome(t);
	const realDir = makeWorkspace(t, home, "real/target");
	const alias = path.join(home, "alias");
	fs.symlinkSync(realDir, alias);
	const walk = walkResolution(alias, { finalKind: "directory" });
	assert.equal(walk.resolved, real(realDir));
	assert.deepEqual(walk.hops, [{ link: alias, target: realDir }]);
	assert.ok(walk.chainNodes.includes(alias));
});

test("G12 terminal links to '.', './' and '/' resolve to the containing/root directory (no misrejection)", (t) => {
	const home = makeFixtureHome(t);
	const base = makeWorkspace(t, home, "base");
	for (const [name, target, expected] of [
		["dot", ".", real(base)],
		["dotslash", "./", real(base)],
		["slash", "/", "/"],
	]) {
		const link = path.join(base, name);
		fs.symlinkSync(target, link);
		const walk = walkResolution(link);
		assert.equal(walk.resolved, expected, `${name} -> ${target}`);
		assert.equal(walk.finalStat.isDirectory(), true);
	}
});

test("G12 relative multi-hop chain: a->b->c resolves hop by hop with every link recorded", (t) => {
	const home = makeFixtureHome(t);
	const c = makeWorkspace(t, home, "c");
	fs.symlinkSync("c", path.join(home, "b"));
	fs.symlinkSync("b", path.join(home, "a"));
	const walk = walkResolution(path.join(home, "a"), { finalKind: "directory" });
	assert.equal(walk.resolved, real(c));
	assert.deepEqual(walk.hops.map((h) => h.target), ["b", "c"]);
});

test("G12 '..' applies to the actually-resolved directory across links (kernel equality)", (t) => {
	const home = makeFixtureHome(t);
	const sub = makeWorkspace(t, home, "p/q");
	const other = makeWorkspace(t, home, "p/other");
	fs.symlinkSync("q", path.join(home, "p", "link"));
	// "p/link/../other" must resolve like the kernel: link -> q, then ".." from p/q -> p, then other.
	const viaConcat = `${home}/p/link/../other`;
	const walk = walkResolution(viaConcat, { finalKind: "directory" });
	assert.equal(walk.resolved, real(other));
	assert.equal(walk.resolved, real(viaConcat));
	const trailing = walkResolution(`${home}/p/q/..`, { finalKind: "directory" });
	assert.equal(trailing.resolved, real(path.join(home, "p")));
});

test("G12 suffix through a parent-directory link is audited under the real target", (t) => {
	const home = makeFixtureHome(t);
	const realBase = makeWorkspace(t, home, "b/c");
	fs.symlinkSync(path.join(home, "b"), path.join(home, "link"));
	const walk = walkResolution(`${home}/link/c`, { finalKind: "directory" });
	assert.equal(walk.resolved, real(realBase));
	assert.deepEqual(walk.hops.map((h) => h.link), [path.join(home, "link")]);
});

test("G12 finalKind mismatches and broken links fail", (t) => {
	const home = makeFixtureHome(t);
	const file = path.join(home, "f");
	fs.writeFileSync(file, "x");
	assert.throws(() => walkResolution(file, { finalKind: "directory" }), /not a directory/);
	assert.throws(() => walkResolution(path.join(home, "missing")), /cannot lstat|cannot resolve/);
	fs.symlinkSync(path.join(home, "missing-target"), path.join(home, "broken"));
	assert.throws(() => walkResolution(path.join(home, "broken")), /cannot lstat|cannot resolve/);
});

// --- G11: protection sets and admission -------------------------------------

/** Deterministic fixture layout: all protected paths live inside the fixture home. */
function makeLayout(t, home, { additionalRoots = [], env } = {}) {
	const dshHome = path.join(home, ".dsh");
	const dshRoot = makeWorkspace(t, home, "host/dsh");
	const packageDir = makeWorkspace(t, home, "host/plugin");
	const nodeExecutable = path.join(home, "host/node");
	fs.writeFileSync(nodeExecutable, "binary");
	const binDir = path.join(home, "bin");
	fs.mkdirSync(binDir, { recursive: true });
	fs.writeFileSync(path.join(binDir, "bwrap"), "binary");
	return collectLayout({
		env: env ?? { HOME: home, PATH: binDir },
		dshHome,
		paths: { dshRoot, packageDir, nodeExecutable },
		additionalRoots,
	});
}

test("G11 ordinary project, prefix-similar dirs and subdirectory roots are allowed", (t) => {
	const home = makeFixtureHome(t);
	const extra = makeWorkspace(t, home, "projects/a");
	const layout = makeLayout(t, home, { additionalRoots: [{ index: 0, path: extra }] });
	assert.equal(layout.layoutErrors.length, 0);
	assert.equal(layout.additionalRootErrors.length, 0);
	assert.equal(layout.bwrapCandidates.length, 1);
	for (const root of [
		makeWorkspace(t, home, "projects/demo"),
		makeWorkspace(t, home, "projects/a2"), // prefix-similar to the additional root
		makeWorkspace(t, home, "projects/demo/sub/dir"),
	]) {
		assertWorkspaceAllowed(real(root), layout.sets);
	}
});

test("G11 '/', HOME, HOME-covering ancestors and protected-tree conflicts are refused", (t) => {
	const home = makeFixtureHome(t);
	const layout = makeLayout(t, home);
	const dshHome = path.join(home, ".dsh");
	const cases = [
		["/", '"/"'],
		[home, "covers protected"], // == HOME: covers the DSH_HOME tree (and the HOME node)
		[path.dirname(home), "covers protected"], // HOME-covering ancestor
		[path.join(dshHome, "sub"), "inside protected tree"],
		[path.dirname(path.join(home, "host/dsh")), "covers protected tree"], // parent of dshRoot
		[path.join(home, "host/dsh", "inner"), "inside protected tree"],
		[path.join(home, "host", "plugin", "inner"), "inside protected tree"],
		[path.join(home, "host"), "covers protected"], // covers the dshRoot/packageDir trees and the node executable
		[path.join(home, "bin"), "covers protected path"], // covers the bwrap candidate node
	];
	for (const [root, pattern] of cases) {
		fs.mkdirSync(root, { recursive: true });
		assert.throws(() => assertWorkspaceAllowed(real(root), layout.sets), new RegExp(pattern), root);
	}
});

test("G11 additional roots only widen protection: inside or covering them is refused, never the built-ins", (t) => {
	const home = makeFixtureHome(t);
	const extra = makeWorkspace(t, home, "data/keep");
	const layout = makeLayout(t, home, { additionalRoots: [{ index: 0, path: extra }] });
	fs.mkdirSync(path.join(extra, "inner"), { recursive: true });
	assert.throws(() => assertWorkspaceAllowed(real(path.join(extra, "inner")), layout.sets), /inside protected tree/);
	assert.throws(() => assertWorkspaceAllowed(real(path.join(home, "data")), layout.sets), /covers protected tree/);
	// Built-in protection is unchanged by the extra root: a normal project still passes.
	assertWorkspaceAllowed(real(makeWorkspace(t, home, "projects/demo")), layout.sets);
});

test("G11 symlinked additional root protects both the nominal and resolved forms", (t) => {
	const home = makeFixtureHome(t);
	const realKeep = makeWorkspace(t, home, "data/keep");
	const alias = path.join(home, "keep-alias");
	fs.symlinkSync(realKeep, alias);
	const layout = makeLayout(t, home, { additionalRoots: [{ index: 0, path: alias }] });
	assert.equal(layout.layoutErrors.length + layout.additionalRootErrors.length, 0);
	assert.throws(() => assertWorkspaceAllowed(real(realKeep), layout.sets), /inside protected tree/);
	assert.throws(() => assertWorkspaceAllowed(home, layout.sets), /covers/);
});

test("collection failures are recorded per class: HOME, expected paths, additional entries", (t) => {
	const home = makeFixtureHome(t);
	const noHome = makeLayout(t, home, { env: { PATH: path.join(home, "bin") } });
	assert.equal(noHome.layoutErrors.some((e) => /HOME is unset or not absolute/.test(e.reason)), true);

	const missingDshHome = collectLayout({
		env: { HOME: home, PATH: path.join(home, "bin") },
		dshHome: path.join(home, ".dsh-missing"),
		paths: { dshRoot: path.join(home, "host/dsh"), packageDir: path.join(home, "host/plugin"), nodeExecutable: path.join(home, "host/node") },
	});
	assert.equal(missingDshHome.layoutErrors.some((e) => e.path.endsWith(".dsh-missing")), true);

	const badRoots = makeLayout(t, home, { additionalRoots: [{ index: 2, path: path.join(home, "missing-root") }] });
	assert.deepEqual(badRoots.additionalRootErrors.map((e) => e.index), [2]);
});

test("resolveSessionRoot: canonicalizes existing directories, refuses missing/file/relative roots", (t) => {
	const home = makeFixtureHome(t);
	const dir = makeWorkspace(t, home);
	assert.equal(resolveSessionRoot(dir), real(dir));
	const alias = path.join(home, "ws-alias");
	fs.symlinkSync(dir, alias);
	assert.equal(resolveSessionRoot(alias), real(dir));
	const file = path.join(home, "f");
	fs.writeFileSync(file, "x");
	assert.throws(() => resolveSessionRoot(file), /not a directory/);
	assert.throws(() => resolveSessionRoot(path.join(home, "missing")), /cannot be resolved/);
	assert.throws(() => resolveSessionRoot("relative/path"), /absolute path/);
});

test("pathContains: containment semantics used by tree and node rules", () => {
	assert.equal(pathContains("/a", "/a"), true);
	assert.equal(pathContains("/a", "/a/b"), true);
	assert.equal(pathContains("/a/b", "/a"), false);
	assert.equal(pathContains("/a", "/a2"), false, "prefix-similar is not containment");
	assert.equal(pathContains("/", "/a"), true);
});
