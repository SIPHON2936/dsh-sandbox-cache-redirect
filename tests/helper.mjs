/**
 * Shared fixtures for the V7 test suite: private HOME-mkdtemp fixtures, a
 * minimal cordis-flavored ctx stub, and the real Host peer bundle resolved
 * once from the actual DSH installation (DSH_CLI override for CI).
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { format } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

export const PACKAGE_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
export const DSH_CLI = process.env.DSH_CLI ?? execFileSync("sh", ["-c", "command -v dsh"], { encoding: "utf8" }).trim();

/** Shared peer bundle, resolved once from the real Host installation. */
export const shared = await (await import("../lib/peers.js")).resolveHostPeers({ anchor: DSH_CLI, packageUrl: pathToFileURL(PACKAGE_DIR + path.sep) });

export function makeFixtureHome(t) {
	const home = fs.mkdtempSync(path.join(os.homedir(), path.sep, "dsh-v7-test-"));
	fs.mkdirSync(path.join(home, ".dsh"), { mode: 0o700 }); // the fixture DSH_HOME, always present like a real one
	t.after(() => fs.rmSync(home, { recursive: true, force: true }));
	return home;
}

export function makeWorkspace(t, home, name = "projects/demo") {
	const workspace = path.join(home, name);
	fs.mkdirSync(workspace, { recursive: true });
	return workspace;
}

/**
 * Minimal cordis-flavored ctx stub: real service table, stub loader tree
 * (same-tree rows configurable for timeout inheritance), captured warnings
 * and effect callbacks.
 */
export function makeCtx({ home, nativeRow, extraRows = [] } = {}) {
	const services = new Map();
	const warnings = [];
	const infos = [];
	const effects = [];
	const native = nativeRow === undefined
		? { id: "sandbox", name: "@deepseek-ai/dsh-sandbox-local", disabled: true }
		: nativeRow;
	const rows = [native, { id: "bash-sandbox", name: "@deepseek-ai/dsh-bash-sandbox" }, ...extraRows].filter(Boolean);
	const ownEntry = { parent: { data: rows, tree: { store: {} } } };
	const ctx = {
		fiber: { uid: 1 },
		warnings,
		infos,
		effects,
		reflect: { provide: (name, value) => services.set(`reflect:${name}`, value) },
		loader: {
			locate: () => "include:sandbox-cache-redirect",
			resolve: () => ownEntry,
		},
		sandboxPolicy: { resolve: () => ({ mode: "read-only", workspaceRoot: "/" }) },
		dshHomePath: (...segments) => path.join(home ?? os.homedir(), ".dsh", ...segments),
		logger: { info: (...args) => infos.push(format(...args)), warn: (...args) => warnings.push(format(...args)) },
		provide: (name, value) => services.set(name, value),
		get: (name) => services.get(name),
		// cordis ctx.effect(fn) runs fn() immediately and registers its
		// RETURNED function as the disposer; `effects` collects disposers.
		effect: (fn) => {
			const disposer = fn();
			if (typeof disposer === "function") effects.push(disposer);
		},
	};
	return ctx;
}

/** Build the provider class bound to a fixture environment/platform. */
export async function providerClass({ home, platform = "linux", path: fixturePath } = {}) {
	const { buildProvider } = await import("../lib/provider.js");
	return buildProvider(shared, {
		env: { HOME: home, PATH: fixturePath ?? path.join(home, "bin") },
		platform,
	});
}

/** Construct a provider instance with a fixture ctx. */
export async function makeProvider(t, { home, config = {}, platform, nativeRow, fixturePath } = {}) {
	const Class = await providerClass({ home, platform, fixturePath });
	const ctx = makeCtx({ home, nativeRow });
	const provider = new Class(ctx, config);
	t.after(() => {
		for (const effect of ctx.effects.splice(0)) effect();
	});
	return { provider, ctx };
}

/** Dispose a provider made by makeProvider (runs captured ctx.effect callbacks). */
export function dispose(ctx) {
	for (const effect of ctx.effects.splice(0)) effect();
}

/** Environment variable guard: sets keys, restores them afterwards. */
export function withEnv(t, patch) {
	const before = new Map();
	for (const key of Object.keys(patch)) {
		before.set(key, process.env[key]);
		if (patch[key] === undefined) delete process.env[key];
		else process.env[key] = patch[key];
	}
	t.after(() => {
		for (const [key, value] of before) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
	});
}
