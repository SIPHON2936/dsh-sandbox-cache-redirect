/**
 * Host peer resolution: this plugin runs inside the DSH Host process, so the
 * DSH CLI entry (process.argv[1], a stable fact of the trusted launch
 * environment) anchors module resolution to the very installation that is
 * running us. Imports then converge on the same module instances the Host
 * already loaded — subclass and error-identity checks depend on it.
 *
 * Versions of the DSH runtime and the sandbox seam packages are pinned:
 * the runner strictly matches DSH 0.2.1-alpha.2 bwrap profile templates, so
 * an upgraded runtime must fail loudly here and go through re-acceptance,
 * never silently confine with an unchecked template.
 */
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { fail } from "./trust.js";

export const PINNED_VERSIONS = {
	dsh: "0.2.1-alpha.2",
	sandboxLocal: "0.2.1-alpha.2",
	sandbox: "0.2.1-alpha.2",
};

export const RUNNER_FILE_NAME = "dsh-bwrap-redirect-v6-0ef04d1a72ad";
export const RUNNER_SHA256 = "0ef04d1a72ad9aa31a00e212246e8fb6765ed1948b74c654af8ce5e99b579216";

function readPackageVersion(require, specifier, mainPath) {
	try {
		return require(`${specifier}/package.json`).version;
	} catch {
		// The package may not export ./package.json; derive its root from the resolved main file.
		let directory = path.dirname(mainPath);
		while (true) {
			const candidate = path.join(directory, "package.json");
			if (fs.existsSync(candidate)) {
				const manifest = JSON.parse(fs.readFileSync(candidate, "utf8"));
				if (manifest.name === specifier) return manifest.version;
			}
			const parent = path.dirname(directory);
			if (parent === directory) break;
			directory = parent;
		}
		fail(`cannot determine the installed version of ${specifier}`);
	}
}

/**
 * @param anchor - DSH CLI entry to resolve from; defaults to process.argv[1].
 * @param packageUrl - this package's own directory URL (for the bundled runner).
 */
export async function resolveHostPeers({ anchor = process.argv[1], packageUrl } = {}) {
	if (!anchor) fail("cannot locate the DSH CLI entry (process.argv[1] is empty); the host launch environment is unsupported");
	let cliEntry;
	try {
		cliEntry = fs.realpathSync(anchor);
	} catch (error) {
		fail(`cannot resolve the DSH CLI entry ${anchor}: ${error.message}`);
	}
	const dshRoot = path.dirname(path.dirname(cliEntry));
	const dshManifest = JSON.parse(fs.readFileSync(path.join(dshRoot, "package.json"), "utf8"));
	if (dshManifest.name !== "@deepseek-ai/dsh") fail(`CLI entry ${cliEntry} does not belong to @deepseek-ai/dsh`);
	if (dshManifest.version !== PINNED_VERSIONS.dsh) {
		fail(`DSH ${dshManifest.version} is not the pinned ${PINNED_VERSIONS.dsh}; the bwrap profile templates must be re-reviewed before this plugin confines commands (upgrade discipline)`);
	}

	const require = createRequire(cliEntry);
	const resolve = (specifier) => {
		try {
			return require.resolve(specifier);
		} catch (error) {
			fail(`cannot resolve host peer ${specifier} from ${cliEntry}: ${error.message}`);
		}
	};
	const importPeer = async (specifier) => {
		const resolved = resolve(specifier);
		let canonical = fs.realpathSync(resolved);
		if (canonical.endsWith(".cjs")) {
			// The require condition may select a CJS twin; the Host loaded the
			// ESM twin, and sharing its instance keeps one module graph.
			const esmTwin = `${canonical.slice(0, -4)}.mjs`;
			if (fs.existsSync(esmTwin)) canonical = esmTwin;
		}
		return { module: await import(pathToFileURL(canonical).href), resolved, canonical };
	};

	// Sequential on purpose: parallel dynamic imports of one module graph can
	// trip Node's ESM/CJS race condition.
	const sandboxLocal = await importPeer("@deepseek-ai/dsh-sandbox-local");
	const sandbox = await importPeer("@deepseek-ai/dsh-sandbox");
	const schemastery = await importPeer("@deepseek-ai/schemastery");

	const versions = {
		dsh: dshManifest.version,
		sandboxLocal: readPackageVersion(require, "@deepseek-ai/dsh-sandbox-local", sandboxLocal.resolved),
		sandbox: readPackageVersion(require, "@deepseek-ai/dsh-sandbox", sandbox.resolved),
		schemastery: readPackageVersion(require, "@deepseek-ai/schemastery", schemastery.resolved),
	};
	if (versions.sandboxLocal !== PINNED_VERSIONS.sandboxLocal) fail(`dsh-sandbox-local ${versions.sandboxLocal} is not the pinned ${PINNED_VERSIONS.sandboxLocal}`);
	if (versions.sandbox !== PINNED_VERSIONS.sandbox) fail(`dsh-sandbox ${versions.sandbox} is not the pinned ${PINNED_VERSIONS.sandbox}`);

	const { LocalSandboxProvider } = sandboxLocal.module;
	const { SandboxUnavailableError, canonicalPath } = sandbox.module;
	const z = schemastery.module.default;
	if (typeof LocalSandboxProvider !== "function") fail("host dsh-sandbox-local did not export LocalSandboxProvider");
	if (typeof SandboxUnavailableError !== "function" || typeof canonicalPath !== "function") fail("host dsh-sandbox exports are incomplete");
	if (typeof z?.object !== "function") fail("host schemastery default export is unusable");

	const nodeExecutable = fs.realpathSync(process.execPath);
	const nodeRoot = path.dirname(path.dirname(nodeExecutable));
	if (!packageUrl) fail("internal error: packageUrl is required");
	const packageDir = fileURLToPath(packageUrl);

	return {
		LocalSandboxProvider,
		SandboxUnavailableError,
		canonicalPath,
		z,
		versions,
		paths: {
			cliEntry,
			dshRoot,
			nodeRoot,
			nodeExecutable,
			packageDir,
		},
		runnerFileName: RUNNER_FILE_NAME,
		expectedRunnerSha256: RUNNER_SHA256,
	};
}
