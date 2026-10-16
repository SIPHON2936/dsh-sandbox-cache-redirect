/**
 * dsh-sandbox-cache-redirect — pluggable cache/runtime redirection for the
 * native local sandbox provider (V7 scheme).
 *
 * The entry resolves the Host's own module graph from the DSH CLI anchor
 * (this plugin runs inside the Host process) and builds the provider class:
 * a LocalSandboxProvider subclass that injects the nine cache/runtime
 * environment options into the native bwrap argv for Linux workspace-write
 * calls. There is no external runner, no installation step, and no
 * profile/home patch: disabling or removing this bundle restores the native
 * provider as the other configuration layers decide.
 *
 * A resolution failure here still aborts the bundle import (the bundle
 * patch disables the native row, so confined execution fails closed); the
 * manager's disable path and tools/bundle-selection.mjs do not import this
 * module, so recovery never depends on it loading.
 */
import { resolveHostPeers } from "./lib/peers.js";
import { buildProvider } from "./lib/provider.js";

const shared = await resolveHostPeers({ packageUrl: new URL(".", import.meta.url) });

export default buildProvider(shared);
