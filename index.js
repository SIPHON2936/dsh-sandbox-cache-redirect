/**
 * dsh-sandbox-cache-redirect — guarded sandbox provider for the V6.2
 * workspace cache/runtime redirection scheme.
 *
 * The entry resolves the Host's own module graph from the DSH CLI anchor
 * (this plugin runs inside the Host process), pins the runtime/seam versions
 * the runner's bwrap templates were reviewed against, then builds and exports
 * the GuardedProvider class. Any failure here aborts the bundle import: the
 * bundle patch keeps the native sandbox row disabled, so no sandbox service
 * registers and confined execution fails closed rather than falling back to
 * an unverified runner.
 */
import { resolveHostPeers } from "./lib/peers.js";
import { buildProvider } from "./lib/provider.js";

const shared = await resolveHostPeers({ packageUrl: new URL(".", import.meta.url) });

export default buildProvider(shared);
