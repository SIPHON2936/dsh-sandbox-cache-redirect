# dsh-sandbox-cache-redirect

[中文](README.md) | English

A bundle plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH), V7 pluggable scheme, Linux.

It redirects the uv/pip/npm/Go cache and runtime directories of `workspace-write` confined commands into the project, fixing tool failures caused by unwritable default cache locations inside the sandbox — no per-command cache prefixes. **This version is pluggable: the enhancement lives only in this bundle's own patch layer. Disabling or uninstalling restores the native sandbox as the other effective configuration layers decide — no manual cleanup.**

## Why

DSH's workspace-write mode maps the host root filesystem read-only, leaving only the workspace and a per-command `/tmp` tmpfs writable. Tools like uv default to caches under `~/.cache` (read-only territory), so the command fails:

```text
Failed to initialize cache at .../.cache/uv
Read-only file system (os error 30)
```

This plugin makes DSH inject tool-specific directory variables when it invokes bwrap: caches, Python runtimes, and Go state all land inside the project.

## How it works

```text
bash / GUI PTY / other same-realm consumers
  → sandbox.confine(payload, policy, signal)
  → the native LocalSandboxProvider selects the backend and builds the argv
    (bwrap, with Landlock fallback)
  → when bwrap is selected, nine environment options are inserted at the
    "--" before the payload; other backends pass through unchanged
  → DSH's original subprocess/PTY execution, cancellation, and error
    classification
```

The nine injected variables:

| Variable | Project-relative path |
|---|---|
| `UV_CACHE_DIR` | `.dsh-cache/uv` |
| `PIP_CACHE_DIR` | `.dsh-cache/pip` |
| `npm_config_cache` | `.dsh-cache/npm` |
| `GOCACHE` | `.dsh-cache/go-build` |
| `UV_PYTHON_CACHE_DIR` | `.dsh-cache/uv-python` |
| `UV_PYTHON_INSTALL_DIR` | `.dsh-state/uv/python` |
| `UV_PYTHON_BIN_DIR` | `.dsh-state/uv/bin` |
| `GOMODCACHE` | `.dsh-cache/go-mod` |
| `GOPATH` | `.dsh-state/go` |

The cache root comes from the current call's session workspace root (canonical path), not the command cwd. The tools create these directories themselves inside the sandbox; the plugin never pre-creates anything on the host, adds no writable mounts, and never touches the Host's `process.env`, PATH, HOME, or any configuration.

## State contract

| State | Behavior |
|---|---|
| Not installed / disabled / uninstalled / bundle skipped by DSH | The plugin's configuration layer exits; the native provider returns as the other layers decide; no readiness dependency or patch remains |
| Linux + workspace-write + native bwrap + valid layout | Full nine-variable injection; native mounts and payload preserved |
| Linux + workspace-write + native Landlock | Native result returned as-is; one explicit downgrade warning per provider instance; **cache redirection is not claimed active** (uv and friends may still fail on unwritable default caches) |
| read-only | Native result returned as-is; no injection, no spurious enhancement warnings |
| danger-full-access | DSH consumers bypass confine as usual; a direct low-level call to this provider with that mode is refused |
| Unknown mode, dangerous workspace, incompatible native return shape, revoked instance | The current call fails closed — the original argv is never returned, nothing runs unsandboxed |
| Both bwrap and Landlock unavailable | The native SandboxUnavailableError propagates |
| Config field errors or unresolvable expected layout | The provider still registers; Linux workspace-write calls are refused with a remediation path; read-only calls are unaffected |
| Workspace root containing a colon (e.g. `/data/proj:ect`) | Layout checks still apply; because a colon cannot be expressed in the Unix GOPATH list syntax, the **whole enhancement is skipped**, native confinement stands, one warning per instance (unlike 6.x, which refused such workspaces outright) |

## Capability boundaries (intentional reductions vs 6.x)

- **No bwrap binary identity verification.** This version reuses DSH's native PATH resolution and functional probes; the old audits of bwrap/python ownership, setuid/setgid bits, writable bits, and the whole execution trust chain are **not retained**. The Host launch environment, installation, and PATH must be trusted.
- **Environment visibility reduction.** The plugin can only enumerate canonical keys and case aliases present in the Host's `process.env` at call time (aliases are unset inside the sandbox before the canonical key is set to the workspace value). Aliases introduced solely via `spec.env`/`spec.dshEnv`, never seen by the Host, cannot be enumerated and may still enter the sandbox and affect tool configuration; complete redirection for such customized calls is not guaranteed. Canonical keys themselves are always set to workspace values (bwrap applies the argv environment options before the sandboxed process starts, and the native environment scrubbing does not revoke options carried in argv).
- No external Python runner, no installer, no runner digest pinning, and no profile-layer fail-closed patch anymore.
- Non-Linux platforms: no cache redirection promised; when this package loads there, native provider results pass through and the unsupported platform is reported.

Retained protection: a one-time read-only deployment layout collection (HOME, DSH_HOME, the actual Host/plugin/Node paths, and bwrap candidates on PATH) records the Host code and configuration domains as protection trees/nodes; a workspace root overlapping them in either direction, or covering them, is refused per call. This only prevents a workspace from covering Host dependencies — it does **not** replace the removed binary identity audits.

## Configuration

This row supports exactly two fields:

- `probeTimeoutMs`: a positive integer. An explicit value wins; when unset, a plain positive integer from the same-tree native sandbox row's config is inherited; otherwise the verified SDK default (5000) applies.
- `additionalProtectedRoots`: an array of resolvable absolute directories. Each entry becomes a protection tree (a workspace root equal to it, inside it, or covering it is refused), always **merged** with the built-in protection set (it can only widen, never shrink), and adds no writable mounts.

**The effective types and value requirements are governed by the business validation contract in this section; the wide receiving types (any) shown by `--dump-config-schema` and the manager UI are NOT the business type basis — any does not mean any value will run.**

Error handling: unknown fields, an invalid `probeTimeoutMs`, non-array/relative/missing/non-directory/unresolvable `additionalProtectedRoots` entries, and expected-layout collection failures are all recorded as config/layout error states (log tags `CACHE_REDIRECT_CONFIG` / `CACHE_REDIRECT_LAYOUT`, naming the entry, field, index, and reason). The provider still registers; read-only calls are unaffected; Linux workspace-write calls are precisely refused with the remediation path: **fix this row's config/directories and reload or restart, or disable this bundle to restore the native provider**. Fixing the config and reloading (a rebuilt instance) recovers.

## Enable, disable, uninstall, recovery

- **Manager UI (web)**: toggle the bundle; act on the returned `applied` / `restart-required` (the latter needs a restart). The native sandbox returns on disable — no YAML editing.
- **Uninstall**: `dsh plugin --profile <p> remove dsh-sandbox-cache-redirect`. The dependency and the bundle selection are revoked by the manager together.
- **Profiles without a GUI (e.g. headless)**: with the profile's Host stopped and a backup made, use the shipped offline selection script (it changes only the bundle selection — no dependencies, no YAML):
  ```bash
  node ~/.dsh/profiles/<p>/node_modules/dsh-sandbox-cache-redirect/tools/bundle-selection.mjs \
    "$(command -v dsh)" ~/.dsh/profiles/<p> disable   # re-enable: enable
  ```
  The script respects the profile's existing exact-version exemptions and never grants or edits them. After saving the selection, restart the profile and verify with `--dump-config`.
- **Recovery from construct/import failure**: when the management plane is available, disable the bundle there; otherwise stop the Host, revoke the selection with the offline script above, and start again — the native configuration is back. No manual YAML deletion.

Note: already-started processes, background tasks, and PTYs keep the environment and isolation they were created with; disabling never rewrites them retroactively. To switch completely, finish old tasks normally and close/recreate persistent terminals.

## Supported scope

- Platform: Linux (the enhancement only applies on the Linux + workspace-write + bwrap path).
- Verified environment: Fedora 44 (WSL2), DSH 0.2.1-alpha.2, Node 24, bwrap 0.12.0; npm-form DSH CLI/Host. Packaged Electron, other launchers, and remote executors are not verified.
- The peer range stays conservative: only versions with real acceptance evidence are declared; after a DSH upgrade, re-run compatibility acceptance before widening. Runtime no longer performs fixed version-string equality; per-call structural contracts (payload suffix, selectedRunner shape, metadata) fail the call closed on incompatibility instead.
- Projects using GOPATH source mode or depending on a host-custom GOPATH are not promised compatibility; the plugin never sets GOSUMDB=off and never modifies GOPROXY/GOTOOLCHAIN/GOFLAGS.

## For project maintainers: .gitignore

If you use this plugin in a Git project, keep your existing rules and append to the project root `.gitignore`:

```gitignore
/.dsh-cache/
/.dsh-state/
```

Caches and locally downloaded runtimes should not be committed; the Python under `.dsh-state` may also be referenced by existing venvs. Ignore rules do not untrack already-tracked files — handle those per your project's own process. The plugin never edits `.gitignore` and never runs `git rm`; disabling or uninstalling does not delete these runtime directories.

## Migrating from 6.x

The 6.x scheme shipped an external runner and a profile-layer fail-closed patch, so uninstalling did not restore the native sandbox. Migration to 7.x must follow this order: stop the affected Hosts → uninstall the old package via `dsh plugin remove` → precisely remove the old guard entry from each profile's `cordis.patch.yml` (the `id: sandbox` entry carrying the `sandboxCacheRedirectGuardReady` inject — keep every other user setting) → delete the old dedicated runner (`~/.local/libexec/dsh/dsh-bwrap-redirect-v6-*`; treat V3-era files like `~/.local/bin/dsh-bwrap-redirect` separately by reference) → start the Host and verify the native baseline (confined bash works, isolation holds) → then install 7.x. See section 10 of the construction plan for the full procedure and acceptance ordering.

## Acceptance

The delivery ships same-version acceptance tools: `tools/session-check.py` (run inside a real confined session: nine variables, workspace write, out-of-workspace sentinel denial, backend mount evidence, token marker; `--expect native` for native-baseline acceptance) and `tools/bundle-selection.mjs` (offline enable/disable for GUI-less profiles). Test suite: `node --test tests/*.test.mjs` (needs a DSH CLI installed locally, or set `DSH_CLI=/path/to/dsh`).

License: MIT.
