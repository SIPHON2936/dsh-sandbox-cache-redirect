# dsh-sandbox-cache-redirect

[中文](README.md) | English

A bundle plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH). Once installed, bash commands confined under `workspace-write` automatically write their uv/pip/npm/Go caches and runtimes into the current project — no per-command cache prefixes, no prompt-level reminders.

> [!IMPORTANT]
> **Linux only.** This plugin relies on Linux-specific bubblewrap (bwrap) confinement and user namespaces. DSH on macOS and Windows uses entirely different sandbox backends, and this package refuses to load there. Tested on Fedora 44 (WSL2); see "Supported scope" at the bottom.

## Why

DSH's workspace-write mode maps the host root filesystem read-only, leaving only the workspace and a per-command `/tmp` tmpfs writable. Tools like uv default to caches under `~/.cache` (read-only territory), so the command fails:

```text
Failed to initialize cache at .../.cache/uv
Read-only file system (os error 30)
```

This plugin makes DSH inject tool-specific directory variables whenever it invokes bwrap, so caches, Python runtimes, and Go state all land inside the project.

## How it works

```text
DSH bash executor → sandbox.confine(argv, policy)
  → /usr/bin/python3 -IS <trusted runner> <bwrap profile> -- bash -c <command>
  → runner strictly matches the DSH 0.2.1-alpha.2 bwrap templates and injects
    nine directory variables before the --
  → /usr/bin/bwrap (caches/runtimes land in the workspace)
```

The bundle does two things (a **guarded provider** structure since 6.2.1):

1. **cordis.patch.yml** disables the native `sandbox` entry and attaches a readiness dependency to it (so a higher patch layer that re-enables it still cannot activate while the guarded provider is unhealthy); it then inserts this package's guarded entry.
2. **The guarded provider (index.js + lib/)** subclasses the Host's own `LocalSandboxProvider` and bakes "verify before registering, re-verify on every call" into its construction and call paths:
   - **Before registering** (prepare): platform/UID gates; composition checks (native row disabled with its inject blocker in place, bash row intact); dual-path identity audits of python3/bwrap (**including the setuid bit**, before any version query); bwrap ≥ 0.12.0 (the CVE-2026-87766 fix floor) and `python3 -IS` flags; the bundled runner's digest must equal `0ef04d1a…579216`; the install chain is **audited level by level before anything is created** (symlinks, group/other-writable or untrusted-owned directories refused); the runner is **atomically published** via staging + exclusive `link()` (an existing file is reused only if it is a same-digest, user-owned, mode-0500, single-link regular file — **never overwritten**).
   - **On every confine**: re-checks the runner's inode/bytes, python/bwrap identity, and instance liveness; validates the call's mode and the actual session root (refusing `/`, all of HOME, colon-bearing paths, and any workspace layout overlapping the **protected sets** — runner, DSH_HOME, the DSH installation, this plugin package, the Python stdlib, and operator-added roots); after delegating argv generation to the native method, it asserts byte-for-byte that the result is exactly "pinned runner + locked template + original payload".
   - Every failure raises a structured `SandboxUnavailableError` — never returns the raw command, never swaps in a local executor, never retries with more privilege.

If any stage fails, `ctx.sandbox` is never registered: the confined bash executor that requires it stays unavailable and **fails closed** instead of falling back to an uncertified runner.

The runner itself only matches strings and execs: it creates, resolves, or cleans no cache directories on the host and adds no mounts; unknown bwrap profiles are rejected outright, never passed through as unsandboxed commands.

The provider row's config is strict: only an optional positive-integer `probeTimeoutMs` and an optional absolute-directory array `additionalProtectedRoots` (which can only widen the protected sets) are accepted; `runnerCommand` and every other field is rejected — no configuration layer can point the runner elsewhere.

## The nine redirected directories

| Variable | Path under the workspace | Purpose |
|---|---|---|
| UV_CACHE_DIR | .dsh-cache/uv | uv dependency cache |
| PIP_CACHE_DIR | .dsh-cache/pip | pip download/build cache |
| npm_config_cache | .dsh-cache/npm | npm/npx cache and logs |
| GOCACHE | .dsh-cache/go-build | Go build cache |
| UV_PYTHON_CACHE_DIR | .dsh-cache/uv-python | managed Python archive cache |
| UV_PYTHON_INSTALL_DIR | .dsh-state/uv/python | installed Python interpreters (persistent runtime) |
| UV_PYTHON_BIN_DIR | .dsh-state/uv/bin | managed Python entry links |
| GOMODCACHE | .dsh-cache/go-mod | Go modules and sumdb cache |
| GOPATH | .dsh-state/go | sumdb checkpoints and other Go state |

The tools create these directories inside the sandbox themselves; nothing needs to be pre-created on the host. `read-only` mode passes the variables through without injection; `danger-full-access` bypasses the runner entirely.

Exclude `.dsh-cache/` and `.dsh-state/` in your project's `.gitignore`, `.dockerignore`, packaging, and backup rules:

```gitignore
.dsh-cache/
.dsh-state/
```

## Install and uninstall

### Option 1: one-command install via dsh (recommended)

```bash
dsh plugin --profile <your-profile> add github:Siphon2673/dsh-sandbox-cache-redirect
```

This installs the repository as a git dependency into the given profile and registers the bundle. The package ships no build scripts, so no pnpm allowBuilds exemption is needed.

### Option 2: pack it yourself

```bash
git clone https://github.com/Siphon2673/dsh-sandbox-cache-redirect.git
cd dsh-sandbox-cache-redirect
npm pack           # produces dsh-sandbox-cache-redirect-<version>.tgz
```

Then install the tarball in the DSH plugin manager — or download a ready-made tarball from the GitHub Releases page (built automatically by the tag-triggered release workflow).

Either way the bundle is copied into the profile's node_modules, never linked to the source tree.

Uninstall / roll back:

- Temporary: disable the bundle in the plugin manager — the sandbox falls back to the built-in bwrap backend; the runner file is kept.
- Permanent: remove the bundle. Python interpreters under `.dsh-state` may still be referenced by project virtualenvs; use uv's own commands to retire them instead of deleting the directory.

## Acceptance tools

`tools/` ships two standalone re-verification tools (Python standard library only):

```bash
# Standalone smoke: run on the host; --parent must be a private directory
# outside both the workspace and /tmp
/usr/bin/python3 -IS tools/smoke-v6.py \
  --wrapper "$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad" \
  --parent "$HOME/<private-dir>"
```

The smoke suite covers: nine-variable injection, a host-writable positive control, explicit EROFS, workspace persistence, /tmp not leaking back to the host, read-only passthrough/refusal, and rejection of unknown profiles without executing the payload.

`tools/session-check-v6.py` is for end-to-end session acceptance: copy it to a private location, then have the agent run it verbatim through the bash tool in a fresh workspace-write session (its arguments carry a one-time token and a host sentinel path). It verifies all nine injected values, workspace writability, and EROFS refusal outside the workspace.

## Upgrading

When upgrading DSH/bwrap or replacing the runner: re-check the bwrap profile templates → update this package with a **new versioned file name** and digest (`RUNNER_SHA256`, `RUNNER_FILE_NAME`, and `PINNED_VERSIONS` in `lib/peers.js`, plus the `runner/` source file) → re-run the test suite and smoke acceptance → `npm pack` and reinstall. Never overwrite a runner file that is in use.

The runner strictly matches DSH's bwrap templates, and the plugin entry pins DSH and the sandbox-seam packages to `0.2.1-alpha.2`: after a DSH upgrade this plugin **refuses to load** (the bundle import fails, the native row stays disabled, confined commands fail closed) until the new version is re-validated through the procedure above.

## Supported scope

- Platform: Linux only (tested on Fedora 44 WSL2 with bwrap 0.12.0, Python 3.14, uv 0.13, Go 1.26). macOS/Windows are unsupported — their sandboxes use their own backends, and this package refuses to load there.
- DSH: strictly pinned to 0.2.1-alpha.2 (templates matched byte-for-byte by the runner, versions pinned at the plugin entry; any other version refuses to load).
- uv ≥ 0.7.0 is required (`UV_PYTHON_CACHE_DIR` was introduced in 0.7.0); Go is supported in module mode only; workspace paths containing colons are refused.
- Never use `/` or all of HOME as a workspace; protected trees (runner, DSH_HOME, the DSH installation, this plugin package, the Python stdlib) cannot host projects — checked on every confine call.
- Launch-directory freedom: `dsh web` may be started from `~` or anywhere else; the launch cwd is only the deployment default root, and an unsafe one merely logs a warning without blocking startup. The hard per-call checks target each session's actual workspace root — a session rooted at HOME, `/`, or a protected tree has its confined commands refused one by one, with a hint to pick a project subdirectory. Read-only sessions are unaffected.

## License

[MIT](LICENSE)
