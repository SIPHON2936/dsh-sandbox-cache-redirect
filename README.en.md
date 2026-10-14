# dsh-sandbox-cache-redirect

[中文](README.md) | English

A bundle plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH). Once installed, bash commands confined under `workspace-write` automatically write their uv/pip/npm/Go caches and runtimes into the current project — no per-command cache prefixes, no prompt-level reminders.

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

The bundle does two things:

1. **cordis.patch.yml** replaces the `sandbox` entry's (`@deepseek-ai/dsh-sandbox-local`) config wholesale:
   `runnerCommand` points at the trusted runner, `runnerFailureSignatures` registers its failure dialect, `probeTimeoutMs` 5000.
2. **index.js (Host plugin)** installs and verifies the runner at activation:
   - verifies the bundled runner's SHA-256 (must equal `0ef04d1a…579216`);
   - creates `$HOME/.local/libexec/dsh/dsh-bwrap-redirect-v6-0ef04d1a72ad` exclusively, mode 0500, `O_NOFOLLOW`;
   - reuses an existing file only if it is a same-digest, user-owned regular file without group/other write permission — it is **never overwritten**;
   - re-verifies the installed file's digest and permission bits, and audits the parent chain (every component owned by root or the current user, never group/world-writable);
   - preflight gates: Linux only; `/usr/bin/python3` and `/usr/bin/bwrap` executable; bwrap ≥ 0.12.0 (the CVE-2026-87766 fix floor).

If any check fails, the plugin throws during load; the sandbox then **fails closed** (commands never run unconfined) instead of silently degrading.

The runner itself only matches strings and execs: it creates, resolves, or cleans no cache directories on the host and adds no mounts; unknown bwrap profiles are rejected outright, never passed through as unsandboxed commands.

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
dsh plugin --profile <your-profile> add github:SIPHON2936/dsh-sandbox-cache-redirect
```

This installs the repository as a git dependency into the given profile and registers the bundle. The package ships no build scripts, so no pnpm allowBuilds exemption is needed.

### Option 2: pack it yourself

```bash
git clone https://github.com/SIPHON2936/dsh-sandbox-cache-redirect.git
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

When upgrading DSH/bwrap or replacing the runner: re-check the bwrap profile templates → update this package with a **new versioned file name** and digest (`RUNNER_SHA256` and `RUNNER_FILE_NAME` in `index.js`, the runnerCommand path in `cordis.patch.yml`, and the `runner/` source file) → re-run the smoke acceptance → `npm pack` and reinstall. Never overwrite a runner file that is in use.

The runner strictly matches DSH's bwrap templates; if a DSH upgrade changes the templates, confined commands fail closed with `unrecognized bwrap profile` — follow the procedure above to re-validate.

## Supported scope

- Platform: Linux only (tested on Fedora 44 WSL2 with bwrap 0.12.0, Python 3.14, uv 0.13, Go 1.26). macOS/Windows are unsupported — their sandboxes use their own backends, and this package refuses to load there.
- DSH: the runner is strictly locked to 0.2.1-alpha.2's bwrap templates.
- uv ≥ 0.7.0 is required (`UV_PYTHON_CACHE_DIR` was introduced in 0.7.0); Go is supported in module mode only.

## License

[MIT](LICENSE)
