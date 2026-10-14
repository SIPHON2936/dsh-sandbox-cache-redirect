#!/usr/bin/python3 -IS
"""Run ONLY via the actual DSH bash tool in a fresh workspace-write session."""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import stat
import tempfile

PATHS = {
    "UV_CACHE_DIR": ".dsh-cache/uv", "PIP_CACHE_DIR": ".dsh-cache/pip",
    "npm_config_cache": ".dsh-cache/npm", "GOCACHE": ".dsh-cache/go-build",
    "UV_PYTHON_CACHE_DIR": ".dsh-cache/uv-python",
    "UV_PYTHON_INSTALL_DIR": ".dsh-state/uv/python",
    "UV_PYTHON_BIN_DIR": ".dsh-state/uv/bin",
    "GOMODCACHE": ".dsh-cache/go-mod", "GOPATH": ".dsh-state/go",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True)
    p.add_argument("--sentinel", required=True)
    p.add_argument("--token", required=True)
    args = p.parse_args()
    root = Path(args.root)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise RuntimeError("--root must be the confirmed canonical session root")
    if not Path.cwd().resolve().is_relative_to(root):
        raise RuntimeError("command cwd is outside the confirmed session root")
    if not re.fullmatch("[a-f0-9]{32}", args.token):
        raise RuntimeError("token must contain 32 lowercase hex digits")
    sentinel = Path(args.sentinel).resolve(strict=True)
    if sentinel.is_relative_to(root) or sentinel.is_relative_to("/tmp"):
        raise RuntimeError("sentinel must be outside workspace and /tmp")
    info = sentinel.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("sentinel must be a fresh regular file without hardlink aliases")
    for k, v in PATHS.items():
        if os.environ.get(k) != str(root / v):
            raise RuntimeError("unexpected injected value: " + k)
    try:
        fd = os.open(sentinel, os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise RuntimeError("sentinel denied with unexpected errno: " + str(exc.errno))
    else:
        os.close(fd)
        raise RuntimeError("sentinel write-open succeeded; isolation not established")
    marker = root / (".dsh-accept-" + args.token)
    with marker.open("x") as stream:
        stream.write(args.token + "\n")
    with tempfile.TemporaryDirectory(prefix="dsh-session-", dir="/tmp") as tmp:
        (Path(tmp) / "f").write_text(args.token)
    print(json.dumps({"root": str(root), "marker": str(marker),
                      "env_count": len(PATHS), "sentinel": "EROFS-CONFIRMED"}))
    print("DSH-SESSION-PASS " + args.token)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("DSH-SESSION-FAIL:", str(exc))
        raise SystemExit(1)
