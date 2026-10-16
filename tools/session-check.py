#!/usr/bin/python3 -IS
"""Run ONLY via the actual DSH bash tool in a fresh workspace-write session.

--expect enhanced (default): the cache-redirect enhancement must be active
(the nine variables hold the workspace values). --expect native: the native
provider must be running WITHOUT this plugin's enhancement; the nine
variables are only recorded (they may be absent or inherited from the
Host), never asserted. Both modes prove confined execution (workspace write
+ out-of-workspace sentinel denial) and report mount evidence for the
actual backend (bwrap: tmpfs /tmp plus the workspace bind in
/proc/self/mountinfo).
"""
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
DENIAL_ERRNOS = {errno.EROFS: "EROFS", errno.EACCES: "EACCES", errno.EPERM: "EPERM"}


def mount_evidence(root):
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return {"available": False}
    tmp_tmpfs = False
    root_mount = False
    root_rw = None
    root_ro = None
    for line in lines:
        fields = line.split()
        if "-" not in fields or len(fields) < 6:
            continue
        sep = fields.index("-")
        mount_point, flags = fields[4], fields[5]
        fstype = fields[sep + 1] if len(fields) > sep + 1 else ""
        if mount_point == "/tmp" and fstype == "tmpfs" and flags.startswith("rw"):
            tmp_tmpfs = True
        if mount_point == str(root):
            root_mount = True
            root_rw = flags.startswith("rw")
        if mount_point == "/":
            root_ro = flags.startswith("ro")
    return {"available": True, "tmpfs_tmp": tmp_tmpfs, "workspace_mount": root_mount,
            "workspace_rw": root_rw, "rootfs_ro": root_ro,
            "bwrap_evidence": bool(tmp_tmpfs and root_mount)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True)
    p.add_argument("--sentinel", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--expect", choices=["enhanced", "native"], default="enhanced")
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
    env_report = {}
    for k, v in PATHS.items():
        actual = os.environ.get(k)
        env_report[k] = actual
        if args.expect == "enhanced" and actual != str(root / v):
            raise RuntimeError("unexpected injected value: " + k)
    try:
        fd = os.open(sentinel, os.O_WRONLY | os.O_APPEND)
    except OSError as exc:
        if exc.errno not in DENIAL_ERRNOS:
            raise RuntimeError("sentinel denied with unexpected errno: " + str(exc.errno))
        denial = DENIAL_ERRNOS[exc.errno]
    else:
        os.close(fd)
        raise RuntimeError("sentinel write-open succeeded; isolation not established")
    marker = root / (".dsh-accept-" + args.token)
    with marker.open("x") as stream:
        stream.write(args.token + "\n")
    with tempfile.TemporaryDirectory(prefix="dsh-session-", dir="/tmp") as tmp:
        (Path(tmp) / "f").write_text(args.token)
    print(json.dumps({"root": str(root), "marker": str(marker), "expect": args.expect,
                      "env": env_report, "sentinel": denial + "-CONFIRMED",
                      "mounts": mount_evidence(root)}))
    print("DSH-SESSION-PASS " + args.token)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("DSH-SESSION-FAIL:", str(exc))
        raise SystemExit(1)
