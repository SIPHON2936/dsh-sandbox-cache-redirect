#!/usr/bin/python3 -IS
"""Standalone minimum gate. Does not import other acceptance files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

PY = "/usr/bin/python3"
BASE = ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid",
        "--proc", "/proc", "--die-with-parent"]
PATHS = {
    "UV_CACHE_DIR": ".dsh-cache/uv", "PIP_CACHE_DIR": ".dsh-cache/pip",
    "npm_config_cache": ".dsh-cache/npm", "GOCACHE": ".dsh-cache/go-build",
    "UV_PYTHON_CACHE_DIR": ".dsh-cache/uv-python",
    "UV_PYTHON_INSTALL_DIR": ".dsh-state/uv/python",
    "UV_PYTHON_BIN_DIR": ".dsh-state/uv/bin",
    "GOMODCACHE": ".dsh-cache/go-mod", "GOPATH": ".dsh-state/go",
}
PROBE = """
import errno,os,sys
try: fd=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND)
except OSError as e:
    if e.errno==errno.EROFS:
        print('EROFS-CONFIRMED');sys.exit(0)
    print('OTHER-ERRNO',e.errno,file=sys.stderr);sys.exit(3)
os.close(fd);sys.exit(2)
"""
PAYLOAD = """
import errno,json,os,sys
from pathlib import Path
expected=json.loads(sys.argv[1])
if any(os.environ.get(k)!=v for k,v in expected.items()):sys.exit(41)
try: fd=os.open(sys.argv[2],os.O_WRONLY|os.O_APPEND)
except OSError as e:
    if e.errno!=errno.EROFS:sys.exit(42)
else:
    os.close(fd);sys.exit(43)
Path(sys.argv[3]).write_text('WS-MARKER')
Path(sys.argv[4]).mkdir(parents=True)
(Path(sys.argv[4])/'inner').write_text('TMP-MARKER')
print('PAYLOAD-COMPLETE')
"""


def demand(condition, message):
    if not condition:
        raise RuntimeError(message)
    print("OK", message, flush=True)


def run(argv, cwd, env=None):
    p = subprocess.run([str(x) for x in argv], cwd=cwd, env=env,
                       capture_output=True, text=True, timeout=30)
    print(json.dumps({"argv": [str(x) for x in argv], "rc": p.returncode,
                      "stdout": p.stdout, "stderr": p.stderr}), flush=True)
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True)
    parser.add_argument("--parent", required=True,
                        help="trusted existing writable directory outside /tmp")
    args = parser.parse_args()
    wrapper = Path(args.wrapper).resolve(strict=True)
    parent = Path(args.parent).resolve(strict=True)
    demand(parent.is_dir() and not parent.is_relative_to("/tmp"),
           "fixture parent outside /tmp")
    with tempfile.TemporaryDirectory(prefix="dsh-smoke-", dir=parent) as raw:
        with tempfile.TemporaryDirectory(prefix="dsh-smoke-host-", dir="/tmp") as traw:
            root, host_tmp = Path(raw), Path(traw)
            ws = root / "ws"
            ws.mkdir()
            sentinel = root / "host-sentinel"
            sentinel.write_bytes(b"HOST-ORIGINAL\n")
            before = hashlib.sha256(sentinel.read_bytes()).hexdigest()
            fd = os.open(sentinel, os.O_WRONLY | os.O_APPEND)
            os.close(fd)
            demand(True, "host writable positive control")
            prefix = [PY, "-IS", wrapper, *BASE, "--tmpfs", "/tmp",
                      "--bind", ws, ws, "--"]
            sandbox_tmp = host_tmp / "sandbox-only"
            expected = {k: str(ws / v) for k, v in PATHS.items()}
            p = run([*prefix, PY, "-IS", "-c", PAYLOAD, json.dumps(expected),
                     sentinel, ws / "marker", sandbox_tmp], ws)
            demand(p.returncode == 0 and p.stdout.strip() == "PAYLOAD-COMPLETE",
                   "nine envs + EROFS + workspace/tmp payload completed")
            demand((ws / "marker").read_text() == "WS-MARKER", "host sees workspace marker")
            demand(not sandbox_tmp.exists(), "sandbox tmpfs did not persist to host")
            demand(hashlib.sha256(sentinel.read_bytes()).hexdigest() == before,
                   "host sentinel digest unchanged")
            inherited = {k: "INHERITED-" + str(i) for i, k in enumerate(PATHS)}
            code = "import os,json;print(json.dumps({k:os.environ.get(k) for k in " + repr(list(PATHS)) + "}))"
            ro = [PY, "-IS", wrapper, *BASE, "--"]
            p = run([*ro, PY, "-IS", "-c", code], ws, os.environ | inherited)
            demand(p.returncode == 0 and json.loads(p.stdout) == inherited,
                   "read-only preserves nine known inherited values")
            ro_tmp = host_tmp / "ro-sentinel"
            ro_tmp.write_text("RO-TMP")
            for target in (ws / "marker", ro_tmp):
                p = run([*ro, PY, "-IS", "-c", PROBE, target], ws)
                demand(p.returncode == 0 and p.stdout.strip() == "EROFS-CONFIRMED",
                       "read-only explicit EROFS for " + str(target))
            marker = ws / "negative"
            marker_code = "from pathlib import Path;import sys;Path(sys.argv[1]).write_text('RAN')"
            bad = [PY, "-IS", wrapper, "--bind", "/", "/", *BASE[3:], "--",
                   PY, "-IS", "-c", marker_code, marker]
            p = run(bad, ws)
            demand(p.returncode == 1 and p.stderr.startswith("dsh-bwrap-redirect:")
                   and not marker.exists(), "unknown profile rejected without marker")
    print("SMOKE PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("SMOKE FAIL:", str(exc), flush=True)
        raise SystemExit(1)
