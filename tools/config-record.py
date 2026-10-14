#!/usr/bin/python3 -IS
"""Record/restore trusted user-owned DSH patch files; not a YAML editor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inspect(path):
    if path.parent.resolve() != path.parent:
        raise RuntimeError("patch parent contains a symlink: " + str(path))
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"present": False}
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("patch must be a user-owned regular file: " + str(path))
    data = path.read_bytes()
    return {"present": True, "sha256": digest(data),
            "mode": stat.S_IMODE(info.st_mode)}


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def save_json(path, value):
    save(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["backup", "seal", "restore"])
    p.add_argument("--record", required=True)
    p.add_argument("--home")
    p.add_argument("--profile")
    a = p.parse_args()
    record = Path(a.record).resolve(strict=True)
    info = record.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("record directory must be user-owned and private (0700)")
    manifest = record / "before.json"
    if a.action == "backup":
        if not a.home or not a.profile or "/" in a.profile or a.profile in (".", ".."):
            raise RuntimeError("backup requires absolute --home and a single profile name")
        if not Path(a.home).is_absolute():
            raise RuntimeError("--home must be absolute")
        home = Path(a.home).resolve(strict=True)
        paths = {"profile": home / "profiles" / a.profile / "cordis.patch.yml",
                 "home": home / "cordis.patch.yml"}
        before = {}
        for label, path in paths.items():
            state = inspect(path)
            if state["present"]:
                data = path.read_bytes()
                if digest(data) != state["sha256"]:
                    raise RuntimeError("patch changed while backing up: " + str(path))
                save(record / (label + ".before"), data)
            before[label] = {"path": str(path), **state}
        save_json(manifest, before)
        print("BACKUP PASS", record)
        return
    before = json.loads(manifest.read_text())
    if set(before) != {"profile", "home"}:
        raise RuntimeError("unexpected backup manifest")
    paths = {k: Path(v["path"]) for k, v in before.items()}
    if a.action == "seal":
        save_json(record / "applied.json", {k: inspect(v) for k, v in paths.items()})
        print("SEAL PASS", record)
        return
    if (record / "restored.json").exists():
        raise RuntimeError("this record was already restored; inspect before reusing")
    applied = json.loads((record / "applied.json").read_text())
    originals = {}
    # Validate BOTH destinations and all backup bytes before the first write.
    for label, target in paths.items():
        if inspect(target) != applied[label]:
            raise RuntimeError("patch changed after seal; manual merge required: " + str(target))
        if before[label]["present"]:
            data = (record / (label + ".before")).read_bytes()
            if digest(data) != before[label]["sha256"]:
                raise RuntimeError("backup digest mismatch: " + label)
            originals[label] = data
    completed = []
    try:
        for label, target in paths.items():
            if before[label]["present"]:
                fd, tmp = tempfile.mkstemp(prefix=".dsh-restore-", dir=target.parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        os.fchmod(stream.fileno(), before[label]["mode"])
                        stream.write(originals[label])
                    os.replace(tmp, target)
                finally:
                    Path(tmp).unlink(missing_ok=True)
            elif applied[label]["present"]:
                target.unlink()
            completed.append(label)
    except Exception:
        print("RESTORE INCOMPLETE; completed:", ",".join(completed))
        raise
    save_json(record / "restored.json", {"completed": completed})
    print("RESTORE PASS", record)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("CONFIG RECORD FAIL:", str(exc))
        raise SystemExit(1)
