#!/usr/bin/env python3
"""Build a reproducible, standalone skill ZIP with no private workspace files."""
import argparse
import hashlib
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/cloneguard"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    target = Path(args.out).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(SKILL.rglob("*")):
                relative = path.relative_to(SKILL)
                if path.is_symlink():
                    raise SystemExit("Refusing symlink in skill")
                if not path.is_file() or "__pycache__" in relative.parts or path.suffix == ".pyc":
                    continue
                if path.suffix not in {".md", ".py", ".yaml"}:
                    raise SystemExit("Unexpected file type in skill")
                entry = zipfile.ZipInfo("cloneguard/" + relative.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, path.read_bytes())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksum = target.with_suffix(target.suffix + ".sha256")
    with checksum.open("x") as stream:
        stream.write(f"{digest}  {target.name}\n")
    print(f"{target.name}: {target.stat().st_size} bytes\nSHA-256: {digest}")
