#!/usr/bin/env python3
"""Build the reviewed Mochirii theme as a deterministic source archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "theme" / "mochirii"
EPOCH = (1980, 1, 1, 0, 0, 0)
ASSET_DIGESTS = {
    "assets/mochirii-emblem.webp": "ed9fe4c522bc2b0d1c2072c1c098f241ee52f0ceec0307cb531ce440e730bb60",
    "assets/mochirii-icon.png": "742422603499f5033e6b0aadbd25383e3db8814734ae7e5fa5c997050ba71409",
    "assets/mochirii-social-card.png": "039a3356756542ed351d87a6756d5f7c769bdaec6a1a0fca58f486149455878b",
}


def validate() -> None:
    about = json.loads((SOURCE / "about.json").read_text(encoding="utf-8"))
    if about.get("name") != "Mochirii Forums":
        raise RuntimeError("Theme identity is not the reviewed Mochirii name.")
    if set(about.get("assets", {}).values()) != set(ASSET_DIGESTS):
        raise RuntimeError("Theme asset inventory differs from the reviewed set.")
    for relative, expected in ASSET_DIGESTS.items():
        path = SOURCE / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise RuntimeError(f"Mochirii brand asset digest changed: {relative}")


def build(output: Path) -> None:
    validate()
    entries = {
        path.relative_to(SOURCE).as_posix(): path.read_bytes()
        for path in sorted(SOURCE.rglob("*"))
        if path.is_file()
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mochirii-theme-") as temporary:
        candidate = Path(temporary) / "theme.zip"
        with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in sorted(entries):
                info = zipfile.ZipInfo(name, EPOCH)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, entries[name])
        shutil.copyfile(candidate, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / ".artifacts" / "mochirii-theme.zip")
    args = parser.parse_args()
    build(args.output.resolve())
    print("Built deterministic Mochirii theme archive.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
