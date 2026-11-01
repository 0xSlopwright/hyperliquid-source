#!/usr/bin/env python3
"""Fail-closed replay for the bounded partial-fill caller evidence."""

import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WINDOW_FILE_OFFSET = 0x4311289
WINDOW_LENGTH = 118
WINDOW_SHA256 = "cc7957f79f8ced525c50ca8077cec35abbbc2afb38ad38e54faed2cbc25283c7"


def fail(message):
    print(f"RE-006 node94-orderbook verify: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        expected, name = line.split("  ", 1)
        actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{name}: {actual} != {expected}")

    target = TARGET.read_bytes()
    digest = hashlib.sha256(target).hexdigest()
    if digest != TARGET_SHA256:
        fail(f"target: {digest} != {TARGET_SHA256}")
    window = target[WINDOW_FILE_OFFSET : WINDOW_FILE_OFFSET + WINDOW_LENGTH]
    window_digest = hashlib.sha256(window).hexdigest()
    if window_digest != WINDOW_SHA256:
        fail(f"caller window: {window_digest} != {WINDOW_SHA256}")

    rows = (HERE / "partial-fill-caller.tsv").read_text().splitlines()
    windows = [row for row in rows if row.startswith("window\t")]
    if len(windows) != 1:
        fail("expected exactly one retained caller window")
    if not windows[0].startswith("window\t" + window.hex() + "\t"):
        fail("retained window bytes differ from the authenticated target")
    print("RE-006 node94-orderbook verify: OK", WINDOW_SHA256)


if __name__ == "__main__":
    main()
