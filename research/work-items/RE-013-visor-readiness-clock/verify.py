#!/usr/bin/env python3
"""Regenerate the static packet and exercise capture/record corruption controls."""
import argparse
import json
from pathlib import Path

from survey import Image, RANGES, SIZE, survey


def check_files(actual, retained):
    if set(actual) != {p.name for p in retained.iterdir() if p.is_file()}:
        raise ValueError("retained export set differs")
    for name, data in actual.items():
        if data != (retained / name).read_bytes():
            raise ValueError("regenerated export differs: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    retained = Path(__file__).resolve().parent / "records"
    actual = survey(args.binary)
    check_files(actual, retained)
    if survey(args.binary) != actual:
        raise ValueError("second independent regeneration differs")
    original = args.binary.read_bytes()
    admitted = Image(original)
    cases = {"truncated": original[:-1], "LFS-pointer": b"version https://git-lfs.github.com/spec/v1\n"}
    for label, va in (("clock-call", 0x44460D), ("strict-compare", 0x5B44C6),
                      ("duration", 0x6E748), ("clock-slot-data", 0x7E5388)):
        changed = bytearray(original)
        changed[admitted.offset(va, 1)] ^= 1
        cases[label] = bytes(changed)
    refused = []
    for label, changed in cases.items():
        try:
            Image(changed)
        except ValueError:
            refused.append(label)
        else:
            raise ValueError("changed capture was admitted: " + label)
    # Corrupt a generated record, with every native export otherwise intact.
    altered = dict(actual)
    record = json.loads(altered["record.json"])
    record["ranges"]["readiness"]["endVA"] = "0x5b470c"
    altered["record.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    try:
        check_files(altered, retained)
    except ValueError:
        refused.append("retained-FDE-end")
    else:
        raise ValueError("corrupted FDE extent record was admitted")
    # The checker must also notice a changed raw native byte, not only JSON.
    altered = dict(actual)
    altered["clock-os.txt"] += b"changed raw export\n"
    try:
        check_files(altered, retained)
    except ValueError:
        refused.append("retained-native-export")
    else:
        raise ValueError("corrupted native export was admitted")
    print(json.dumps({"targetBytes": SIZE, "fdeExtents": len(RANGES),
                      "regenerations": 2, "negativeControlsRefused": refused,
                      "capturedExecution": False, "emulation": False}, sort_keys=True))


if __name__ == "__main__":
    main()
