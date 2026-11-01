#!/usr/bin/env python3
"""Static regeneration by default; --emulate requires prior execution authorization.
The committed emulation JSON is historical author evidence until independently rerun.
"""
import hashlib
import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecmul as tool  # noqa: E402

PACKET_JSON = HERE / "bn254-ecmul.json"
JSON_SHA256 = "ae212bc9791ccdd53cc48dff1446aec74f07693be008b62746d83a601af3b980"
NO_EMU_JSON_SHA256 = "79149c497481d1f9daff231044ca8d2ca135af3907086a0f63393209208322f4"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--emulate", action="store_true")
    args = ap.parse_args(argv)
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=args.emulate,
                          allow_execution=args.emulate)
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    digest = hashlib.sha256(text.encode()).hexdigest()
    if args.emulate:
        if digest != JSON_SHA256:
            errors.append("regenerated output sha256 mismatch")
        if PACKET_JSON.read_text() != text:
            errors.append("committed json differs from regenerated output")
        emu_note = "emu=ran"
    else:
        if digest != NO_EMU_JSON_SHA256:
            errors.append("regenerated --no-emu sha256 mismatch")
        emu_note = "emu=not-requested"
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d got_slot_refs=%d %s errors=%d" % (
        result["key_insns_count"], len(result["vectors"]),
        result["got_slot_refs"]["total"], emu_note, len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
