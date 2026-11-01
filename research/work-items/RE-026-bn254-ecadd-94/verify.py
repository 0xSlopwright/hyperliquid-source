#!/usr/bin/env python3
"""Regenerate RE-026 with the tool and compare to the committed packet.

Only with --emulate, after explicit authorization, regenerate with emulation and
require an exact match to the committed JSON (full pin). When unicorn is
not requested, run static checks only, compare the no-emu pin, report emulation
as not run, and exit 0 for this explicitly static scope.
"""
import hashlib
import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecadd as tool  # noqa: E402

PACKET_JSON = HERE / "bn254-ecadd.json"
JSON_SHA256 = "0ece19222a62722e80d336bca990ba1113a9e3765a26aa0f858b46c7af335581"
NO_EMU_JSON_SHA256 = "8832409f27af72886b0f2cf4c1355e142bf29f76ac6a1faf7dc1d35684df1716"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulate", action="store_true")
    args = parser.parse_args(argv)
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=args.emulate)
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
        emu_note = "emu=not-run; scope=static-only"
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d got_slot_refs=%d %s errors=%d" % (
        result["key_insns_count"], len(result["vectors"]),
        result["got_slot_refs"]["total"], emu_note, len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
