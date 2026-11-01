#!/usr/bin/env python3
"""Regenerate RE-024 with the tool and compare to the committed packet.

Default runs only static checks. After separate explicit authorization,
--emulate regenerates captured-code results and requires the documented
corrected full JSON pin. Installed Unicorn alone never enables execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import ripemd160_compress as tool  # noqa: E402

PACKET_JSON = HERE / "ripemd160-compress.json"
ORIGINAL_JSON_SHA256 = "6167af924de2bbdb68943119ea66c3866448fa024b20992a10cd9bdd7ecefb43"
JSON_SHA256 = "83668b82009784802f8c16f8eaf6bc83bcb3a30466bef680967347b5b0fbc7ec"
NO_EMU_JSON_SHA256 = "6ca0789fb398d47cfd51c6a04e7ed003b1203f1ecf130a2b1519dc02dba72520"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulate", action="store_true", help="requires separate explicit authorization")
    args = parser.parse_args()
    do_emu = args.emulate
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=do_emu)
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    digest = hashlib.sha256(text.encode()).hexdigest()
    original = PACKET_JSON.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_JSON_SHA256:
        errors.append("archived original receipt sha256 mismatch")
    expected = json.loads(original)
    # Explicit static correction only; original emulation fields are unchanged.
    expected["got_mov_caller_count"] = 2
    if do_emu:
        if digest != JSON_SHA256:
            errors.append("regenerated output sha256 mismatch")
        if tool.render(expected) != text:
            errors.append("regenerated output differs from archived receipt plus documented census correction")
        emu_note = "emu=ran"
    else:
        if digest != NO_EMU_JSON_SHA256:
            errors.append("regenerated --no-emu sha256 mismatch")
        emu_note = "emu=not_requested"
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d got_mov_callers=%d got_ff15_callers=%d %s errors=%d" % (
        result["key_insns_count"],
        len(result["vectors"]),
        result["got_mov_caller_count"],
        result["got_ff15_caller_count"],
        emu_note,
        len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
