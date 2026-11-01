#!/usr/bin/env python3
"""Static verification by default; --emulate requires separate authorization.

The full receipt includes bounded captured-code execution with allocator stubs.
Dependency availability alone never enables execution.
"""
import hashlib
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import modexp as tool  # noqa: E402

PACKET_JSON = HERE / "modexp.json"
JSON_SHA256 = "20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360"
NO_EMU_JSON_SHA256 = "e7fb0730df145fa34bc18534712ec4b4b5fa1bcf8769540f4b2b6d8cfdf4eced"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulate", action="store_true", help="requires explicit authorization")
    do_emu = parser.parse_args().emulate
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=do_emu)
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    digest = hashlib.sha256(text.encode()).hexdigest()
    if do_emu:
        if digest != JSON_SHA256:
            errors.append("regenerated output sha256 mismatch")
        if PACKET_JSON.read_text() != text:
            errors.append("committed json differs from regenerated output")
        emu_note = "emu=ran"
    else:
        if digest != NO_EMU_JSON_SHA256:
            errors.append("regenerated --no-emu sha256 mismatch")
        emu_note = "emu=not_requested"
    for e in errors:
        print("FAIL", e)
    print(
        "verify: key_insns=%d vectors=%d got_slot_refs=%d %s errors=%d"
        % (
            len(result["key_insns"]),
            len(result["vectors"]),
            result["slot_ref_counts"]["call"],
            emu_note,
            len(errors),
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
