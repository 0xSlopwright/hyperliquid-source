#!/usr/bin/env python3
"""Regenerate RE-022 with the tool and compare to the committed packet.

Default runs only static checks. After separate explicit authorization,
--emulate regenerates captured-code results and requires the committed full
JSON pin. Installed Unicorn alone never enables execution.
"""
import argparse
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import chacha12_guts as tool  # noqa: E402

PACKET_JSON = HERE / "chacha12-guts.json"
JSON_SHA256 = "146a164a1fbc9be96ede3696385ee093560a303539b890fc68707f6770d9c3ab"
NO_EMU_JSON_SHA256 = "d3d31f80bfbf74bc86c3fb528853e413e53548025288ca4c0335e07fa569d48b"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulate", action="store_true", help="requires separate explicit authorization")
    args = parser.parse_args()
    do_emu = args.emulate
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
    print("verify: key_insns=%d vectors=%d got_callers=%d %s errors=%d" % (
        result["key_insns_count"],
        len(result["vectors"]),
        result["got_caller_count"],
        emu_note,
        len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
