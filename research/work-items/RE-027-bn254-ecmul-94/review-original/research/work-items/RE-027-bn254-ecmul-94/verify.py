#!/usr/bin/env python3
"""Regenerate RE-027 with the tool and compare to the committed packet.

When unicorn is importable, regenerate with emulation (malloc stubbed) and
require an exact match to the committed JSON (full pin). When unicorn is
absent, run static checks only (equivalent to --no-emu), compare against the
no-emu pin, report emulation as skipped, and exit 0 if static checks pass.
"""
import hashlib
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecmul as tool  # noqa: E402

PACKET_JSON = HERE / "bn254-ecmul.json"
JSON_SHA256 = "ae212bc9791ccdd53cc48dff1446aec74f07693be008b62746d83a601af3b980"
NO_EMU_JSON_SHA256 = "79149c497481d1f9daff231044ca8d2ca135af3907086a0f63393209208322f4"


def main():
    has_unicorn = importlib.util.find_spec("unicorn") is not None
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=has_unicorn)
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    digest = hashlib.sha256(text.encode()).hexdigest()
    if has_unicorn:
        if digest != JSON_SHA256:
            errors.append("regenerated output sha256 mismatch")
        if PACKET_JSON.read_text() != text:
            errors.append("committed json differs from regenerated output")
        emu_note = "emu=ran"
    else:
        if digest != NO_EMU_JSON_SHA256:
            errors.append("regenerated --no-emu sha256 mismatch")
        emu_note = "emu=skipped"
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d got_slot_refs=%d %s errors=%d" % (
        result["key_insns_count"], len(result["vectors"]),
        result["got_slot_refs"]["total"], emu_note, len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
