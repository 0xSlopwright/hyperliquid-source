#!/usr/bin/env python3
"""Regenerate RE-028 with the tool and compare to the committed packet.

When unicorn is importable, regenerate with emulation (alloc stubs) and
require an exact match to the committed JSON (full pin). When unicorn is
absent, run static checks only (equivalent to --no-emu), compare against the
no-emu pin, report emulation as skipped, and exit 0 if static checks pass.
"""
import hashlib
import importlib.util
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
