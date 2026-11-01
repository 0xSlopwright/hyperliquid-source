#!/usr/bin/env python3
"""Regenerate RE-026 with the tool and compare to the committed packet.

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
import bn254_ecadd as tool  # noqa: E402

PACKET_JSON = HERE / "bn254-ecadd.json"
JSON_SHA256 = "0ece19222a62722e80d336bca990ba1113a9e3765a26aa0f858b46c7af335581"
NO_EMU_JSON_SHA256 = "8832409f27af72886b0f2cf4c1355e142bf29f76ac6a1faf7dc1d35684df1716"


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
