#!/usr/bin/env python3
"""Regenerate RE-022 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import chacha12_guts as tool  # noqa: E402

PACKET_JSON = HERE / "chacha12-guts.json"
JSON_SHA256 = "66f083054342ba1320e13341e3fdfe568f26c57f10b90f2d528910d0aab8d4cf"


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append("regenerated output sha256 mismatch")
    if PACKET_JSON.read_text() != text:
        errors.append("committed json differs from regenerated output")
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d got_callers=%d errors=%d" % (
        result["key_insns_count"],
        len(result["vectors"]),
        result["got_caller_count"],
        len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
