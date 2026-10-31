#!/usr/bin/env python3
"""Regenerate RE-019 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import rmp_json_loader as tool  # noqa: E402

PACKET_JSON = HERE / "rmp-json-loader.json"
JSON_SHA256 = "d434acc77db5a0e8636833b1fab0d009416a9548b16d7ac49a4866d894fb472d"


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
    print("verify: key_insns=%d callers=%d labels=%d locations=%d errors=%d" % (
        len(result["key_bytes"]), len(result["callers"]), len(result["labels"]),
        len(result["locations"]), len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
