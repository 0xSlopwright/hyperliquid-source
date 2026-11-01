#!/usr/bin/env python3
"""Regenerate RE-021 with the tool and compare to the committed packet, exactly."""
import argparse
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import blake2b_compress as tool  # noqa: E402

PACKET_JSON = HERE / "blake2b-compress.json"
JSON_SHA256 = "dc2420392ce8f7ad5f63dbc313b8ddb8095143a91a25eef1e9a2a7663ad78f92"
NO_EMU_JSON_SHA256 = "bf027d6f03afb99a699b8a3def6ccecb026be95f6714d6e61c743ea52aed7ed6"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulate", action="store_true", help="requires separate explicit authorization")
    args = parser.parse_args()
    result = tool.analyse(tool.TARGET.read_bytes(), run_emu=args.emulate)
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    expected = JSON_SHA256 if args.emulate else NO_EMU_JSON_SHA256
    if hashlib.sha256(text.encode()).hexdigest() != expected:
        errors.append("regenerated output sha256 mismatch")
    if args.emulate and PACKET_JSON.read_text() != text:
        errors.append("committed json differs from regenerated output")
    print("emu=ran" if args.emulate else "emu=not_requested")
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d vectors=%d rol_total=%d errors=%d" % (
        result["key_insns_count"],
        len(result["eip152_vectors"]),
        sum(result["rol_counts"].values()),
        len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
