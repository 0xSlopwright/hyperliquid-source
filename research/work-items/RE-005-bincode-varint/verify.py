#!/usr/bin/env python3
"""Recompute RE-005 evidence from the pinned node #94 artifact and check it byte-for-byte.

Run from the repo root:  python3 -I -B research/work-items/RE-005-bincode-varint/verify.py
Uses explicit checks (no assert), so it is also valid under python -O.
"""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402


def fail(msg):
    print(f'RE-005 verify: FAIL: {msg}', file=sys.stderr)
    raise SystemExit(1)


def main():
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        want, name = line.split('  ', 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if got != want:
            fail(f'{name} sha256 {got} != manifest {want}')
    try:
        text = bv.render(bv.scan(bv.TARGET.read_bytes()))
    except bv.EvidenceError as e:
        fail(str(e))
    if text != (HERE / 'varint-sites.json').read_text():
        fail('recomputed varint-sites.json differs from committed copy')
    print('RE-005 verify: OK', hashlib.sha256(text.encode()).hexdigest())


if __name__ == '__main__':
    main()
