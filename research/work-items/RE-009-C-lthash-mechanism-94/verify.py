#!/usr/bin/env python3
"""Regenerate RE-009-C with the tool and compare to the committed packet."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import lthash_mechanism as tool  # noqa: E402

PACKET_JSON = HERE / 'lthash-mechanism.json'
JSON_SHA256 = '9450c6225fbc78446bfd7813592ec7e9700006c1fa0bf9ad567216ddb703b12a'
EXPECT = {'leaves': 3, 'lattice_loops': 6, 'count_blocks': 3}


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = []
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append('regenerated output sha256 mismatch')
    if PACKET_JSON.read_text() != text:
        errors.append('committed json differs from regenerated output')
    if result['counts'] != EXPECT:
        errors.append(f"counts {result['counts']} != {EXPECT}")
    for L in result['leaves']:
        for key in ('lattice_entry_add', 'lattice_merge_add'):
            r = L[key]
            if (r['u16_words_total'], r['bytes_covered'], r['byte_order'], r['overflow']) != \
                    (1024, 0x800, 'big-endian', 'wrapping-mod-2^16'):
                errors.append(f"{L['leaf']} {key}: mechanism fields")
        if L['count_add']['overflow'] != 'saturating-u64' or L['xof_len'] != '0x800':
            errors.append(f"{L['leaf']}: count/xof fields")
    for e in errors:
        print('FAIL', e)
    print(f'verify: leaves=3 loops=6 count_blocks=3 errors={len(errors)}')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
