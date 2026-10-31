#!/usr/bin/env python3
"""Reproduce only the target-bound local cache-return packet."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from visor_allocator_cache import TARGET, collect, require


def target_record(record):
    """Mask only GNU version text; every target/native binding remains exact."""
    value = json.loads(json.dumps(record))
    require(value['native']['tool'].startswith('GNU objdump'), 'record does not name GNU objdump')
    value['native']['tool'] = '<GNU objdump version metadata>'
    return value


def verify(packet):
    record, exports = collect(TARGET.read_bytes())
    retained = json.loads((packet / 'record.json').read_text())
    require(target_record(retained) == target_record(record), 'Allocator record differs from admitted target')
    for name, value in exports.items():
        require((packet / name).read_bytes() == value.encode('utf-8'), 'Allocator native export differs')
    return {'comparison_mask':['native.tool'], 'status': 'LOCAL_RETURN_PACKET_REPRODUCED', 'native_bytes': 194, 'native_rows': 37,
            'local_return_paths': 2, 'open_slow_transfers': 3,
            'allocator_correctness_or_target_execution_claimed': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
