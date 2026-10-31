#!/usr/bin/env python3
"""Reproduce the target-bound conditional normal collection packet."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from visor_child_args_collection import TARGET,collect,require


def target_record(record):
    """Mask only GNU version text; every target/native binding remains exact."""
    value = json.loads(json.dumps(record))
    require(value['native_method']['tool'].startswith('GNU objdump'), 'record does not name GNU objdump')
    value['native_method']['tool'] = '<GNU objdump version metadata>'
    return value


def verify(packet,data):
    record,exports = collect(data)
    retained = json.loads((packet / 'record.json').read_text())
    require(target_record(retained) == target_record(record),'collection record differs from fresh target bindings')
    for name,raw in exports.items():
        require((packet/name).read_bytes()==raw,'collection native export differs from fresh target bindings')
    return {'comparison_mask':['native_method.tool'], 'owned_bytes':860,'native_instruction_rows':220,'blocks':61,
            'normal_projection_nodes':176,'conditional_projection_nodes':144,
            'opaque_allocator_copy_contracts_assumed_not_recovered':True,
            'captured_code_executed_or_emulated':False,'automatic_machine_equivalence_verifier':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
