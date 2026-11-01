#!/usr/bin/env python3
"""Authenticate and regenerate the retained bounded lookup record/native export."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from visor_lookup_result import TARGET, collect, require


def target_record(record):
    """Exclude only decoder version text; retain all bytes, hashes and operands."""
    value = json.loads(json.dumps(record))
    require(value['native_method']['tool'].startswith('GNU objdump'),
            'lookup record does not name GNU objdump')
    value['native_method']['tool'] = '<GNU objdump version metadata>'
    return value


def verify(packet, data):
    record,native = collect(data)
    retained = json.loads((packet/'record.json').read_text())
    require(target_record(retained) == target_record(record), 'lookup record differs from target regeneration')
    require((packet/'lookup.objdump.txt').read_bytes() == native, 'lookup native export differs from target regeneration')
    return {'lookup_bytes':record['lookup_fde']['bytes'],
            'native_instructions':record['normal_CFG']['decoded_instructions'],
            'branches':len(record['normal_CFG']['branches']),
            'normal_calls':len(record['normal_CFG']['calls']),
            'normal_return_low32_upper_bound':record['return_cutset']['normal_return_low32_upper_bound'],
            'captured_target_executed':False,
            'retained_decoder':retained['native_method']['tool'],
            'current_decoder':record['native_method']['tool'],
            'comparison_mask':['native_method.tool only; native export remains byte-exact']}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
