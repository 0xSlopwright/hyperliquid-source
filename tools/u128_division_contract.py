#!/usr/bin/env python3
"""Admit the complete fixed native division contract without interpreting code."""
import hashlib
import json
from pathlib import Path
import struct

from libcore_fmt_correspondence import Elf
import node115_field_adapter_drift as indexed

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-u128-division-94'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODY_SHA256 = '45f632dd0c1fc0915e680ad7ad98cabda1fcf34ba7835c2e73e3569b570a288d'
BEGIN, SIZE, SLOT = 0x565f5a0, 198, 0x576e1a8


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prove_body(body):
    """Fixed-target static transfer certificate, not a CPU or PC interpreter."""
    need(type(body) is bytes and len(body) == SIZE, 'Complete immutable198-byte body required')
    rows = json.loads((PACKET / 'native/rows.json').read_text(encoding='utf-8'))
    cursor = 0
    for row in rows:
        raw = bytes.fromhex(row['bytes_hex'])
        need(row['address'] == BEGIN + cursor and body[cursor:cursor + len(raw)] == raw,
             'Complete native instruction encoding differs')
        cursor += len(raw)
    need(cursor == SIZE and len(rows) == 71 and sha(body) == BODY_SHA256,
         'Complete71-row body identity differs')
    # These immediate values come from the admitted complete encoding. REX.W
    # unsigned DIV/BSR/SHRD/SHLD operand widths are checked by the full rows.
    constants = {'word_bits': 64, 'numerator_bits': 128,
                 'count_mask': body[0x12], 'normalization_bias': body[0x14],
                 'normalization_endpoint_test': body[0x2a],
                 'numerator_half_join_shift': body[0x36],
                 'predecessor_step': body[0x4e],
                 'final_signed_immediate': struct.unpack('b', body[0x78:0x79])[0],
                 'small_digit_bits': body[0x9b]}
    need(constants == {'word_bits': 64, 'numerator_bits': 128, 'count_mask': 63,
                       'normalization_bias': 64, 'normalization_endpoint_test': 64,
                       'numerator_half_join_shift': 63, 'predecessor_step': 1,
                       'final_signed_immediate': -1, 'small_digit_bits': 32},
         'Native arithmetic obligations differ')
    return {'kind': 'COMPLETE_FIXED_NATIVE_TRANSFER_CERTIFICATE', 'constants': constants,
            'bytes': SIZE, 'rows': len(rows), 'body_sha256': sha(body),
            'proof_sha256': sha((PACKET / 'PROOF.md').read_bytes()),
            'returns': [0x565f61d, 0x565f631, 0x565f652, 0x565f665],
            'domain': 'all u128 dividend and nonzero u128 divisor under the explicit ordinary call/frame domain',
            'method': 'Complete71 raw rows plus manual branch/arithmetic proof; no instruction execution or PC model',
            'data_and_callees': 'none; native stack-save/return premises remain explicit',
            'numeric_output_projection': 'RAX + 2^64*RDX = floor(dividend/divisor)',
            'zero_divisor_runtime': 'OUTSIDE_CONTRACT'}


def inspect(data):
    need(type(data) is bytes and len(data) == 91774280 and sha(data) == TARGET_SHA256,
         'Target identity differs')
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, SIZE, executable=True)
    # The full digest authenticates the established unwind index. Consult only
    # its selected entry/local neighbors and actual FDE/CIE, not121k records.
    frame = indexed.selected_frame(indexed.Image(data, 3), BEGIN, SIZE)
    need(frame['body_sha256'] == sha(body), 'Selected FDE and code views disagree')
    slot = image.relative(SLOT)
    need(slot['addend'] == BEGIN, 'Wrong selected division dependency')
    writes = []
    for table in image.sections:
        need(table['type'] != 9, 'Unsupported native REL encoding')
        if table['type'] != 4:
            continue
        need(table['entsize'] == 24 and table['size'] % 24 == 0, 'Invalid RELA table')
        for off in range(table['offset'], table['offset'] + table['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, off)
            if address < SLOT + 8 and address + 8 > SLOT:
                need(address == SLOT and info == 8 and addend == BEGIN,
                     'Conflicting selected-slot write')
                writes.append(off)
            need(not (address < BEGIN + SIZE and address + 8 > BEGIN),
                 'Relocation overlaps the native body')
    need(writes == [slot['record_file_offset']], 'Selected slot is not globally unique')
    return {'target_sha256': TARGET_SHA256, 'target_bytes': len(data), 'mapping': mapping,
            'fde': frame, 'unwind_scope': 'selected index entry/local neighbors and complete FDE/CIE; no global census',
            'slot': slot,
            'proof': prove_body(body), 'byte_identity_or_gate_claim': False}


def load_target(path):
    """The one immutable snapshot is the only source for every parsed fact."""
    return Path(path).read_bytes()
