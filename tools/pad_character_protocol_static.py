#!/usr/bin/env python3
"""Static certificate for node94's 95-byte character-request adapter.

No captured execution, instruction evaluator, renderer or original Result ABI.
The licensed research artifact supplies typed correspondence, not source identity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from node115_field_adapter_drift import Image, archive_member, selected_frame

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SIZE = 91774280
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARCHIVE_SIZE = 2917630
ARCHIVE_SHA256 = 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
MEMBER_SHA256 = '57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13'
START, SIZE, LAYOUT = 0x157cfa0, 95, 0x5674210
FUNCTION = '_ZN68_$LT$core..fmt..builders..PadAdapter$u20$as$u20$core..fmt..Write$GT$10write_char17h2522b7af324989a1E'
SECTION = '.text.' + FUNCTION
LAYOUT_SECTION = '.data.rel.ro..Lanon.566e8472f54db27c7ffa65d7a5411555.48'

# Each row has one fixed raw operand/control role. The four PC32 bytes are the
# only variable encoding; derive separately binds their actual data destination.
# These are finite static witnesses, not a register/memory/PC evaluator.
ROLES = (
    (0, '55', 'save entry RBP'),
    (1, '4889e5', 'establish frame'),
    (4, '4157', 'save entry R15'),
    (6, '4156', 'save entry R14'),
    (8, '4154', 'save entry R12'),
    (10, '53', 'save entry RBX'),
    (11, '4c8b7710', 'cache flag pointer from receiver+16'),
    (15, '488b1f', 'cache destination from receiver+0'),
    (18, '4c8b7f08', 'cache method-table pointer from receiver+8'),
    (22, '41803e00', 'sample current flag byte against zero'),
    (26, '742b', 'zero flag bypasses indent to scalar comparison'),
    (28, '488d0500000000', 'PC32 address of four-space bytes'),
    (35, 'ba04000000', 'indent request length is four'),
    (40, '4889df', 'indent destination is cached D'),
    (43, '4189f4', 'save full low32 character across indent callback'),
    (46, '4889c6', 'indent byte address argument'),
    (49, '41ff5718', 'fresh byte-method call through cached V+24'),
    (53, '4489e6', 'restore low32 character after indent callback'),
    (56, '84c0', 'test only callback low8 AL'),
    (58, '740b', 'zero AL reaches scalar comparison'),
    (60, 'b001', 'nonzero indent AL returns canonical low8 one'),
    (62, '5b', 'error restore RBX'),
    (63, '415c', 'error restore R12'),
    (65, '415e', 'error restore R14'),
    (67, '415f', 'error restore R15'),
    (69, '5d', 'error restore RBP'),
    (70, 'c3', 'indent-error return, no controller flag store'),
    (71, '83fe0a', 'compare full32 character with LF scalar ten'),
    (74, '410f9406', 'store LF predicate byte through cached flag pointer'),
    (78, '498b4720', 'load current character method V+32 AFTER flag store'),
    (82, '4889df', 'character destination is cached D'),
    (85, '5b', 'tail restore RBX'),
    (86, '415c', 'tail restore R12'),
    (88, '415e', 'tail restore R14'),
    (90, '415f', 'tail restore R15'),
    (92, '5d', 'tail restore RBP'),
    (93, 'ffe0', 'tail request; character low8 status has no normalizing successor'),
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prove_body(raw):
    """Below-identity, fixed-shape static operand/control certificate only."""
    need(type(raw) is bytes and len(raw) == SIZE, 'expected complete 95-byte body')
    rows, cursor = [], 0
    for offset, encoding, role in ROLES:
        expected = bytes.fromhex(encoding)
        need(offset == cursor, 'internal static witness tiling error')
        actual = raw[offset:offset + len(expected)]
        checked = bytearray(actual)
        if offset == 28:
            checked[3:7] = bytes(4)
        need(bytes(checked) == expected, 'character operand/control changed at ' + hex(offset))
        rows.append({'offset': offset, 'VA': START + offset, 'raw_hex': actual.hex(),
                     'bytes': len(actual), 'role': role})
        cursor += len(expected)
    need(cursor == SIZE, 'static witnesses do not enclose the complete body')
    branches = []
    for offset in (26, 58):
        destination = offset + 2 + struct.unpack_from('<b', raw, offset + 1)[0]
        need(destination == 71, 'branch does not reach the full32 scalar comparison')
        branches.append({'offset': offset, 'destination_offset': destination})
    return {'bytes': SIZE, 'rows': rows, 'row_count': len(rows), 'branches': branches,
            'parameters': {'indent_bytes': struct.unpack_from('<I', raw, 36)[0],
                           'byte_method_slot': raw[52], 'character_method_slot': raw[81],
                           'character_width_bits': 32, 'LF_scalar': raw[73], 'status_width_bits': 8,
                           'indent_error_status': raw[61], 'flag_store_offset': 74},
            'normal_paths': [
                {'condition': 'entry flag byte is zero', 'requests': ['character'],
                 'controller_flag_store': 'full32(character)==10 before character request',
                 'status': 'raw low8 character callback result'},
                {'condition': 'entry flag nonzero and indent low8 result nonzero',
                 'requests': ['four spaces'], 'controller_flag_store': None,
                 'status': 'canonical low8 one; callback flag effects survive'},
                {'condition': 'entry flag nonzero and indent low8 result zero',
                 'requests': ['four spaces', 'character'],
                 'controller_flag_store': 'full32(character)==10 after indent, before character',
                 'status': 'raw low8 character callback result'}],
            'source_order': ['cache N/D/V', 'sample N', 'optional byte request',
                             'own N store', 'fresh character-method load', 'tail request'],
            'frame': {'own_saved_bytes': 40, 'saved_registers': ['RBP', 'R15', 'R14', 'R12', 'RBX'],
                      'requires_normal_callback_returns_and_preserved_frame': True},
            'instruction_evaluator': False}


def derive(target, archive):
    """Unqualified correspondence/control seam; analyze admits exact identities."""
    member, member_offset = archive_member(archive)
    source, image = Image(member, 1), Image(target, 3)
    section = source.named(SECTION)
    need(section['size'] == SIZE and section['flags'] & 4, 'source complete FUNC section changed')
    symbols = source.named('.symtab')
    definitions = [source.symbol(symbols['index'], i) for i in range(symbols['size'] // 24)]
    definitions = [s for s in definitions if s['section_index'] == section['index'] and s['info'] & 15 == 2]
    need(len(definitions) == 1 and definitions[0]['name'] == FUNCTION
         and definitions[0]['value'] == 0 and definitions[0]['size'] == SIZE,
         'source selected definition is not the complete 95-byte FUNC')
    original = source.content(section)
    frame = selected_frame(image, START, SIZE)
    actual, file_offset, _ = image.virtual(START, SIZE, code=True)
    source_proof, target_proof = prove_body(original), prove_body(actual)
    relocations = source.object_relocations(section)
    need(len(relocations) == 1, 'expected exactly one source code relocation')
    relocation = relocations[0]
    need(relocation['offset'] == 31 and relocation['type'] == 2 and relocation['addend'] == -4,
         'source character PC32 field kind/addend changed')
    symbol = relocation['symbol']
    need(symbol['info'] & 15 == 1 and symbol['size'] == 4
         and 0 < symbol['section_index'] < len(source.sections), 'source indent is not the 4-byte object')
    data_section = source.sections[symbol['section_index']]
    constant = source.content(data_section)[symbol['value']:symbol['value'] + symbol['size']]
    need(constant == b'    ', 'source indentation bytes changed')
    destination = START + 35 + struct.unpack_from('<i', actual, 31)[0]
    data, data_offset, data_segment = image.virtual(destination, 4)
    need(data == constant, 'target four-space reference disagrees with source')
    mask = set(range(31, 35))
    need(all(original[i] == actual[i] for i in range(SIZE) if i not in mask),
         '95-byte body differs outside its actual PC32 field')
    table_section = source.named(LAYOUT_SECTION)
    layout = source.content(table_section)
    need(len(layout) == 48, 'selected source layout extent changed')
    layout_actual, layout_offset, _ = image.virtual(LAYOUT, 48)
    need(layout_actual == layout, 'selected layout raw data disagreement')
    pointers = [r for r in source.object_relocations(table_section) if r['offset'] == 32]
    need(len(pointers) == 1, 'source character pointer is not unique')
    pointer = pointers[0]
    need(pointer['type'] == 1 and pointer['addend'] == 0
         and pointer['symbol'] == definitions[0], 'source +32 is not the selected complete FUNC')
    slot = LAYOUT + 32
    actual_pointers = [r for r in image.rela_rows(image.named('.rela.dyn')) if r['offset'] == slot]
    need(len(actual_pointers) == 1, 'captured +32 pointer lacks one relocation')
    dynamic = actual_pointers[0]
    need(dynamic['type'] == 8 and dynamic['symbol_index'] == 0 and dynamic['addend'] == START,
         'captured +32 is not a symbol-free RELATIVE to the selected character body')
    slot_raw, slot_offset, slot_section = image.virtual(slot, 8)
    dynamic.update(slot_file_offset=slot_offset, slot_section=slot_section['name'], raw_slot_hex=slot_raw.hex())
    return {'schema': 'node94-character-request-v1', 'identity_admitted': False,
            'target': {'release': 94, 'bytes': len(target), 'sha256': sha(target)},
            'official_archive': {'bytes': len(archive), 'sha256': sha(archive),
                                 'member_data_offset': member_offset, 'member_sha256': sha(member)},
            'source_FUNC': definitions[0], 'source_section': section,
            'frame': frame, 'body_file_offset': file_offset, 'raw_target_hex': actual.hex(),
            'raw_source_hex': original.hex(), 'target_proof': target_proof, 'source_proof': source_proof,
            'comparison': {'bytes': SIZE, 'actual_RELA_bytes': 4, 'equal_nonRELA_bytes': 91,
                           'raw_equal': actual == original, 'masked_offsets': sorted(mask)},
            'code_RELA': relocation,
            'indent_data': {'target_VA': destination, 'target_file_offset': data_offset,
                            'target_section': data_segment['name'], 'raw_hex': data.hex(),
                            'source_object': symbol, 'raw_equal': True},
            'selected_layout': {'target_VA': LAYOUT, 'target_file_offset': layout_offset,
                                'source_section': table_section, 'raw_hex': layout.hex(),
                                'source_pointer': pointer, 'target_pointer': dynamic},
            'limits': ['Conditional normal callback request protocol, not rendering or UTF8 encoding.',
                       'Safe Rust valid char/reference and separated frame/receiver/table/flag roles are stronger premises.',
                       'AL is the observed status projection; raw values are not established original Result discriminants.',
                       'RAX high bits, RSI high32, unwinding, concurrency and raw aliases are not qualified.',
                       'Callbacks preserve callee-saved/frame obligations; proxy dispatch bridges cached D/V and fresh methods.',
                       'Other layout edges and prior1456-byte primary denominator are unchanged; no gate/whole-ELF/sourcebuild claim.']}


def analyze(target, archive):
    need(type(target) is bytes and len(target) == TARGET_SIZE and sha(target) == TARGET_SHA256,
         'expected immutable authenticated node94 bytes')
    need(type(archive) is bytes and len(archive) == ARCHIVE_SIZE and sha(archive) == ARCHIVE_SHA256,
         'expected immutable authenticated official archive bytes')
    member, _ = archive_member(archive)
    need(sha(member) == MEMBER_SHA256, 'selected official member changed')
    result = derive(target, archive)
    result['identity_admitted'] = True
    return result


def generate(binary, libcore, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('output already exists; preserve previous evidence')
    result = analyze(Path(binary).read_bytes(), Path(libcore).read_bytes())
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'records.json').open('xb') as handle:
        handle.write((json.dumps(result, indent=2, sort_keys=True) + '\n').encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--libcore', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.binary, args.libcore, args.output)


if __name__ == '__main__':
    main()
