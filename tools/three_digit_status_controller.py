#!/usr/bin/env python3
"""Bind the node94 ':status' selector and stores before unresolved callbacks.

Static evidence only: no target instructions, emulator, reconstructed Rust or
native provider runs. analyze() is the below-identity structural seam;
collect() admits one immutable full-SHA input before producing any output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_BYTES = 91774280
CALLER_START, CALLER_END = 0x1682220, 0x1682735
LEAF_START, LEAF_END = 0x1683670, 0x16836c5
TABLE_VA = 0x27fac8
CALLER_SHA256 = 'a1a34984f457e4413ab96820190afa549708a6c14a7eb9ca0715a5d65a7b078b'
LEAF_SHA256 = '90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca'
TABLE_SHA256 = '563293dcb3e8905b6330bcb5121ea5f8b4356c4b95e6c1363fd0fea2207ee5f1'
TABLE_TARGETS = (0x168226f, 0x1682676, 0x168242c,
                 0x1682676, 0x1682399, 0x16824ae)
# These disjoint spans are a subset of the 1301-byte boundary body, not an
# additional function or coverage denominator. The85-byte leaf is separate.
SELECTED_SPANS = ((0x168222e, 0x168226f), (0x16822fd, 0x1682306),
                  (0x1682306, 0x1682320), (0x168242c, 0x1682442),
                  (0x16825cc, 0x168261f), (0x168267f, 0x16826b8))
FDE_RECORDS = (
    ('caller', 0x10008c0, CALLER_START, CALLER_END, 0xfbdc2c,
     '50000000982c04005819680015050000048fad94ff410e10420e18420e20420e28420e30410e38440e800183078c068d058e048f038602037f040e38410e30420e28420e20420e18420e10410e08410e80010000',
     '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000'),
    ('leaf', 0xd05d1c, LEAF_START, LEAF_END, 0xce1518,
     '10000000084802004cd997005500000000000000',
     '1400000000000000017a5200017810011b0c070890010000'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(raw, address, opcode):
    """Decode only an explicitly selected rel8/rel32 instruction field."""
    prefix = bytes.fromhex(opcode)
    require(raw.startswith(prefix), f'Branch opcode changed at {address:#x}')
    width = len(raw) - len(prefix)
    require(width in (1, 4), 'Unsupported selected relative width')
    return address + len(raw) + int.from_bytes(raw[len(prefix):], 'little', signed=True)


def selected_facts(caller, leaf, table):
    """Qualify actual small byte spans, without interpreting a CPU or memory."""
    require(len(caller) == CALLER_END - CALLER_START, 'Caller byte extent changed')
    require(len(leaf) == LEAF_END - LEAF_START, 'Leaf byte extent changed')
    require(len(table) == 24, 'Six signed-DWord table extent changed')
    table_rows = []
    for i, displacement in enumerate(struct.unpack('<6i', table)):
        target = TABLE_VA + displacement
        require(target == TABLE_TARGETS[i], f'Selected table destination changed at index {i}')
        table_rows.append({'index': i, 'key_length': i + 5,
                           'raw': table[i * 4:i * 4 + 4].hex(),
                           'signed_displacement': displacement, 'target_va': hex(target)})

    def code(va, raw, label):
        expected = bytes.fromhex(raw)
        off = va - CALLER_START
        actual = caller[off:off + len(expected)]
        require(actual == expected, f'{label} changed at {va:#x}')
        return actual

    # Raw address-role/length/pointer loads and the complete selected-byte gate.
    for va, raw, label in (
        (0x168222e, '4989d7', 'Value record role'),
        (0x1682231, '4889f3', 'Key record role'),
        (0x1682234, '4989fe', 'Output role'),
        (0x1682237, '488b5610', 'Key length load'),
        (0x168223b, '4885d2', 'Zero key length test'),
        (0x1682244, '488b7308', 'Key pointer load'),
        (0x1682248, '803e3a', 'First literal byte'),
        (0x1682251, '4883c2fb', 'Unsigned length subtract5'),
        (0x1682255, '4883fa05', 'Unsigned length upper bound'),
        (0x168225f, '488d0562d8bffe', 'Table PC-relative base'),
        (0x1682266, '48630c90', 'Signed-DWord table read'),
        (0x168226a, '4801c1', 'Relative table target addition'),
        (0x168226d, 'ffe1', 'Indirect table branch'),
        (0x168242c, '0fb64601', 'Second literal byte load'),
        (0x1682430, '83f873', 'Second literal byte'),
        (0x1682439, '83f86d', 'Other length7 byte comparison'),
        (0x16825cc, '0fb64602', 'Third literal byte load'),
        (0x16825d0, '83f863', 'Alternate third byte comparison'),
        (0x16825d5, '83f874', 'Third literal byte'),
        (0x16825de, '807e0361', 'Fourth literal byte'),
        (0x16825e8, '807e0474', 'Fifth literal byte'),
        (0x16825f2, '807e0575', 'Sixth literal byte'),
        (0x16825f8, '807e0673', 'Seventh literal byte'),
        (0x16825fe, '498b7f08', 'Leaf pointer argument'),
        (0x1682602, '498b7710', 'Leaf length argument'),
        (0x168260b, '6685c0', 'AX zero test'),
        (0x1682614, '66418906', 'Nonzero WORD output store'),
        (0x1682618, '41c6464007', 'Nonzero tag7 store'),
        (0x16822fd, '41c60607', 'Invalid BYTE output store'),
        (0x1682301, '41c6464008', 'Invalid tag8 store'),
    ):
        code(va, raw, label)
    # Re-derive the table base from the real RIP displacement, not a guessed VA.
    base_code = caller[0x168225f - CALLER_START:0x1682266 - CALLER_START]
    base = 0x1682266 + int.from_bytes(base_code[3:], 'little', signed=True)
    require(base == TABLE_VA, 'Table base relation changed')

    flows = []
    for va, raw, opcode, target in (
        (0x168223e, '0f84a1000000', '0f84', 0x16822e5),
        (0x168224b, '0f859a000000', '0f85', 0x16822eb),
        (0x1682259, '0f8717040000', '0f87', 0x1682676),
        (0x1682433, '0f8493010000', '0f84', 0x16825cc),
        (0x168243c, '0f8534020000', '0f85', 0x1682676),
        (0x16825d3, '744a', '74', 0x168261f),
        (0x16825d8, '0f8598000000', '0f85', 0x1682676),
        (0x16825e2, '0f858e000000', '0f85', 0x1682676),
        (0x16825ec, '0f8584000000', '0f85', 0x1682676),
        (0x16825f6, '757e', '75', 0x1682676),
        (0x16825fc, '7578', '75', 0x1682676),
        (0x1682606, 'e865100000', 'e8', LEAF_START),
        (0x168260e, '0f84e9fcffff', '0f84', 0x16822fd),
        (0x168261d, 'eb60', 'eb', 0x168267f),
        (0x168231b, 'e974030000', 'e9', 0x1682694),
    ):
        b = code(va, raw, 'Selected control flow')
        actual = relative(b, va, opcode)
        require(actual == target, 'Selected raw relative destination changed')
        flows.append({'va': hex(va), 'raw': b.hex(), 'target_va': hex(actual)})

    # Keep the actual post-store unresolved effects visible in the certificate.
    callbacks = []
    for va, raw, label in (
        (0x1682306, '498b07498b7708498b57104983c7184c89ffff5020', 'Invalid-route callback setup'),
        (0x168267f, '498b07498b7708498b57104983c7184c89ffff5020', 'Nonzero-route callback setup'),
        (0x1682694, '488d7b18488b03488b7308488b5310ff5020', 'Common key callback setup'),
        (0x16826a6, '4c89f04883c4485b415c415d415e415f5dc3', 'Normal epilogue'),
    ):
        b = code(va, raw, label)
        callbacks.append({'va': hex(va), 'raw': b.hex(), 'role': label})

    # Hashes bind the unused boundary context and exact admitted leaf; this is
    # not a general decoder or an assertion that every caller path is qualified.
    require(digest(caller) == CALLER_SHA256, 'Caller boundary bytes changed')
    require(digest(leaf) == LEAF_SHA256, 'Existing three-digit leaf bytes changed')
    require(digest(table) == TABLE_SHA256, 'Table bytes changed')
    literal_sites = ((0x168224a, 1), (0x1682432, 1), (0x16825d7, 1),
                     (0x16825e1, 1), (0x16825eb, 1),
                     (0x16825f5, 1), (0x16825fb, 1))
    literal = bytes(caller[va - CALLER_START] for va, _ in literal_sites)
    require(literal == b':status', 'Derived key literal changed')
    return {
        'table': table_rows,
        'selected_key': {'length': 7, 'raw': literal.hex(),
                         'ascii': literal.decode('ascii'),
                         'source_instruction_immediate_vas': [hex(va) for va, _ in literal_sites]},
        'selected_relative_edges': flows,
        'post_store_callbacks_and_epilogue': callbacks,
        'leaf_relation': 'Length3 and b0 ASCII1..9/b1,b2 ASCII0..9 gives100*(b0-48)+10*(b1-48)+(b2-48) in100..999; otherwise AX0',
        'observation_boundaries': {'nonzero_next_va': '0x168261d', 'zero_next_va': '0x1682306'},
        'ordered_nonzero_stores': [
            {'va': '0x1682614', 'bits': 16, 'output_offset': 0, 'value': 'AX100..999'},
            {'va': '0x1682618', 'bits': 8, 'output_offset': 64, 'value': 7}],
        'ordered_zero_stores': [
            {'va': '0x16822fd', 'bits': 8, 'output_offset': 0, 'value': 7},
            {'va': '0x1682301', 'bits': 8, 'output_offset': 64, 'value': 8}],
        'invalid_output_byte1_written_by_selected_stage': False,
        'whole_return_contents_qualified': False,
        'runtime_callback_targets_or_contracts_qualified': False,
        'rust_or_controller_equivalence_claim': False,
    }


def analyze(data):
    """Below full identity: static mappings and the narrowly supported records."""
    require(data[:6] == b'\x7fELF\x02\x01' and len(data) >= 64,
            'Expected ELF64 little-endian input')
    require(struct.unpack_from('<HH', data, 16) == (3, 62), 'Expected captured ET_DYN x86-64')
    secs = sections(data)
    for name in ('.text', '.rodata', '.eh_frame'):
        require(sum(s['name'] == name for s in secs) == 1, f'Duplicate or missing selected section {name}')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    require(phsize >= 56 and phcount and phoff + phsize * phcount <= len(data), 'Invalid program table')
    segments = []
    for i in range(phcount):
        typ, flags, off, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        require(filesz <= memsz and off + filesz <= len(data), 'Invalid program extent')
        if typ == 1:
            segments.append({'flags': flags, 'offset': off, 'va': va,
                             'filesz': filesz, 'memsz': memsz, 'align': align})
    mappings = {}

    def read(va, size, name):
        ss = [s for s in secs if s['type'] != 8 and s['address'] <= va
              and va + size <= s['address'] + s['size']]
        pp = [p for p in segments if p['va'] <= va and va + size <= p['va'] + p['filesz']]
        require(len(ss) == len(pp) == 1, f'Non-unique file-backed source mapping at {va:#x}')
        s, p = ss[0], pp[0]
        off = s['offset'] + va - s['address']
        require(off == p['offset'] + va - p['va'] and s['name'] == name,
                f'Section/PT_LOAD source disagreement at {va:#x}')
        if name == '.text':
            require(s['flags'] & 4 and p['flags'] & 1, 'Code mapping is not executable')
        mappings[hex(va)] = {'va': hex(va), 'bytes': size, 'file_offset': off,
                             'section': s, 'PT_LOAD': p}
        return bytes(data[off:off + size])

    caller = read(CALLER_START, CALLER_END - CALLER_START, '.text')
    leaf = read(LEAF_START, LEAF_END - LEAF_START, '.text')
    table = read(TABLE_VA, 24, '.rodata')
    facts = selected_facts(caller, leaf, table)
    files = {'caller-boundary.bin': caller, 'existing-leaf.bin': leaf, 'jump-table.bin': table}
    fdes = []
    for label, va, start, end, cie_va, fde_hex, cie_hex in FDE_RECORDS:
        expected, expected_cie = bytes.fromhex(fde_hex), bytes.fromhex(cie_hex)
        fde = read(va, len(expected), '.eh_frame')
        cie = read(cie_va, len(expected_cie), '.eh_frame')
        require(fde == expected and cie == expected_cie, f'{label} narrow FDE/CIE bytes changed')
        require(struct.unpack_from('<I', fde)[0] + 4 == len(fde), 'Declared narrow FDE extent changed')
        require(va + 4 - struct.unpack_from('<I', fde, 4)[0] == cie_va, 'Narrow FDE CIE pointer changed')
        pc = va + 8 + struct.unpack_from('<i', fde, 8)[0]
        extent = struct.unpack_from('<I', fde, 12)[0]
        require((pc, pc + extent) == (start, end), 'Narrow FDE function extent changed')
        files[label + '.fde.bin'], files[label + '.cie.bin'] = fde, cie
        fdes.append({'role': label, 'start_va': hex(pc), 'end_va': hex(pc + extent),
                     'fde_va': hex(va), 'fde_bytes': len(fde), 'cie_va': hex(cie_va),
                     'qualification': 'Exact selected records/known encodings only; no full unwind or LSDA semantics'})
    spans = []
    combined = bytearray()
    for start, end in SELECTED_SPANS:
        b = caller[start - CALLER_START:end - CALLER_START]
        spans.append({'start_va': hex(start), 'end_va': hex(end), 'bytes': len(b),
                      'concatenated_file_offset': len(combined), 'sha256': digest(b)})
        combined.extend(b)
    require(len(combined) == 262, 'Selected subset denominator changed')
    files['selected-code.bin'] = bytes(combined)
    report = {'schema': 'node94-status-selected-static-v1',
              'target_sha256': TARGET_SHA256, 'target_bytes': TARGET_BYTES,
              'scope': {'caller_boundary_bytes': len(caller),
                        'selected_caller_subset_bytes': len(combined),
                        'existing_leaf_bytes': len(leaf), 'table_bytes': len(table),
                        'subset_is_not_additional_code_coverage': True},
              'selected_spans': spans, 'source_mappings': mappings, 'narrow_FDEs': fdes,
              'facts': facts,
              'conditions': [
                  'Exact admitted node94 code/data under one common ET_DYN load bias',
                  'Ordinary caller entry; protected valid stack/RET/code; no external entry or exception transfer',
                  'Valid record fields/key/value reads and selected output writes; separated regions if preservation of other roles is required',
                  'Observation ends immediately after selected stores, before callback setup/effects'],
              'unknowns': [
                  'Runtime callback targets, writes/aliases, normal return and unwind contracts',
                  'Final returned memory, other key-route outcomes, complete caller/source/type/runtime identity'],
              'inferences': ['HTTP-style status pseudo-header is a possible interpretation of observed literal; field purpose is not established by bytes alone'],
              'progress_gate_change': False,
              'captured_native_emulator_or_reconstructed_code_execution': False}
    return report, files


def collect(binary, output):
    binary, output = Path(binary), Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    data = binary.read_bytes()
    require(len(data) == TARGET_BYTES and digest(data) == TARGET_SHA256, 'Node94 full immutable input digest mismatch')
    report, files = analyze(data)
    report['analysis_source_bindings'] = {
        name: digest((Path(__file__).parent / name).read_bytes())
        for name in (Path(__file__).name, 'elf_index.py')}
    report['admission'] = 'One complete SHA-authenticated immutable bytes object; every target fact and exported slice derives from it. Source-file hashes are observations, not an atomic hostile-host guarantee.'
    files['REPORT.json'] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    manifest = {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in sorted(files.items())}
    files['MANIFEST.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        (output / name).write_bytes(raw)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    report = collect(args.binary, args.output_dir)
    print(json.dumps({'scope': report['scope'], 'selected_key': report['facts']['selected_key'],
                      'whole_return_contents_qualified': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print(f'three_digit_status_controller: {error}', file=sys.stderr)
        raise SystemExit(1)
