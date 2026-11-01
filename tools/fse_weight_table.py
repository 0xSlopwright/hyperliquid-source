"""Bounded static evidence for the qualified node94 weight-table constructor.

Captured code is never run. The instruction-byte schema is evidence validation,
not an implementation or general x86 decoder; Rust compilation uses separate
independently authored source. Rendered disassembler prose is not authoritative.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_SIZE = 91774280
PRIMARY_START = 0x556fb60
PRIMARY_END = 0x556fe63
BODY_SHA256 = '8d7636d905df5188c3a5d0d495cf337bf1eca14949a373cc7e5393f5ae94484e'
PROVIDER = Path('/usr/bin/x86_64-linux-gnu-objdump')
PROVIDER_SHA256 = '96afb8521834982d0e711b5d6e9785252bf82129fb0106b93a6bd54d83fae11f'
# Every original instruction's offset/length/data-flow bytes; declared operand
# fields below are decoded separately. None of these bytes enters rustc.
ROW_SCHEMA = (
    (0, '4157'),
    (2, '4156'),
    (4, '4155'),
    (6, '4154'),
    (8, '55'),
    (9, '53'),
    (10, '89d3'),
    (12, '488d4301'),
    (16, '89c2'),
    (18, '48894424d8'),
    (23, 'b801000000'),
    (28, '48d3e0'),
    (31, '488d445008'),
    (36, '4939c1'),
    (39, '48c7c0d2ffffff'),
    (46, '410f92c4'),
    (50, '81fbff000000'),
    (56, '0f97c2'),
    (59, '4108d4'),
    (62, '0f858a010000'),
    (68, '89cd'),
    (70, '48c7c0d4ffffff'),
    (77, '83f90c'),
    (80, '0f8778010000'),
    (86, '41be01000000'),
    (92, '4989f3'),
    (95, '488d4704'),
    (99, '4889de'),
    (102, '4489f2'),
    (105, '48894424d0'),
    (110, '83c601'),
    (113, '4531d2'),
    (116, 'd3e2'),
    (118, '0fb7c9'),
    (121, '41bd01000000'),
    (127, '4531ff'),
    (130, '81c900000100'),
    (136, '448d4aff'),
    (140, '895424e8'),
    (144, '894c24f4'),
    (148, '894c24e0'),
    (152, '8d4dff'),
    (155, '41d3e6'),
    (158, '4489c9'),
    (161, 'eb21'),
    (163, '0f1f440000'),
    (168, '664439f0'),
    (172, '6643890450'),
    (177, '41bc01000000'),
    (183, '450f4def'),
    (187, '4983c201'),
    (191, '4139f2'),
    (194, '732d'),
    (196, '430fb70453'),
    (201, '6683f8ff'),
    (205, '75d9'),
    (207, '488b5424d0'),
    (212, '89c8'),
    (214, '83e901'),
    (217, '4488548202'),
    (222, 'b801000000'),
    (227, '6643890450'),
    (232, '4983c201'),
    (236, '4139f2'),
    (239, '72d3'),
    (241, '8b5424e8'),
    (245, '4584e4'),
    (248, '7412'),
    (250, '440fb75424f4'),
    (256, '41c1e510'),
    (260, '4509ea'),
    (263, '44895424e0'),
    (268, '8b4424e0'),
    (272, '4189d4'),
    (275, '4189d2'),
    (278, '4531ed'),
    (281, '41c1ea03'),
    (285, '41d1ec'),
    (288, '478d641403'),
    (293, '8907'),
    (295, '4531d2'),
    (298, '4439c9'),
    (301, '0f84a6000000'),
    (307, '895424d8'),
    (311, '4c8b7c24d0'),
    (316, '0f1f4000'),
    (320, '470fbf346b'),
    (325, '4489eb'),
    (328, '31c0'),
    (330, '664585f6'),
    (334, '7e23'),
    (336, '4489d2'),
    (339, '41885c9702'),
    (344, '0f1f840000000000'),
    (352, '4501e2'),
    (355, '4521ca'),
    (358, '4439d1'),
    (361, '72f5'),
    (363, '83c001'),
    (366, '4439f0'),
    (369, '75dd'),
    (371, '4983c501'),
    (375, '4139f5'),
    (378, '72c4'),
    (380, '8b5424d8'),
    (384, '48c7c0ffffffff'),
    (391, '4585d2'),
    (394, '7542'),
    (396, '4189d1'),
    (399, '31f6'),
    (401, '0f1f8000000000'),
    (408, '0fb644b706'),
    (413, '498d0c40'),
    (417, '0fb701'),
    (420, '448d5001'),
    (424, '66448911'),
    (428, '0fbdc8'),
    (431, '83f11f'),
    (434, '8d4c0de1'),
    (438, 'd3e0'),
    (440, '884cb707'),
    (444, '4429c8'),
    (447, '668944b704'),
    (452, '4883c601'),
    (456, '39d6'),
    (458, '72cc'),
    (460, '31c0'),
    (462, '5b'),
    (463, '5d'),
    (464, '415c'),
    (466, '415d'),
    (468, '415e'),
    (470, '415f'),
    (472, 'c3'),
    (473, '488b4424d8'),
    (478, '4189ce'),
    (481, '895424d8'),
    (485, '4589e7'),
    (488, '4c897424e0'),
    (493, '4531c9'),
    (496, '31c9'),
    (498, '4d8d1440'),
    (502, '488d441b0a'),
    (507, '48897c24e8'),
    (512, '4889c7'),
    (515, '4b0fbf146b'),
    (520, '4d890c0a'),
    (524, '6683fa08'),
    (528, '7e77'),
    (530, '0fbfc2'),
    (533, '83e809'),
    (536, '89c3'),
    (538, 'c1eb03'),
    (541, '83c301'),
    (544, '83f807'),
    (547, '0f86d0000000'),
    (553, '4189dc'),
    (556, '488d040f'),
    (560, '66490f6ec1'),
    (565, '41d1ec'),
    (568, '4c01c0'),
    (571, '660f6cc0'),
    (575, '49c1e404'),
    (579, '4d8d3404'),
    (583, '4183e410'),
    (587, '7413'),
    (589, '0f1100'),
    (592, '4883c010'),
    (596, '4c39f0'),
    (599, '7417'),
    (601, '0f1f8000000000'),
    (608, '0f1100'),
    (611, '4883c020'),
    (615, '0f1140f0'),
    (619, '4c39f0'),
    (622, '75f0'),
    (624, 'f6c301'),
    (627, '7414'),
    (629, '83e3fe'),
    (632, '8d04dd08000000'),
    (639, '4898'),
    (641, '498d1c0a'),
    (645, '4c890c03'),
    (649, '48b80101010101010101'),
    (659, '4983c501'),
    (663, '4801d1'),
    (666, '4901c1'),
    (669, '4139f5'),
    (672, '0f825dffffff'),
    (678, '48635c24d8'),
    (683, '4c8b7424e0'),
    (688, '31f6'),
    (690, '31c9'),
    (692, '488b7c24e8'),
    (697, '488b4424d0'),
    (702, '4889da'),
    (705, '450fb61c32'),
    (710, '4d89f1'),
    (713, '4921c9'),
    (716, '4c01f9'),
    (719, '46885c8802'),
    (724, '4d89f1'),
    (727, '450fb65c3201'),
    (733, '4883c602'),
    (737, '4921c9'),
    (740, '4c01f9'),
    (743, '46885c8802'),
    (748, '4c21f1'),
    (751, '4839de'),
    (754, '72cd'),
    (756, 'e993feffff'),
    (761, 'b808000000'),
    (766, 'e97cffffff'),
)
FDE_RAW = bytes.fromhex('44000000ac132d0098d25b040303000000420e108f02420e188e03420e208d04420e288c05410e308606410e38830703c5010a0e30410e28420e20420e18420e10420e08410b0000')
CIE_RAW = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
# name: (linked instruction address, field offset, size, signed, admitted value)
FIELDS = {
    'scratch_extra': (0x556fb7f, 4, 1, False, 8),
    'max_symbol_guard': (0x556fb92, 2, 4, False, 255),
    'log_guard': (0x556fbad, 2, 1, False, 12),
    'table_header_bytes': (0x556fbbf, 3, 1, False, 4),
    'table_mask_adjustment': (0x556fbe8, 3, 1, True, -1),
    'half_log_adjustment': (0x556fbf8, 2, 1, True, -1),
    'low_high_decrement': (0x556fc36, 2, 1, False, 1),
    'low_symbol_field': (0x556fc39, 4, 1, False, 2),
    'low_next_initial': (0x556fc3e, 1, 4, False, 1),
    'stride_bias': (0x556fc80, 4, 1, False, 3),
    'final_symbol_field': (0x556fcf8, 4, 1, False, 6),
    'final_bits_field': (0x556fd18, 3, 1, False, 7),
    'final_base_field': (0x556fd1f, 4, 1, False, 4),
    'padded_list_base': (0x556fd56, 4, 1, False, 10),
}

# Separate revisited caller cuts: these bytes are not primary771 coverage.
CALLER_WITNESSES = (
    ('builder_workspace_advertisement', 90083223, '488db9e0030000488d89e00400004c8d9424b400000041514989c1686c030000514c89d156be000100004c8d8424d0000000e8a269f8ff'),
    ('compressed_caller_limit_and_selector', 89583408, '4c8d69014c39e872e86a01498d51014c89f74883ee01ff7424484c8b4c244841b806000000e8361a0000'),
    ('selected_decoder_workspace_formula', 89587435, '8b4c24104139cc0f82f80300008b742414ba01000000b801000000c4e2f1f7d2c4e271f7c048988d7e01488d547a0b48c1ea02488d94108300000048c1e20248395424600f82bb0300004c8b4c246089f2488d048504020000488dbb000200004c8d04034889de4929c1e806fcffff'),
)

class EvidenceError(ValueError):
    """The selected original bytes/provider/proof domain is not admitted."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def authenticate(data):
    if type(data) is not bytes or len(data) != TARGET_SIZE or digest(data) != TARGET_SHA256:
        raise EvidenceError('Expected authenticated immutable node94 bytes')


def load_target(binary=TARGET):
    binary = Path(binary)
    with binary.open('rb') as handle:
        before = os.fstat(handle.fileno())
        data = handle.read()
        after = os.fstat(handle.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if identity(before) != identity(after):
        raise EvidenceError('Source changed while admitting immutable bytes')
    authenticate(data)
    return data


def verify_listing(listing, raw, start=PRIMARY_START):
    """Bind full byte tiling and exact instruction boundaries, not prose."""
    pattern = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S+)(?:\s+(.*))?$')
    found = []
    for line in listing.splitlines():
        match = pattern.match(line)
        if match:
            found.append((int(match[1], 16), bytes.fromhex(match[2])))
    if len(found) != len(ROW_SCHEMA):
        raise EvidenceError('Native listing instruction count/coverage changed')
    cursor = start
    for (address, observed), (offset, expected_hex) in zip(found, ROW_SCHEMA):
        expected_size = len(bytes.fromhex(expected_hex))
        if address != cursor or address != start + offset or len(observed) != expected_size:
            raise EvidenceError('Native listing address/boundary coverage changed')
        if observed != raw[offset:offset + expected_size]:
            raise EvidenceError('Native listing bytes differ from selected raw input')
        cursor += expected_size
    if cursor != start + len(raw):
        raise EvidenceError('Native listing does not cover the full selected extent')
    return found


def prove_table(raw, listing=None):
    """Validate actual opcode/data-flow fields and their bounded proof facts.

    This seam is deliberately below whole-ELF identity for real byte controls.
    It does not execute instructions, emulate their state, or accept prose as
    operand authority. It is specific to this measured 771-byte instruction map.
    """
    if type(raw) is not bytes or len(raw) != PRIMARY_END - PRIMARY_START:
        raise EvidenceError('Expected the complete 771-byte constructor extent')
    variable = set()
    values = {}
    for name, (address, at, size, signed, wanted) in FIELDS.items():
        offset = address - PRIMARY_START + at
        values[name] = int.from_bytes(raw[offset:offset + size], 'little', signed=signed)
        variable.update(range(offset, offset + size))
    for offset, expected_hex in ROW_SCHEMA:
        expected = bytes.fromhex(expected_hex)
        actual = raw[offset:offset + len(expected)]
        for index, (observed, wanted) in enumerate(zip(actual, expected)):
            if offset + index not in variable and observed != wanted:
                raise EvidenceError(f'Opcode/register/store data flow changed at {PRIMARY_START+offset:#x}')
    # The selected odd-step coverage premise is evaluated from the actual LEA
    # operand before applying this capture's exact operand identity below.
    for log in (5, 6):
        total = 1 << log
        stride = total // 2 + total // 8 + values['stride_bias']
        if math.gcd(stride, total) != 1:
            raise EvidenceError('Actual stride fails the complete table permutation premise')
    for name, (_, _, _, _, wanted) in FIELDS.items():
        if values[name] != wanted:
            raise EvidenceError(f'Actual {name} operand does not establish the captured layout/contract')
    if listing is not None:
        verify_listing(listing, raw)
    domains = []
    for log in (5, 6):
        total = 1 << log
        stride = total // 2 + total // 8 + values['stride_bias']
        actual_max = max(m for m in range(256)
                         if 4*(total + (total+2*(m+1)+11)//4 + 0x83) <= 876)
        constructor_max = max(m for m in range(256)
                              if total+2*(m+1)+values['scratch_extra'] <= 876-(4*total+0x204))
        domains.append({'log': log, 'T': total, 'stride': stride,
                        'caller876_max_symbol': actual_max,
                        'constructor_residual_only_max_symbol': constructor_max,
                        'table_bytes': 4+4*total,
                        'normalized_input': '-1 or0..T; initialized256WORDs; zero afterm; lastnonzero; sumabs=T',
                        'normal_row_relation': 'n=c..2c-1 forpositivec, n=1 forlow-1; b=log-floorlog2n; v=n*2^b-T',
                        'state_bound': '0<=v and v+(2^b-1)<T',
                        'flag_relation': 'headerhighWORD1 implies everyrow b>=1',
                        'workspace': 'scratch>=2*(m+1)+T+8; output4+4*T; countsread2*(m+1)'})
    return {'scope': 'Conditional771-byte constructor normal serialized-table relation only',
            'raw_sha256': digest(raw), 'native_rows': len(ROW_SCHEMA),
            'parameters': values, 'domains': domains,
            'whole_decoder_or_Rust_or_byte_identity_claim': False,
            'listing_prose_semantic_authority': False,
            'caller_qualification_note': '876/outer0x83/0x204 and91/11 are separately bound caller premises, not constants decoded from the primary771 body',
            'proof': {'both_spread_routes': True, 'all_low_edge_retained_in_native_proof': True,
                      'no_low_padded_SIMD_extent': '2*B nextWORDbytes then T+8 temporarysymbolbytes',
                      'calls': 0, 'normal_RAX': 0,
                      'out_of_domain_errors_observed_not_all_claimed_reachable': [-46, -44, -1],
                      'memory_domain': 'Normal nonwrapping accessible separated counts/output/scratch/protectedframe/code, architectural integer/BSR/SSE semantics'}}


def derive_metadata(data):
    """Selected FDE/section/PT_LOAD validation below the full identity gate."""
    try:
        secs = sections(data)
        frames = [section for section in secs if section['name'] == '.eh_frame']
        if len(frames) != 1 or frames[0]['type'] == 8:
            raise EvidenceError('Selected .eh_frame must be unique and file-backed')
        _, all_fdes = eh_frame_records(data, secs)
        selected = [row for row in all_fdes if row['start'] == PRIMARY_START]
        if len(selected) != 1 or selected[0]['end'] != PRIMARY_END:
            raise EvidenceError('Actual unique FDE extent must be exactly 771 bytes')
        fde = selected[0]
        if fde['lsda'] is not None:
            raise EvidenceError('Unexpected selected LSDA binding')
        executable = [s for s in secs if s['type'] != 8 and s['flags'] & 4
                      and s['address'] <= PRIMARY_START < PRIMARY_END <= s['address'] + s['size']]
        if len(executable) != 1:
            raise EvidenceError('Constructor needs one file-backed executable section')
        section = executable[0]
        offset = section['offset'] + PRIMARY_START - section['address']
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phentsize, phnum = struct.unpack_from('<HH', data, 54)
        if phentsize != 56 or phoff + phentsize*phnum > len(data):
            raise EvidenceError('Malformed ELF program-header table')
        loads = []
        for index in range(phnum):
            kind, flags, file_offset, va, _, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', data, phoff+index*phentsize)
            if kind == 1 and flags & 1 and va <= PRIMARY_START < PRIMARY_END <= va+filesz:
                loads.append({'index': index, 'flags': flags, 'va': va, 'file_offset': file_offset,
                              'filesz': filesz, 'memsz': memsz, 'alignment': alignment,
                              'selected_offset': file_offset+PRIMARY_START-va})
        if len(loads) != 1 or loads[0]['selected_offset'] != offset:
            raise EvidenceError('Executable PT_LOAD and section mapping must agree uniquely')
        if not 0 <= offset <= len(data)-(PRIMARY_END-PRIMARY_START):
            raise EvidenceError('Selected source bytes lie outside the file')
        frame = frames[0]
        bound = {}
        for name, address, wanted in [('FDE', fde['fde'], FDE_RAW), ('CIE', fde['cie'], CIE_RAW)]:
            at = frame['offset'] + address-frame['address']
            if not frame['offset'] <= at <= frame['offset']+frame['size']-4:
                raise EvidenceError('Selected frame record lies outside .eh_frame')
            length = struct.unpack_from('<I', data, at)[0]
            if length == 0xffffffff or at+4+length > frame['offset']+frame['size']:
                raise EvidenceError('Selected frame record length is unsupported/out of bounds')
            raw = data[at:at+4+length]
            if raw != wanted:
                raise EvidenceError(f'Complete selected {name} record differs from admitted original')
            bound[name] = {'va': address, 'file_offset': at, 'bytes': len(raw), 'raw': raw.hex()}
        caller_context = []
        for label, start, expected_hex in CALLER_WITNESSES:
            expected = bytes.fromhex(expected_hex)
            matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4
                       and s['address'] <= start and start+len(expected) <= s['address']+s['size']]
            if len(matches) != 1:
                raise EvidenceError('Caller witness needs unique executable source mapping')
            witness_section = matches[0]
            witness_offset = witness_section['offset']+start-witness_section['address']
            observed = data[witness_offset:witness_offset+len(expected)]
            if observed != expected:
                raise EvidenceError('Separate caller qualification witness changed: '+label)
            caller_context.append({'label': label, 'start': start, 'end': start+len(observed),
                                   'bytes': len(observed), 'file_offset': witness_offset,
                                   'sha256': digest(observed), 'raw': observed.hex(),
                                   'scope': 'Revisited caller qualification witness only; not primary771 coverage or an instruction transfer evaluator'})
        return {'start': PRIMARY_START, 'end': PRIMARY_END, 'bytes': PRIMARY_END-PRIMARY_START,
                'file_offset': offset, 'FDE': fde, 'frame_records': bound,
                'section': section, 'PT_LOAD': loads[0], 'caller_context': caller_context,
                'note': 'Selected metadata/records only, no full unwind behavior or global function denominator'}
    except EvidenceError:
        raise
    except (ValueError, KeyError, StopIteration, struct.error, IndexError) as error:
        raise EvidenceError(f'ELF/FDE metadata not admitted: {error}') from error


def decode_span(raw, start=PRIMARY_START):
    """Run the measured GNU reader only on a tiny owned non-executable file."""
    if type(raw) is not bytes or not 0 < len(raw) <= 1024:
        raise EvidenceError('Only the bounded tiny raw native input is allowed')
    if not PROVIDER.is_file() or digest(PROVIDER.read_bytes()) != PROVIDER_SHA256:
        raise EvidenceError('Qualified GNU provider unavailable; do not claim native qualification')
    with tempfile.TemporaryDirectory(prefix='fwt-') as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        raw_path = folder/'table.bin'
        with raw_path.open('xb') as handle:
            handle.write(raw)
        raw_path.chmod(0o600)
        argv = [str(PROVIDER), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma='+str(start), 'table.bin']
        result = subprocess.run(argv, cwd=folder, stdin=subprocess.DEVNULL, capture_output=True,
                                check=False, env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
        if result.returncode or result.stderr:
            raise EvidenceError('Native decoder did not complete with clean stderr')
        if raw_path.read_bytes() != raw or stat.S_IMODE(raw_path.stat().st_mode) != 0o600:
            raise EvidenceError('Owned native view changed')
    if digest(PROVIDER.read_bytes()) != PROVIDER_SHA256:
        raise EvidenceError('Native provider changed')
    text = result.stdout.decode('utf-8')
    pattern = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S+)(?:\s+(.*))?$')
    rows = []
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            rows.append({'address': int(match[1], 16), 'raw': bytes.fromhex(match[2]).hex(),
                         'mnemonic': match[3], 'operands': match[4] or ''})
    cursor = start
    for row in rows:
        fragment = bytes.fromhex(row['raw'])
        if row['address'] != cursor or fragment != raw[cursor-start:cursor-start+len(fragment)] or row['mnemonic'] in ('(bad)', '.byte'):
            raise EvidenceError('Native output bytes/boundaries/instructions are incomplete')
        cursor += len(fragment)
    if cursor != start+len(raw):
        raise EvidenceError('Native output coverage incomplete')
    provider = {'path': str(PROVIDER), 'sha256': PROVIDER_SHA256,
                'argv': argv, 'exit': result.returncode,
                'environment_overrides': {'LC_ALL': 'C', 'LANG': 'C'},
                'inherited_environment': 'trusted/unrecorded',
                'input_sha256': digest(raw), 'output_sha256': digest(result.stdout),
                'stderr_sha256': digest(result.stderr),
                'scope': 'Before/after provider hash checks, not atomic child-execution provenance; no captured code runs'}
    return rows, text, provider


def analyze(data):
    source_paths = ['tools/fse_weight_table.py', 'tools/elf_index.py', 'tools/fde_extents.py']
    source_before = {name: digest((ROOT/name).read_bytes()) for name in source_paths}
    authenticate(data)
    metadata = derive_metadata(data)
    at = metadata['file_offset']
    raw = data[at:at+metadata['bytes']]
    proof = prove_table(raw)
    rows, listing, provider = decode_span(raw)
    verify_listing(listing, raw)
    source_after = {name: digest((ROOT/name).read_bytes()) for name in source_paths}
    if source_before != source_after:
        raise EvidenceError('Source/provider helper files changed during collection')
    return {'schema': 'node94-qualified-weight-table-v1',
            'target': {'release': 'node94', 'bytes': len(data), 'sha256': digest(data)},
            'metadata': metadata, 'proof': proof, 'native_rows': rows,
            'native_listing': listing, 'provider': provider,
            'source_helpers': source_after,
            'source_binding_scope': 'Before/after file digests with trusted Python loading; not atomic module-load provenance',
            'limits': ['Primary771 bytes only; caller/header/decoder context separate',
                       'No PC/register evaluator, captured execution, runtime/import qualification or full decoder',
                       'No Rust compilation, original ABI/type/compiler/bytes or gate claim']}


def collect(binary, output):
    output = Path(output)
    if os.path.lexists(output):
        raise EvidenceError('Output directory must be new; retained evidence is preserved')
    data = load_target(binary)
    result = analyze(data)
    del data
    # All admission/proof/native work succeeded before exclusive publication.
    output.mkdir(mode=0o700)
    exports = {'records.json': (json.dumps(result, indent=2, sort_keys=True)+'\n').encode('utf-8'),
               'table.objdump.txt': result['native_listing'].encode('utf-8')}
    for name, raw in exports.items():
        with (output/name).open('xb') as handle:
            handle.write(raw)
    manifest = {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in exports.items()}
    with (output/'MANIFEST.json').open('x', encoding='utf-8', newline='\n') as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    result = collect(arguments.binary, arguments.output)
    print(json.dumps({'output': str(arguments.output), 'primary_bytes': 771,
                      'native_rows': result['proof']['native_rows'],
                      'target_sha256': result['target']['sha256']}))

if __name__ == '__main__':
    main()
