#!/usr/bin/env python3
"""Static capacity20 decimal-span contract of one authenticated node94 body.

This checks fixed raw operand/dataflow shapes, CFG edges and mathematical
certificates. It is not an instruction evaluator, target runner or formatter.
The separately reported selector and opaque helpers earn no closed-G claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

import bincode_varint as bv

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
PRIMARY_BASE, PRIMARY_END = 0x1570470, 0x157062C
SELECTOR_BASE, SELECTOR_END = 0x14F7660, 0x14F774B
PAIR_VA, LOWER_VA, UPPER_VA, PREFIX_VA = 0x252B1D, 0x208620, 0x203830, 0x252BED
U64_MAX = (1 << 64) - 1


class EvidenceError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def authenticate(data):
    require(type(data) is bytes and len(data) == SIZE and sha(data) == SHA256,
            'Input is not one authenticated immutable node94 bytes object')


# Fixed observed instruction shapes are evidence, not executable transplanted
# code. Every non-parameter opcode/register/displacement byte is constrained.
# Parameter fields below are decoded and proved; none is silently masked from
# the semantic checks. The Rust implementation will contain no such raw code.
PRIMARY_SCHEMA = (
    (0, '55', 'push   rbp'),
    (1, '4889e5', 'mov    rbp,rsp'),
    (4, '4157', 'push   r15'),
    (6, '4156', 'push   r14'),
    (8, '4154', 'push   r12'),
    (10, '53', 'push   rbx'),
    (11, '4889d1', 'mov    rcx,rdx'),
    (14, '4889fa', 'mov    rdx,rdi'),
    (17, '4989c8', 'mov    r8,rcx'),
    (20, '4881ffe8030000', 'cmp    rdi,0x3e8'),
    (27, '0f82d6000000', 'jb     0x1570567'),
    (33, '4c8d5eff', 'lea    r11,[rsi-0x1]'),
    (37, '4531c0', 'xor    r8d,r8d'),
    (40, '48bb4b598638d6c56d34', 'movabs rbx,0x346dc5d63886594b'),
    (50, '4c8d357426cefe', 'lea    r14,[rip+0xfffffffffece2674]        # 0x252b1d'),
    (57, '4989f9', 'mov    r9,rdi'),
    (60, '0f1f4000', 'nop    DWORD PTR [rax+0x0]'),
    (64, '4e8d1401', 'lea    r10,[rcx+r8*1]'),
    (68, '4983c2fc', 'add    r10,0xfffffffffffffffc'),
    (72, '4c89c8', 'mov    rax,r9'),
    (75, '48f7e3', 'mul    rbx'),
    (78, '4939ca', 'cmp    r10,rcx'),
    (81, '0f833f010000', 'jae    0x1570606'),
    (87, '48c1ea0b', 'shr    rdx,0xb'),
    (91, '69c210270000', 'imul   eax,edx,0x2710'),
    (97, '4589ca', 'mov    r10d,r9d'),
    (100, '4129c2', 'sub    r10d,eax'),
    (103, '4569fa7b140000', 'imul   r15d,r10d,0x147b'),
    (110, '41c1ef13', 'shr    r15d,0x13'),
    (114, '450fb7e7', 'movzx  r12d,r15w'),
    (118, '430fb60466', 'movzx  eax,BYTE PTR [r14+r12*2]'),
    (123, '4188440bfd', 'mov    BYTE PTR [r11+rcx*1-0x3],al'),
    (128, '4a8d0401', 'lea    rax,[rcx+r8*1]'),
    (132, '4883c0fd', 'add    rax,0xfffffffffffffffd'),
    (136, '4839c8', 'cmp    rax,rcx'),
    (139, '0f83f2000000', 'jae    0x15705f3'),
    (145, '430fb6446601', 'movzx  eax,BYTE PTR [r14+r12*2+0x1]'),
    (151, '4188440bfe', 'mov    BYTE PTR [r11+rcx*1-0x2],al'),
    (156, '4a8d0401', 'lea    rax,[rcx+r8*1]'),
    (160, '4883c0fe', 'add    rax,0xfffffffffffffffe'),
    (164, '4839c8', 'cmp    rax,rcx'),
    (167, '0f83d6000000', 'jae    0x15705f3'),
    (173, '416bc764', 'imul   eax,r15d,0x64'),
    (177, '4129c2', 'sub    r10d,eax'),
    (180, '450fb7d2', 'movzx  r10d,r10w'),
    (184, '430fb60456', 'movzx  eax,BYTE PTR [r14+r10*2]'),
    (189, '4188440bff', 'mov    BYTE PTR [r11+rcx*1-0x1],al'),
    (194, '4a8d0401', 'lea    rax,[rcx+r8*1]'),
    (198, '48ffc8', 'dec    rax'),
    (201, '4839c8', 'cmp    rax,rcx'),
    (204, '0f83b1000000', 'jae    0x15705f3'),
    (210, '430fb6445601', 'movzx  eax,BYTE PTR [r14+r10*2+0x1]'),
    (216, '4188040b', 'mov    BYTE PTR [r11+rcx*1],al'),
    (220, '4983c0fc', 'add    r8,0xfffffffffffffffc'),
    (224, '4983c3fc', 'add    r11,0xfffffffffffffffc'),
    (228, '4981f97f969800', 'cmp    r9,0x98967f'),
    (235, '4989d1', 'mov    r9,rdx'),
    (238, '0f874cffffff', 'ja     0x15704b0'),
    (244, '4901c8', 'add    r8,rcx'),
    (247, '4883fa09', 'cmp    rdx,0x9'),
    (251, '7656', 'jbe    0x15705c3'),
    (253, '498d40fe', 'lea    rax,[r8-0x2]'),
    (257, '4839c8', 'cmp    rax,rcx'),
    (260, '737d', 'jae    0x15705f3'),
    (262, '4189d1', 'mov    r9d,edx'),
    (265, '41c1e902', 'shr    r9d,0x2'),
    (269, '450fb7c9', 'movzx  r9d,r9w'),
    (273, '4569c97b140000', 'imul   r9d,r9d,0x147b'),
    (280, '41c1e911', 'shr    r9d,0x11'),
    (284, '456bd164', 'imul   r10d,r9d,0x64'),
    (288, '4429d2', 'sub    edx,r10d'),
    (291, '0fb7d2', 'movzx  edx,dx'),
    (294, '4c8d158025cefe', 'lea    r10,[rip+0xfffffffffece2580]        # 0x252b1d'),
    (301, '450fb61c52', 'movzx  r11d,BYTE PTR [r10+rdx*2]'),
    (306, '46885c06fe', 'mov    BYTE PTR [rsi+r8*1-0x2],r11b'),
    (311, '49ffc8', 'dec    r8'),
    (314, '4939c8', 'cmp    r8,rcx'),
    (317, '736a', 'jae    0x1570619'),
    (319, '410fb6545201', 'movzx  edx,BYTE PTR [r10+rdx*2+0x1]'),
    (325, '42881406', 'mov    BYTE PTR [rsi+r8*1],dl'),
    (329, '4c89ca', 'mov    rdx,r9'),
    (332, '4885ff', 'test   rdi,rdi'),
    (335, '750a', 'jne    0x15705cb'),
    (337, 'eb0d', 'jmp    0x15705d0'),
    (339, '4c89c0', 'mov    rax,r8'),
    (342, '4885ff', 'test   rdi,rdi'),
    (345, '7405', 'je     0x15705d0'),
    (347, '4885d2', 'test   rdx,rdx'),
    (350, '741a', 'je     0x15705ea'),
    (352, '48ffc8', 'dec    rax'),
    (355, '4839c8', 'cmp    rax,rcx'),
    (358, '731b', 'jae    0x15705f3'),
    (360, '83e20f', 'and    edx,0xf'),
    (363, '488d0d3b25cefe', 'lea    rcx,[rip+0xfffffffffece253b]        # 0x252b1d'),
    (370, '0fb64c5101', 'movzx  ecx,BYTE PTR [rcx+rdx*2+0x1]'),
    (375, '880c06', 'mov    BYTE PTR [rsi+rax*1],cl'),
    (378, '5b', 'pop    rbx'),
    (379, '415c', 'pop    r12'),
    (381, '415e', 'pop    r14'),
    (383, '415f', 'pop    r15'),
    (385, '5d', 'pop    rbp'),
    (386, 'c3', 'ret'),
    (387, '488d15fe3b1004', 'lea    rdx,[rip+0x4103bfe]        # 0x56741f8'),
    (394, '4889c7', 'mov    rdi,rax'),
    (397, '4889ce', 'mov    rsi,rcx'),
    (400, 'ff15c2d91f04', 'call   QWORD PTR [rip+0x41fd9c2]        # 0x576dfc8'),
    (406, '488d15eb3b1004', 'lea    rdx,[rip+0x4103beb]        # 0x56741f8'),
    (413, '4c89d7', 'mov    rdi,r10'),
    (416, '4889ce', 'mov    rsi,rcx'),
    (419, 'ff15afd91f04', 'call   QWORD PTR [rip+0x41fd9af]        # 0x576dfc8'),
    (425, '488d15d83b1004', 'lea    rdx,[rip+0x4103bd8]        # 0x56741f8'),
    (432, '4c89c7', 'mov    rdi,r8'),
    (435, '4889ce', 'mov    rsi,rcx'),
    (438, 'ff159cd91f04', 'call   QWORD PTR [rip+0x41fd99c]        # 0x576dfc8'),
)
SELECTOR_SCHEMA = (
    (0, '4156', 'push   r14'),
    (2, '53', 'push   rbx'),
    (3, '4883ec18', 'sub    rsp,0x18'),
    (7, '4889f3', 'mov    rbx,rsi'),
    (10, '8b4610', 'mov    eax,DWORD PTR [rsi+0x10]'),
    (13, 'a900000002', 'test   eax,0x2000000'),
    (18, '7541', 'jne    0x14f76b5'),
    (20, 'a900000004', 'test   eax,0x4000000'),
    (25, '7575', 'jne    0x14f76f0'),
    (27, '488b3f', 'mov    rdi,QWORD PTR [rdi]'),
    (30, '488d742404', 'lea    rsi,[rsp+0x4]'),
    (35, '41be14000000', 'mov    r14d,0x14'),
    (41, 'ba14000000', 'mov    edx,0x14'),
    (46, 'e8dd8d0700', 'call   0x1570470'),
    (51, '4929c6', 'sub    r14,rax'),
    (54, '4c8d0404', 'lea    r8,[rsp+rax*1]'),
    (58, '4983c004', 'add    r8,0x4'),
    (62, 'ba01000000', 'mov    edx,0x1'),
    (67, '4889df', 'mov    rdi,rbx'),
    (70, 'be01000000', 'mov    esi,0x1'),
    (75, '31c9', 'xor    ecx,ecx'),
    (77, '4d89f1', 'mov    r9,r14'),
    (80, 'e988000000', 'jmp    0x14f773d'),
    (85, '488b07', 'mov    rax,QWORD PTR [rdi]'),
    (88, '4531c9', 'xor    r9d,r9d'),
    (91, '488d0d5e0fd1fe', 'lea    rcx,[rip+0xfffffffffed10f5e]        # 0x208620'),
    (98, '4889c2', 'mov    rdx,rax'),
    (101, '66662e0f1f840000000000', 'data16 cs nop WORD PTR [rax+rax*1+0x0]'),
    (112, '89c6', 'mov    esi,eax'),
    (114, '83e60f', 'and    esi,0xf'),
    (117, '48c1ea04', 'shr    rdx,0x4'),
    (121, '0fb6340e', 'movzx  esi,BYTE PTR [rsi+rcx*1]'),
    (125, '4288740c13', 'mov    BYTE PTR [rsp+r9*1+0x13],sil'),
    (130, '49ffc9', 'dec    r9'),
    (133, '4883f80f', 'cmp    rax,0xf'),
    (137, '4889d0', 'mov    rax,rdx'),
    (140, '77e2', 'ja     0x14f76d0'),
    (142, 'eb2e', 'jmp    0x14f771e'),
    (144, '488b07', 'mov    rax,QWORD PTR [rdi]'),
    (147, '4531c9', 'xor    r9d,r9d'),
    (150, '488d0d33c1d0fe', 'lea    rcx,[rip+0xfffffffffed0c133]        # 0x203830'),
    (157, '4889c2', 'mov    rdx,rax'),
    (160, '89c6', 'mov    esi,eax'),
    (162, '83e60f', 'and    esi,0xf'),
    (165, '48c1ea04', 'shr    rdx,0x4'),
    (169, '0fb6340e', 'movzx  esi,BYTE PTR [rsi+rcx*1]'),
    (173, '4288740c13', 'mov    BYTE PTR [rsp+r9*1+0x13],sil'),
    (178, '49ffc9', 'dec    r9'),
    (181, '4883f80f', 'cmp    rax,0xf'),
    (185, '4889d0', 'mov    rax,rdx'),
    (188, '77e2', 'ja     0x14f7700'),
    (190, '4e8d040c', 'lea    r8,[rsp+r9*1]'),
    (194, '4983c014', 'add    r8,0x14'),
    (198, '49f7d9', 'neg    r9'),
    (201, '488d15bdb4d5fe', 'lea    rdx,[rip+0xfffffffffed5b4bd]        # 0x252bed'),
    (208, 'b902000000', 'mov    ecx,0x2'),
    (213, '4889df', 'mov    rdi,rbx'),
    (216, 'be01000000', 'mov    esi,0x1'),
    (221, 'ff15956b2704', 'call   QWORD PTR [rip+0x4276b95]        # 0x576e2d8'),
    (227, '4883c418', 'add    rsp,0x18'),
    (231, '5b', 'pop    rbx'),
    (232, '415e', 'pop    r14'),
    (234, 'c3', 'ret'),
)

# (VA, byte offset, size, signed immediate, mathematical name)
PRIMARY_FIELDS = (
    (0x1570484, 3, 4, True, 'group_threshold'),
    (0x1570498, 2, 8, False, 'division_magic'),
    (0x15704C7, 3, 1, False, 'high_shift'),
    (0x15704CB, 2, 4, True, 'chunk_divisor'),
    (0x15704D7, 3, 4, True, 'pair_magic'),
    (0x15704DE, 3, 1, False, 'pair_shift'),
    (0x157051D, 3, 1, True, 'pair_divisor'),
    (0x1570554, 3, 4, True, 'continuation_threshold'),
    (0x1570567, 3, 1, True, 'tail_single_threshold'),
    (0x1570579, 3, 1, False, 'tail_quarter_shift'),
    (0x1570581, 3, 4, True, 'tail_pair_magic'),
    (0x1570588, 3, 1, False, 'tail_pair_shift'),
    (0x157058C, 3, 1, True, 'tail_pair_divisor'),
    (0x15705D8, 2, 1, True, 'leading_mask'),
)
PRIMARY_RIP_FIELDS = (
    (0x15704A2, 'pairs_group'), (0x1570596, 'pairs_tail'),
    (0x15705DB, 'pairs_single'),
)
SELECTOR_FIELDS = (
    (0x14F766D, 1, 4, False, 'first_mask'),
    (0x14F7674, 1, 4, False, 'second_mask'),
    (0x14F7683, 2, 4, False, 'saved_capacity'),
    (0x14F7689, 1, 4, False, 'call_capacity'),
)
SELECTOR_RIP_FIELDS = (
    (0x14F76BB, 'lower_table'), (0x14F76F6, 'upper_table'),
    (0x14F7729, 'hex_prefix'),
)


def verify_listing(text, body, base):
    rows, cursor = [], base
    for line in text.splitlines():
        columns = line.split('\t')
        if len(columns) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', columns[0]):
            continue
        address = int(columns[0].strip()[:-1], 16)
        try:
            raw = bytes.fromhex(columns[1])
        except ValueError as error:
            raise EvidenceError('Native row contains invalid raw hex') from error
        require(raw and address == cursor and '(bad)' not in columns[2],
                'Native instruction tiling/coverage changed')
        require(body[address-base:address-base+len(raw)] == raw,
                'Native instruction bytes changed')
        rows.append({'va': address, 'bytes': raw.hex(), 'width': len(raw),
                     'assembly': columns[2]})
        cursor += len(raw)
    require(cursor == base+len(body), 'Native listing is not a complete bounded span')
    return rows


def decode_span(body, base):
    sizes = {PRIMARY_BASE: PRIMARY_END-PRIMARY_BASE,
             SELECTOR_BASE: SELECTOR_END-SELECTOR_BASE}
    require(base in sizes and len(body) == sizes[base], 'Unexpected bounded native span')
    version = subprocess.run(['objdump', '--version'], check=True,
                             capture_output=True, text=True).stdout.splitlines()[0]
    require('GNU objdump' in version, 'GNU objdump is required')
    with tempfile.TemporaryDirectory(prefix='integer-digit-raw-') as directory:
        path = Path(directory)/'span.bin'
        with path.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(body)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
                '-M', 'intel', '--insn-width=16', '--adjust-vma='+hex(base), str(path)]
        native = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
        require(path.read_bytes() == body, 'Owned native input changed')
        native = native.replace(str(path), '<node94-digit-span-'+hex(base)+'>')
    rows = verify_listing(native, body, base)
    return rows, native, {'version': version, 'argv': argv[:-1]+['<owned-small-raw-span>'],
                          'input_bytes': len(body), 'captured_execution': False}


def _shape(body, base, rows, schema, fields, rip_fields):
    require(len(rows) == len(schema), 'Observed instruction-row domain changed')
    variables = {}
    for va, start, size, signed, name in fields:
        variables.setdefault(va, []).append((start, size, signed, name))
    for va, name in rip_fields:
        variables.setdefault(va, []).append((3, 4, True, name))
    operands = {}
    for row, (offset, raw_hex, role) in zip(rows, schema):
        va = base+offset
        expected, actual = bytes.fromhex(raw_hex), bytes.fromhex(row['bytes'])
        require(row['va'] == va and len(actual) == len(expected),
                f'Instruction boundary/width changed at {va:#x}')
        variable_positions = set()
        for start, size, signed, name in variables.get(va, []):
            require(start+size <= len(actual), 'Operand field leaves instruction')
            variable_positions.update(range(start, start+size))
            value = int.from_bytes(actual[start:start+size], 'little', signed=signed)
            if (va, name) in rip_fields:
                value += va+len(actual)
            operands[name] = value
        require(all(a == b for i, (a, b) in enumerate(zip(actual, expected))
                    if i not in variable_positions),
                f'Opcode/register/store/dataflow obligation changed at {va:#x}: {role}')
    return operands


def _cfg(rows):
    starts = {row['va'] for row in rows}
    branches, calls, returns = [], [], []
    for row in rows:
        va, raw = row['va'], bytes.fromhex(row['bytes'])
        target, condition = None, None
        if 0x70 <= raw[0] <= 0x7f:
            target = va+2+int.from_bytes(raw[1:2], 'little', signed=True)
            condition = raw[0] & 15
        elif raw[:1] == b'\xeb':
            target = va+2+int.from_bytes(raw[1:2], 'little', signed=True)
        elif raw[:1] == b'\xe9':
            target = va+5+int.from_bytes(raw[1:5], 'little', signed=True)
        elif raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f:
            target = va+6+int.from_bytes(raw[2:6], 'little', signed=True)
            condition = raw[1] & 15
        if target is not None:
            require(target in starts, 'Local CFG target is not instruction-aligned')
            branches.append({'va': hex(va), 'target': hex(target), 'condition_code': condition})
        if raw[:1] == b'\xe8':
            calls.append({'va': hex(va), 'kind': 'direct',
                          'target': hex(va+5+int.from_bytes(raw[1:5], 'little', signed=True))})
        elif raw[:2] == b'\xff\x15':
            calls.append({'va': hex(va), 'kind': 'RIP-slot',
                          'slot': hex(va+6+int.from_bytes(raw[2:6], 'little', signed=True))})
        if raw == b'\xc3':
            returns.append(hex(va))
    return {'branches': branches, 'calls': calls, 'normal_return_sites': returns}


def _mathematics(p):
    require(p['group_threshold'] == 1000 and p['continuation_threshold'] == 9999999,
            'Initial/continuation group thresholds do not establish the <=999 tail')
    require(p['chunk_divisor'] == 10000 and p['high_shift'] == 11,
            'Observed unsigned division10000 shape changed')
    shift = 64+p['high_shift']
    delta = p['division_magic']*10000-(1 << shift)
    require(0 <= delta and delta*U64_MAX < 1 << shift,
            'Reciprocal10000 error bound fails for the full u64 domain')
    require(p['pair_magic'] == p['tail_pair_magic'] and
            p['pair_divisor'] == p['tail_pair_divisor'] == 100 and
            p['pair_shift'] == 19 and p['tail_quarter_shift'] == 2 and
            p['tail_pair_shift'] == 17,
            'Pair/tail quotient widths or divisors changed')
    pair_error = p['pair_magic']*100-(1 << p['pair_shift'])
    tail_error = p['tail_pair_magic']*25-(1 << p['tail_pair_shift'])
    require(0 <= pair_error and pair_error*9999 < 1 << p['pair_shift'],
            'Pair reciprocal error bound fails on0..9999')
    require(0 <= tail_error and tail_error*249 < 1 << p['tail_pair_shift'],
            'Tail reciprocal error bound fails on0..249')
    require(p['tail_single_threshold'] == 9 and p['leading_mask'] == 15,
            'Leading single-digit/zero obligation changed')
    require(9999*p['pair_magic'] < 1 << 31 and 249*p['tail_pair_magic'] < 1 << 31,
            'Observed signed32 products no longer have the proved exact small range')
    bins = []
    previous_end = -1
    for groups in range(6):
        lower = 0 if groups == 0 else 1000*10000**(groups-1)
        upper = 999 if groups == 0 else min(U64_MAX, 1000*10000**groups-1)
        require(lower == previous_end+1 and lower <= upper, 'Group partition is not exhaustive/contiguous')
        quotient_max = upper//(10000**groups)
        require(quotient_max <= 999 and (groups != 5 or quotient_max == 0),
                'Group exit quotient does not fit the proved tail')
        slots = [[20-4*(g+1), 20-4*g] for g in range(groups)]
        require(all(0 <= a < b <= 20 for a, b in slots), 'Group store escapes capacity20')
        max_tail = 0 if groups == 5 else 3
        require(20-4*groups-max_tail >= 0, 'Tail store escapes capacity20')
        bins.append({'groups': groups, 'input_lower': lower, 'input_upper': upper,
                     'remaining_quotient_max': quotient_max, 'group_write_intervals': slots,
                     'remaining_slots': 20-4*groups, 'maximum_high_tail_bytes': max_tail})
        previous_end = upper
    require(previous_end == U64_MAX, 'Unsigned64 domain is incomplete')
    return {'quotient10000': {'power': shift, 'positive_error': delta,
                             'max_error_numerator': delta*U64_MAX, 'bound': 1 << shift},
            'pair100': {'power': 19, 'positive_error': pair_error, 'domain': [0, 9999]},
            'tail25_after_quarter': {'power': 17, 'positive_error': tail_error, 'domain': [0, 249]},
            'low32_remainder': '(low32(n)-low32(10000*q)) mod2^32 = r, since0<=r<10000',
            'group_partition': bins,
            'tail_cases': [{'remaining': '0, original n=0', 'bytes': 1, 'value': 'zero'},
                           {'remaining': '0, original n!=0', 'bytes': 0},
                           {'remaining': '1..9', 'bytes': 1},
                           {'remaining': '10..99', 'bytes': 2},
                           {'remaining': '100..999', 'bytes': 3}],
            'normal_postcondition': 'start=20-D(n); buffer[start:20] is unsigned decimal n, D(0)=1; prefix[0:start] unchanged',
            'guard_call_unreachability': 'Every seven guarded byte-store index is in0..19 at C20; all three guard CALL blocks are outside this domain',
            'proof_kind': 'Static operand certificate plus all-input integer/range argument, not PC/register/memory execution'}


STORE_CERTIFICATES = (
    (0x15704EB, '20-4*(g+1)', 'T[2*floor(r_g/100)]', 0x15704BE, 0x15704C1),
    (0x1570507, '20-4*(g+1)+1', 'T[2*floor(r_g/100)+1]', 0x15704F8, 0x15704FB),
    (0x157052D, '20-4*(g+1)+2', 'T[2*(r_g mod100)]', 0x1570514, 0x1570517),
    (0x1570548, '20-4*(g+1)+3', 'T[2*(r_g mod100)+1]', 0x1570539, 0x157053C),
    (0x15705A2, 'u-2', 'T[2*(t mod100)]', 0x1570571, 0x1570574),
    (0x15705B5, 'u-1', 'T[2*(t mod100)+1]', 0x15705AA, 0x15705AD),
    (0x15705E7, 'u-h', 'T[2*leading_digit+1]', 0x15705D3, 0x15705D6),
)


def _byte_stores(rows):
    sites = []
    for row in rows:
        raw = bytes.fromhex(row['bytes'])
        i = 1 if 0x40 <= raw[0] <= 0x4f else 0
        if raw[i] == 0x88 and raw[i+1] >> 6 != 3:
            sites.append(row['va'])
    return sites


def prove_primary(body, pairs, listing=None):
    require(len(body) == PRIMARY_END-PRIMARY_BASE, 'Primary body is not complete444 bytes')
    require(pairs == ''.join(f'{x:02d}' for x in range(100)).encode('ascii'),
            'Observed decimal pair table is not the exact00..99 sequence')
    rows = decode_span(body, PRIMARY_BASE)[0] if listing is None else verify_listing(listing, body, PRIMARY_BASE)
    p = _shape(body, PRIMARY_BASE, rows, PRIMARY_SCHEMA, PRIMARY_FIELDS, PRIMARY_RIP_FIELDS)
    require(all(p[k] == PAIR_VA for _, k in PRIMARY_RIP_FIELDS), 'Actual pair-table RIP binding changed')
    graph = _cfg(rows)
    require(len(graph['branches']) == 14 and graph['normal_return_sites'] == ['0x15705f2'],
            'Primary normal CFG/RET closure changed')
    require(graph['calls'] == [{'va': hex(x), 'kind': 'RIP-slot', 'slot': '0x576dfc8'}
                               for x in [0x1570600, 0x1570613, 0x1570626]],
            'Guard-call closure changed')
    require(_byte_stores(rows) == [r[0] for r in STORE_CERTIFICATES],
            'Primary byte-store census changed')
    mathematics = _mathematics(p)
    p.update({'capacity': 20, 'division_shift': 64+p['high_shift']})
    stores = [{'va': hex(va), 'width_bits': 8, 'offset_expression': offset,
               'source_expression': source, 'guard_compare': hex(compare),
               'guard_branch': hex(branch)} for va, offset, source, compare, branch in STORE_CERTIFICATES]
    graph['guard_call_sites'] = [c['va'] for c in graph['calls']]
    return {'range': [hex(PRIMARY_BASE), hex(PRIMARY_END)], 'body_sha256': sha(body),
            'instruction_rows': len(rows), 'parameters': p, 'cfg': graph, 'store_sites': stores,
            'mathematics': mathematics,
            'flag_chains': ['CMP old quotient1570554; MOV quotient157055b preserves flags; JA157055e',
                            'TEST original n15705bc/15705c6 and TEST remaining15705cb govern optional high/zero digit'],
            'frame': 'Observed push rbp/r15/r14/r12/rbx and reverse pops; caller buffer/table/code/save/return regions must be separated and valid',
            'domain': 'All unsigned64 n, actual C20; initialized valid nonwrapping separated writable20-byte buffer and observed table; normal memory, no faults/unwind/concurrent mutation',
            'unqualified': ['Other capacities and guard-call semantics', 'Raw aliases/invalid pointers',
                            'Original type/ABI/compiler/bytes/runtime', 'Complete formatter/G and component gates']}


def prove_selector(body, lower, upper, prefix, listing=None):
    require(len(body) == SELECTOR_END-SELECTOR_BASE, 'Selector body is not complete235 bytes')
    require(lower == b'0123456789abcdef' and upper == b'0123456789ABCDEF' and prefix == b'0x',
            'Observed selector alphabets/prefix changed')
    rows = decode_span(body, SELECTOR_BASE)[0] if listing is None else verify_listing(listing, body, SELECTOR_BASE)
    p = _shape(body, SELECTOR_BASE, rows, SELECTOR_SCHEMA, SELECTOR_FIELDS, SELECTOR_RIP_FIELDS)
    require(p['first_mask'] == 1 << 25 and p['second_mask'] == 1 << 26,
            'Selector lowDWORD flag priority changed')
    require(p['saved_capacity'] == p['call_capacity'] == 20, 'Actual decimal caller capacity changed')
    require((p['lower_table'], p['upper_table'], p['hex_prefix']) == (LOWER_VA, UPPER_VA, PREFIX_VA),
            'Selector literal RIP binding changed')
    graph = _cfg(rows)
    require(len(graph['branches']) == 6 and graph['normal_return_sites'] == ['0x14f774a'],
            'Selector context CFG changed')
    require(graph['calls'] == [{'va': '0x14f768e', 'kind': 'direct', 'target': hex(PRIMARY_BASE)},
                               {'va': '0x14f773d', 'kind': 'RIP-slot', 'slot': '0x576e2d8'}],
            'Selector converter/opaque sink call changed')
    require(_byte_stores(rows) == [0x14F76DD, 0x14F770D], 'Selector context store sites changed')
    return {'range': [hex(SELECTOR_BASE), hex(SELECTOR_END)], 'body_sha256': sha(body),
            'instruction_rows': len(rows), 'parameters': p, 'cfg': graph,
            'flag_priority': [25, 26, 'decimal'], 'decimal_buffer_end': 20, 'hex_buffer_end': 16,
            'decimal_callee': hex(PRIMARY_BASE), 'opaque_sink_slot': '0x576e2d8',
            'decimal_arguments': 'B=selectorSP+4,C20; digit pointerB+start,length20-start; prefix raw pointerword1,length0',
            'hex_arguments': 'Relative to the SAME B=SP+4: span[16-k,16),k1..16; prefix literal0x,length2; no physical rendering claim',
            'opaque_result': 'Normal sink low byte forwarded unchanged; sink semantics are not interpreted',
            'complete_G': False, 'Rust_hex_or_flags_implementation': False}


def derive(data):
    sections = bv.sections(data)
    def offset(va, size):
        selected = [r for r in sections.values() if r['addr'] and r['addr'] <= va
                    and va+size <= r['addr']+r['size']]
        require(len(selected) == 1, 'Selected VA range is not uniquely file-backed')
        result = selected[0]['offset']+va-selected[0]['addr']
        require(result+size <= len(data), 'Selected file range is truncated')
        return result
    def read(va, size):
        start = offset(va, size)
        return data[start:start+size]
    extents = bv.fde_extents(data, sections)
    expected = {PRIMARY_BASE: PRIMARY_END, SELECTOR_BASE: SELECTOR_END,
                0x15723B0: 0x15728BF, 0x157B64F: 0x157B68C}
    for start, end in expected.items():
        require(extents.get(start) == end, f'Selected exact FDE changed at {start:#x}')
    slots = {0x566FB18: [], 0x576E2D8: [], 0x576DFC8: []}
    relocation = sections['.rela.dyn']
    require(relocation['size'] % 24 == 0, 'Selected RELA extent is not complete')
    for pos in range(relocation['offset'], relocation['offset']+relocation['size'], 24):
        place, info, addend = struct.unpack_from('<QQq', data, pos)
        if place in slots:
            slots[place].append({'file_offset': hex(pos), 'info': info, 'addend': hex(addend),
                                 'raw': data[pos:pos+24].hex()})
    for place, target in [(0x566FB18, SELECTOR_BASE), (0x576E2D8, 0x15723B0), (0x576DFC8, 0x157B64F)]:
        rows = slots[place]
        require(len(rows) == 1 and rows[0]['info'] == 8 and int(rows[0]['addend'], 16) == target
                and read(place, 8) == bytes(8), f'Unique symbol-free RELATIVE binding changed at {place:#x}')
    require(struct.unpack('<QQQQ', read(0x566FB00, 32)) == (0, 8, 8, 0),
            'Observed descriptor words changed')
    bodies = {'primary': read(PRIMARY_BASE, PRIMARY_END-PRIMARY_BASE),
              'selector': read(SELECTOR_BASE, SELECTOR_END-SELECTOR_BASE)}
    exports, tools, native_rows = {}, {}, {}
    for name, base in [('primary', PRIMARY_BASE), ('selector', SELECTOR_BASE)]:
        rows, listing, tool = decode_span(bodies[name], base)
        native_rows[name], exports[name+'.objdump.txt'], tools[name] = rows, listing, tool
    primary = prove_primary(bodies['primary'], read(PAIR_VA, 200), exports['primary.objdump.txt'])
    selector = prove_selector(bodies['selector'], read(LOWER_VA, 16), read(UPPER_VA, 16),
                              read(PREFIX_VA, 2), exports['selector.objdump.txt'])
    unwind = {}
    hdr = sections['.eh_frame_hdr'];count = struct.unpack_from('<I', data, hdr['offset']+8)[0]
    for i in range(count):
        relative, fde_rel = struct.unpack_from('<ii', data, hdr['offset']+12+i*8)
        start = hdr['addr']+relative
        if start not in expected:
            continue
        fde = hdr['addr']+fde_rel;pos = offset(fde, 16)
        length, cie_ptr = struct.unpack_from('<II', data, pos)
        cie = fde+4-cie_ptr;cie_size = struct.unpack('<I', read(cie, 4))[0]+4
        require(hex(start) not in unwind, 'Duplicate selected FDE binding')
        unwind[hex(start)] = {'end': hex(expected[start]), 'fde_va': hex(fde),
                              'fde_raw': read(fde, length+4).hex(), 'cie_va': hex(cie),
                              'cie_raw': read(cie, cie_size).hex()}
    require(len(unwind) == 4, 'Selected unwind metadata is incomplete')
    return {'schema': 're005-capacity20-decimal-span/1', 'target_sha256': sha(data),
            'target_bytes': len(data), 'primary': primary, 'selector_context': selector,
            'metadata': {'unwind': unwind, 'relocations': {hex(k): v[0] for k, v in slots.items()},
                         'descriptor': {'va': '0x566fb00', 'raw': read(0x566FB00, 32).hex(),
                                        'words': [0, 8, 8, 0], 'nominal_type_claim': False},
                         'tables': {'pairs': {'va': hex(PAIR_VA), 'bytes': 200, 'raw': read(PAIR_VA, 200).hex()},
                                    'lower': {'va': hex(LOWER_VA), 'raw': read(LOWER_VA, 16).hex()},
                                    'upper': {'va': hex(UPPER_VA), 'raw': read(UPPER_VA, 16).hex()},
                                    'prefix': {'va': hex(PREFIX_VA), 'raw': read(PREFIX_VA, 2).hex()}},
                         'opaque_helpers': ['15723b0..15728bf:1295B, sink semantics undecoded',
                                            '157b64f..157b68c:61B, guard-callee semantics undecoded']},
            'tools': tools, 'native': exports, 'component_gates_requested': False,
            'captured_execution_or_emulation': False}


def analyze(data):
    authenticate(data)
    return derive(data)


def generate(binary, output):
    binary, output = Path(binary), Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Existing output is preserved before any target read')
    data = binary.read_bytes()
    record = analyze(data)
    output.mkdir(parents=True, exist_ok=False)
    native = record.pop('native')
    for name, text in native.items():
        with (output/name).open('x') as stream:
            stream.write(text)
    with (output/'records.json').open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True, indent=2)+'\n')
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = generate(args.binary, args.output)
    print(json.dumps({'target': result['target_sha256'], 'primary_bytes': 444,
                      'primary_rows': result['primary']['instruction_rows'],
                      'separate_selector_rows': result['selector_context']['instruction_rows']}))


if __name__ == '__main__':
    main()
