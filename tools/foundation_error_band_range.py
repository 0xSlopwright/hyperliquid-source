#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 error-band range-check evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The shared callee is out of scope: this packet claims only the caller window
and its return rule over the callee result and the post-call rdx.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x555e870, 0x555e898
PAD_END = 0x555e8a0
BODY = bytes.fromhex(
    '4883ec08e8f7fdffff4889c131c04883f988770f39d67c0b48c1fa2031c039d60f9ec04883c408c3')
PAD = b'\xcc' * 8
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('14000000dcfd2c0078d55a042800000000440e10630e0800')
FDE_SECTION_OFFSET = 0x2cfdd8
CALLER_FDE = bytes.fromhex(
    '18000000f4fd2c0090d55a04fc05000000480e1002430a0e08450b00')
CALLER_FDE_SECTION_OFFSET = 0x2cfdf0
CALLER_START, CALLER_END = 0x555e8a0, 0x555ee9c
CALL_SITE = 0x555e874
CALLEE, CALLEE_END = 0x555e670, 0x555e869
CALLERS = [
    '0x555e938',
    '0x555e978',
    '0x555e9a0',
    '0x555e9c8',
    '0x555ea30',
    '0x555eaa8',
    '0x555ead5',
    '0x555eb05',
    '0x555eb48',
    '0x555eb70',
    '0x555eb98',
    '0x555ebc0',
    '0x555ec3c',
    '0x555ec62',
    '0x555ec88',
    '0x555ecae',
    '0x555ecd4',
    '0x555ecf5',
    '0x555ed1b',
    '0x555ed51',
    '0x555ed72',
    '0x555ed98',
    '0x555edbe',
    '0x555ee10',
    '0x555ee32',
    '0x555ee57',
]
BAND_LIMIT = (1 << 64) - 120


def require(condition, message):
    if not condition:
        raise ValueError(message)


def s32(value):
    """Interpret a 32-bit word as signed."""
    return value - (1 << 32) if value & 0x80000000 else value


def check_result(callee_result, esi, rdx_post):
    """The window's return rule over the callee result and post-call rdx.

    The band gate is an unsigned compare against -0x78: `ja` is taken only
    when the callee result is strictly above 2**64 - 120, so the rejected
    band is signed [-119, -1] and the value -120 itself passes. The range
    gate then requires low32(rdx) <= esi <= high32(rdx), both signed. rdx
    is read after the call, so the bounds are the callee's post-call rdx;
    the callee's rdx behavior is not closed here.
    """
    require(0 <= callee_result < (1 << 64), 'Callee result outside u64')
    require(-(1 << 31) <= esi < (1 << 31), 'Input outside i32')
    require(0 <= rdx_post < (1 << 64), 'Post-call rdx outside u64')
    if callee_result > BAND_LIMIT:
        return 0
    if esi < s32(rdx_post & 0xFFFFFFFF):
        return 0
    return 1 if esi <= s32((rdx_post >> 32) & 0xFFFFFFFF) else 0


def _find_once(body, pattern, label):
    positions = []
    start = 0
    while True:
        pos = body.find(pattern, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
    require(len(positions) == 1, '%s pattern count changed' % label)
    return positions[0]


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Error-band range-check instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(FDE_SECTION_OFFSET, FDE, START, END),
                                    (CALLER_FDE_SECTION_OFFSET, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # The window's own constants and edges.
    require(_find_once(body, bytes.fromhex('4883ec08'), 'Stack prologue') >= 0, 'Stack prologue changed')
    rel32 = struct.unpack_from('<i', body, CALL_SITE - START + 1)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Shared-callee call target changed')
    band_imm = struct.unpack_from('<b', body, 0x11)[0]
    require(band_imm == -120, 'Band immediate changed')
    ja = _find_once(body, bytes.fromhex('770f'), 'Band branch')
    require(0x555e882 + 2 + struct.unpack_from('<b', body, ja + 1)[0] == 0x555e893, 'Band branch target changed')
    jl = _find_once(body, bytes.fromhex('7c0b'), 'Low-bound branch')
    require(0x555e886 + 2 + struct.unpack_from('<b', body, jl + 1)[0] == 0x555e893, 'Low-bound branch target changed')
    require(_find_once(body, bytes.fromhex('48c1fa20'), 'High-half shift') >= 0, 'High-half shift changed')
    require(_find_once(body, bytes.fromhex('0f9ec0'), 'Set-less-or-equal') >= 0, 'Set-less-or-equal changed')
    # Incoming call edges: raw direct e8 scan, byte-exact list.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while True:
        pos = code.find(b'\xe8', pos)
        if pos < 0:
            break
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == [int(s, 16) for s in CALLERS], 'Call-pattern candidate set changed')
    require(read(int(CALLERS[0], 16), 5) == bytes.fromhex('e833ffffff'), 'First caller call bytes changed')
    # Rule edges computed from the decoded rule, not assumed.
    edges = [
        {'callee_result': hex((1 << 64) - 120), 'esi': 0, 'rdx_post': hex(0), 'result': 1},
        {'callee_result': hex((1 << 64) - 119), 'esi': 0, 'rdx_post': hex(0), 'result': 0},
        {'callee_result': hex((1 << 64) - 1), 'esi': 0, 'rdx_post': hex(0), 'result': 0},
        {'callee_result': hex(0), 'esi': 0, 'rdx_post': hex(0), 'result': 1},
        {'callee_result': hex((1 << 64) - 121), 'esi': 0, 'rdx_post': hex(0), 'result': 1},
        {'callee_result': hex(0), 'esi': 3, 'rdx_post': hex((5 << 32) | 3), 'result': 1},
        {'callee_result': hex(0), 'esi': 2, 'rdx_post': hex((5 << 32) | 3), 'result': 0},
        {'callee_result': hex(0), 'esi': 5, 'rdx_post': hex((5 << 32) | 3), 'result': 1},
        {'callee_result': hex(0), 'esi': 6, 'rdx_post': hex((5 << 32) | 3), 'result': 0},
        {'callee_result': hex(0), 'esi': -5, 'rdx_post': hex((10 << 32) | 0xFFFFFFFB), 'result': 1},
        {'callee_result': hex(0), 'esi': -6, 'rdx_post': hex((10 << 32) | 0xFFFFFFFB), 'result': 0},
        {'callee_result': hex(0), 'esi': 10, 'rdx_post': hex((10 << 32) | 0xFFFFFFFB), 'result': 1},
        {'callee_result': hex(0), 'esi': 11, 'rdx_post': hex((10 << 32) | 0xFFFFFFFB), 'result': 0},
        {'callee_result': hex((1 << 64) - 1), 'esi': 3, 'rdx_post': hex((5 << 32) | 3), 'result': 0},
    ]
    for edge in edges:
        require(check_result(int(edge['callee_result'], 16), edge['esi'],
                             int(edge['rdx_post'], 16)) == edge['result'],
                'Rule edge changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2cfdd8',
                              padding_bytes=8, padding_stride_end=hex(PAD_END),
                              inferred_label='error-band range-check helper'),
                rule=dict(inputs='callee result rcx (u64, from call to 0x555e670), esi (i32), rdx as observed after the call (u64; low32 and high32 as i32)',
                          band='callee result unsigned greater than 2**64 - 120 returns 0; that band is signed [-119, -1] (the value -120 itself compares equal and does not take the unsigned-above branch)',
                          range='esi must satisfy low32(rdx) <= esi <= high32(rdx), both bounds signed i32',
                          formula='return 1 iff rcx <= 2**64 - 120 (unsigned) and low32(rdx) <= esi <= high32(rdx) (signed); else 0',
                          rdx_caveat="rdx is read after the call, so the range bounds are the callee's post-call rdx; the callee's rdx behavior is not closed here",
                          edges=edges),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=CALLEE_END - CALLEE,
                          target_claimed_here=False),
                incoming=dict(direct_e8_callers=CALLERS,
                              validated_caller_fdes=['0x555e8a0'],
                              complete_xref_census=False),
                captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation error-band range-check evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
