#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 cached-pointer-refresh evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The shared callee is out of scope: this packet claims only the caller window
and its two stores (a cached pointer and a self-reference flag) over the
callee result and the input struct's link field.
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
START, END = 0x5172e20, 0x5172e49
PAD_END = 0x5172e50
BODY = bytes.fromhex(
    'f30f1efa534889fb488b7f08e8cffcffff48894320488b4308488d5018483950180f95c08843285bc3')
PAD = b'\xcc' * 7
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('18000000f4c4290010541f042900000000450e108302630e08000000')
FDE_SECTION_OFFSET = 0x29c4f0
CALLER_FDE = bytes.fromhex(
    '300000007cc62900f85e1f04b900000000460e108c02440e188603440e208304470e3002880a0e20410e18410e10420e08470b00')
CALLER_FDE_SECTION_OFFSET = 0x29c678
CALLER_START, CALLER_END = 0x5173a90, 0x5173b49
CALL_SITE = 0x5172e2c
CALLEE, CALLEE_END = 0x5172b00, 0x5172c01
CALLERS = [
    '0x5173afd',
    '0x5173b8e',
    '0x5173f15',
    '0x5173f9f',
    '0x5174190',
    '0x5175e42',
    '0x5175f8f',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def apply_rule(callee_result, second, link):
    """The window's two stores over the callee result and the link field.

    The callee is called with the input struct's second field (qword at
    +0x08); its result is stored verbatim at +0x20. The link field at
    +0x18 is then compared against its own address (second + 0x18, mod
    2**64): the flag at +0x28 is 1 iff the link differs from its own
    address, 0 iff the link is self-referential. The window claims no
    meaningful return value: after setne, rax still carries the high
    bytes of the second-field pointer, so only the two stores are the
    window's outputs.
    """
    require(0 <= callee_result < (1 << 64), 'Callee result outside u64')
    require(0 <= second < (1 << 64), 'Second field outside u64')
    require(0 <= link < (1 << 64), 'Link field outside u64')
    link_addr = (second + 0x18) % (1 << 64)
    return callee_result, 0 if link == link_addr else 1


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
    require(body == BODY, 'Cached-pointer-refresh instruction window changed')
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
    require(_find_once(body, bytes.fromhex('f30f1efa'), 'Entry endbr64') >= 0, 'Entry endbr64 changed')
    require(_find_once(body, bytes.fromhex('4889fb'), 'Input save') >= 0, 'Input save changed')
    require(_find_once(body, bytes.fromhex('488b7f08'), 'Callee argument') >= 0, 'Callee argument changed')
    rel32 = struct.unpack_from('<i', body, CALL_SITE - START + 1)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Shared-callee call target changed')
    require(_find_once(body, bytes.fromhex('48894320'), 'Cache store') >= 0, 'Cache store changed')
    require(_find_once(body, bytes.fromhex('488b4308'), 'Second-field reload') >= 0, 'Second-field reload changed')
    require(_find_once(body, bytes.fromhex('488d5018'), 'Link address') >= 0, 'Link address changed')
    require(_find_once(body, bytes.fromhex('48395018'), 'Link compare') >= 0, 'Link compare changed')
    require(_find_once(body, bytes.fromhex('0f95c0'), 'Set-not-equal') >= 0, 'Set-not-equal changed')
    require(_find_once(body, bytes.fromhex('884328'), 'Flag store') >= 0, 'Flag store changed')
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
    require(read(int(CALLERS[0], 16), 5) == bytes.fromhex('e81ef3ffff'), 'First caller call bytes changed')
    # Rule edges computed from the decoded rule, not assumed.
    edges = [
        {'callee_result': hex(0), 'second': hex(0x1000), 'link': hex(0x1018), 'cache': hex(0), 'flag': 0},
        {'callee_result': hex(0x1234), 'second': hex(0x1000), 'link': hex(0x2000), 'cache': hex(0x1234), 'flag': 1},
        {'callee_result': hex((1 << 64) - 1), 'second': hex(0x1000), 'link': hex(0), 'cache': hex((1 << 64) - 1), 'flag': 1},
        {'callee_result': hex(0), 'second': hex(0), 'link': hex(0x18), 'cache': hex(0), 'flag': 0},
        {'callee_result': hex(0xabcd), 'second': hex((1 << 64) - 0x18), 'link': hex(0), 'cache': hex(0xabcd), 'flag': 0},
        {'callee_result': hex(0), 'second': hex(0x5000), 'link': hex(0x5017), 'cache': hex(0), 'flag': 1},
        {'callee_result': hex(0), 'second': hex(0x5000), 'link': hex(0x5019), 'cache': hex(0), 'flag': 1},
        {'callee_result': hex(0xdeadbeef), 'second': hex(0x5000), 'link': hex(0x5018), 'cache': hex(0xdeadbeef), 'flag': 0},
    ]
    for edge in edges:
        cache, flag = apply_rule(int(edge['callee_result'], 16), int(edge['second'], 16), int(edge['link'], 16))
        require((hex(cache), flag) == (edge['cache'], edge['flag']), 'Rule edge changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x29c4f0',
                              padding_bytes=7, padding_stride_end=hex(PAD_END),
                              inferred_label='cached-pointer-refresh helper'),
                rule=dict(inputs='callee result rax (u64, from call to 0x5172b00 with the input second field), second field (u64 at input + 0x08), link field (u64 at second + 0x18)',
                          cache='callee result stored verbatim at input + 0x20',
                          flag='byte at input + 0x28 is 1 iff link != (second + 0x18) mod 2**64, else 0 (self-referential link)',
                          formula='cache = callee_result; flag = 0 if link == (second + 0x18) mod 2**64 else 1',
                          return_caveat='no meaningful return value is claimed: after setne, rax still carries the high bytes of the second-field pointer, so only the two stores are the window outputs',
                          edges=edges),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=CALLEE_END - CALLEE,
                          target_claimed_here=False),
                incoming=dict(direct_e8_callers=CALLERS,
                              validated_caller_fdes=['0x5173a90'],
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
        print('Foundation cached-pointer-refresh evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
