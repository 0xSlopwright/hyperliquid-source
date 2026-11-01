#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 min-cap gap-check evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The shared callee is out of scope: this packet claims only the caller window
and its return rule (a min-capped callee equality gate, an i32-range guard,
and a gap-zero test) over the callee result and the second-field gap.
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
START, END = 0x5430db0, 0x5430e07
BODY = bytes.fromhex(
    'f30f1efa55534883ec08488b6e08488b5f084839dd480f46dd4885db7416488b36488b3f4889da'
    'e874f3220089c231c085d2751c4829eb31c04881fbffffff7f7f0e4881fb000000807c0585db0f94c0'
    '4883c4085b5dc3')
# No int3 padding follows this window: the neighbor window starts immediately.
NEIGHBOR_START = bytes.fromhex('bf100000')
NEIGHBOR_TAIL_INT3 = b'\xcc' * 4
NEIGHBOR_TAIL = 0x5430e4c
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
CALLER_CIE_OFFSET = 0x6205d0
FDE = bytes.fromhex('2400000078ae2b001c4a49045700000000450e108602410e188303440e20024a0e18410e10410e08')
FDE_SECTION_OFFSET = 0x2bae74
CALLER_FDE = bytes.fromhex(
    '5000000060dc010064ddf00383040000042ae38bff460e108f02450e188e03420e208d04420e288c054b0e308606440e388307470ef00103cb020a0e38410e30410e28420e20420e18420e10420e08460b000000')
CALLER_FDE_SECTION_OFFSET = 0x63e22c
CALLER_START, CALLER_END = 0x522d4b0, 0x522d933
CALL_SITE = 0x5430dd7
CALLEE = 0x5660150
CALLERS = [
    '0x522d600',
    '0x52464c1',
    '0x52fa39e',
    '0x531c27c',
    '0x531f8f9',
    '0x53218ee',
    '0x54265c8',
    '0x5426ebd',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def apply_rule(a_second, b_second, callee_result):
    """The window's raw return rule over the second fields and callee result.

    min is the unsigned min of the two second fields. A zero min skips the
    callee call, so the callee result is meaningless on that path. Otherwise
    a nonzero callee result rejects. The gap (min - b_second, mod 2**64)
    must then lie in the signed i32 range and have zero low 32 bits.
    """
    require(0 <= a_second < (1 << 64), 'First second field outside u64')
    require(0 <= b_second < (1 << 64), 'Second second field outside u64')
    require(0 <= callee_result < (1 << 32), 'Callee result outside u32')
    cap = a_second if a_second < b_second else b_second
    if cap != 0 and callee_result != 0:
        return 0
    gap = (cap - b_second) % (1 << 64)
    signed = gap if gap < (1 << 63) else gap - (1 << 64)
    if signed < -(1 << 31) or signed > (1 << 31) - 1:
        return 0
    return 1 if gap % (1 << 32) == 0 else 0


def derived_rule(a_second, b_second, callee_result):
    """The simplified form: b_second covered and (zero length or callee pass)."""
    return 1 if b_second <= a_second and (b_second == 0 or callee_result == 0) else 0


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
    require(body == BODY, 'Min-cap-gap instruction window changed')
    require(read(END, 4) == NEIGHBOR_START, 'Neighbor window no longer starts immediately after this window')
    require(read(NEIGHBOR_TAIL, 4) == NEIGHBOR_TAIL_INT3, 'Int3 run after neighbor window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'Window CIE changed')
    require(read(eh['address'] + CALLER_CIE_OFFSET, len(CALLER_CIE)) == CALLER_CIE, 'Caller CIE changed')
    for offset, raw, start, end in [(FDE_SECTION_OFFSET, FDE, START, END),
                                    (CALLER_FDE_SECTION_OFFSET, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # The window's own constants and edges.
    require(_find_once(body, bytes.fromhex('f30f1efa'), 'Entry endbr64') >= 0, 'Entry endbr64 changed')
    require(_find_once(body, bytes.fromhex('480f46dd'), 'Min-cap cmovbe') >= 0, 'Min-cap cmovbe changed')
    require(_find_once(body, bytes.fromhex('7416'), 'Min-zero skip') >= 0, 'Min-zero skip changed')
    rel32 = struct.unpack_from('<i', body, CALL_SITE - START + 1)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Shared-callee call target changed')
    require(_find_once(body, bytes.fromhex('85d2'), 'Callee equality test') >= 0, 'Callee equality test changed')
    require(_find_once(body, bytes.fromhex('751c'), 'Callee reject branch') >= 0, 'Callee reject branch changed')
    require(_find_once(body, bytes.fromhex('4829eb'), 'Gap subtraction') >= 0, 'Gap subtraction changed')
    require(_find_once(body, bytes.fromhex('4881fbffffff7f'), 'Upper range bound') >= 0, 'Upper range bound changed')
    require(_find_once(body, bytes.fromhex('4881fb00000080'), 'Lower range bound') >= 0, 'Lower range bound changed')
    require(_find_once(body, bytes.fromhex('0f94c0'), 'Gap-zero sete') >= 0, 'Gap-zero sete changed')
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
    require(read(int(CALLERS[0], 16), 5) == bytes.fromhex('e8ab372000'), 'First caller call bytes changed')
    # Rule edges computed from the decoded rule, not assumed.
    edges = [
        {'a_second': hex(0x5), 'b_second': hex(0x0), 'callee_result': 12345, 'note': 'min == 0 skips the callee gate entirely; callee_result is meaningless here', 'result': 1},
        {'a_second': hex(0xa), 'b_second': hex(0x7), 'callee_result': 0, 'note': 'b_second <= a_second, callee == 0, gap 0', 'result': 1},
        {'a_second': hex(0xa), 'b_second': hex(0x7), 'callee_result': 5, 'note': 'callee != 0 rejects', 'result': 0},
        {'a_second': hex(0x7), 'b_second': hex(0xa), 'callee_result': 0, 'note': 'b_second > a_second, gap -3 in range but low32 != 0', 'result': 0},
        {'a_second': hex(0x7), 'b_second': hex(0xa), 'callee_result': 9, 'note': 'b_second > a_second and callee != 0', 'result': 0},
        {'a_second': hex(0x0), 'b_second': hex(0x100000000), 'callee_result': 0, 'note': 'trap: min == 0 path, gap -2**32 has low32 == 0 but is out of the i32 range, so the range guard rejects', 'result': 0},
        {'a_second': hex(0x3), 'b_second': hex(0x100000003), 'callee_result': 0, 'note': 'trap: callee == 0 but gap -2**32 is out of range despite low32 == 0', 'result': 0},
        {'a_second': hex(0x5), 'b_second': hex(0x80000005), 'callee_result': 0, 'note': 'boundary: gap -2**31 is in range but low32 0x80000000 != 0', 'result': 0},
        {'a_second': hex(0x2a), 'b_second': hex(0x2a), 'callee_result': 0, 'note': 'equal seconds, callee == 0, gap 0', 'result': 1},
        {'a_second': hex(0x2a), 'b_second': hex(0x2a), 'callee_result': 1, 'note': 'equal seconds, callee != 0', 'result': 0},
        {'a_second': hex((1 << 64) - 1), 'b_second': hex((1 << 64) - 1), 'callee_result': 0, 'note': 'max values, equal, callee == 0', 'result': 1},
        {'a_second': hex((1 << 64) - 1), 'b_second': hex((1 << 64) - 2), 'callee_result': 0, 'note': 'b_second <= a_second at the top of the range, gap 0', 'result': 1},
        {'a_second': hex(0x1), 'b_second': hex((1 << 64) - 1), 'callee_result': 0, 'note': 'mod-arithmetic edge: gap mod 2**64 is 2, in range but nonzero', 'result': 0},
    ]
    for edge in edges:
        got = apply_rule(int(edge['a_second'], 16), int(edge['b_second'], 16), edge['callee_result'])
        require(got == edge['result'], 'Rule edge changed')
        require(derived_rule(int(edge['a_second'], 16), int(edge['b_second'], 16), edge['callee_result']) == edge['result'],
                'Derived form disagrees with raw rule')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2bae74',
                              padding_bytes=0,
                              padding_note='no int3 padding follows this window: the next FDE begins immediately at 0x5430e07 (a 69-byte neighbor window, excluded here), and the 4 int3 bytes at [0x5430e4c, 0x5430e50) belong after that neighbor, not after this window',
                              inferred_label='min-cap gap-check helper', next_fde_start='0x5430e07', fde_cie='0x00000000'),
                rule=dict(inputs='a_first (u64 at input a + 0x00), a_second (u64 at input a + 0x08), b_first (u64 at input b + 0x00), b_second (u64 at input b + 0x08), callee_result (low 32 bits of eax from the call to 0x5660150 with (a_first, b_first, min))',
                          raw_formula='min = min_u64(a_second, b_second); if min != 0 and callee_result != 0: return 0; gap = (min - b_second) mod 2**64; return 1 iff gap_signed in [-2**31, 2**31 - 1] and low32(gap) == 0, else 0',
                          derived_formula='return 1 iff b_second <= a_second (unsigned) and (b_second == 0 or callee_result == 0); the checker verifies the raw and derived formulas agree on every edge below',
                          formula_note='gap is always <= 0 before the mod (min <= b_second), so a positive in-range gap never occurs; the range guard is only observable on negative gaps whose low 32 bits are zero (notably -2**32)',
                          edges=edges),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=None,
                          target_claimed_here=False, target_fde_start=False,
                          target_note='the callee is not an FDE start, so no body size is claimed for it; it is the shared comparator also used by the killed cmovbe family, but this window is not a family member (see README)'),
                incoming=dict(direct_e8_callers=CALLERS,
                              validated_caller_fdes=['0x522d4b0'],
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
        print('Foundation min-cap-gap evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
