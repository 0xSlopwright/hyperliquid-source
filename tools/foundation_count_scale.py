#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 scaled-count evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The call target is out of scope: this packet claims only the caller window.
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
START, END = 0x51c96d0, 0x51c9701
PAD_END = 0x51c9710
BODY = bytes.fromhex(
    'f30f1efa538b064889f34889f9488b7e08488d348048c1e6044801fe'
    'e80fa9ffff482b43085b48c1f80469c0cdccccccc3')
PAD = b'\xcc' * 15
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('18000000b00e2a00047324043100000000450e108302610e08000000')
FDE_SECTION_OFFSET = 0x2a0eac
CALLER_FDE = bytes.fromhex(
    '4c000000cc0e2a0028732404f405000000460e108d02420e188c03410e208604440e2883054a0ef0010384040a0e28440e20410e18420e10420e084c0b026e0a0e28410e20410e18420e10420e08440b')
CALLER_FDE_SECTION_OFFSET = 0x2a0ec8
CALLER_START, CALLER_END = 0x51c9710, 0x51c9d04
CALL_SITE = 0x51c96ec
CALLEE, CALLEE_END = 0x51c4000, 0x51c4167
CALLERS = [0x51c976d, 0x51c9d4d, 0x51ca374]
CALLER_BYTES = {
    0x51c976d: bytes.fromhex('e85effffff'),
    0x51c9d4d: bytes.fromhex('e87ef9ffff'),
    0x51ca374: bytes.fromhex('e857f3ffff'),
}
MAGIC = 0xcccccccd


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ptr_of(count, base):
    """The window's pointer computation: base + count * 80 (mod 2**64).

    count is the u32 dword at [rsi]; the lea forms [rax + rax*4] (= 5*count)
    and shifts left by 4, giving 80 * count, added to the base at [rsi + 8].
    """
    require(0 <= count < (1 << 32), 'Count outside u32')
    return (base + count * 80) % (1 << 64)


def scaled(diff):
    """The window's return for a signed 64-bit (callee_result - base).

    The window arithmetic-shifts right by 4, keeps the low 32 bits, and
    multiplies by 0xcccccccd keeping the low 32 bits. For a difference that
    is a multiple of 80, this equals the difference divided by 80 (mod 2**32):
    (80k >> 4) = 5k, and 5 * 0xcccccccd = 0x400000001 = 2**34 + 1, so
    (5k * 0xcccccccd) mod 2**32 = k mod 2**32.
    """
    shifted = (diff >> 4) & 0xFFFFFFFF
    return (shifted * MAGIC) & 0xFFFFFFFF


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
    require(body == BODY, 'Scaled-count instruction window changed')
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
    # The window's own call edge and arithmetic constants.
    rel32 = struct.unpack_from('<i', body, 29)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Call target changed')
    require(body[24] == 4, 'Stride shift changed')
    require(body[41] == 4, 'Result shift changed')
    require(struct.unpack_from('<I', body, 44)[0] == MAGIC, 'Scale magic changed')
    # Incoming call edges: exactly three direct e8 sites, byte-exact.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    for opcode in (b'\xe8',):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == START:
                    direct.append(text['address'] + pos)
            pos += 1
    require(direct == CALLERS, 'Call-pattern candidate set changed')
    for site, raw in CALLER_BYTES.items():
        require(read(site, 5) == raw, 'Caller call bytes changed')
    # Arithmetic edges computed from the decoded formula, not assumed.
    aligned = {k: scaled(80 * k) for k in (0, 1, 3, 7, 10, 255, 4096, (1 << 32) - 1)}
    require(all(v == k for k, v in aligned.items()), 'Aligned count identity changed')
    raw_edges = {d: scaled(d) for d in (1, 16, 79, 81, -80, 800)}
    require(raw_edges == {1: 0, 16: 0xcccccccd, 79: 858993460, 81: 1, -80: 0xFFFFFFFF, 800: 10},
            'Raw scaled edges changed')
    ptr_edges = {c: ptr_of(c, 0x100000) for c in (0, 1, 10, 4096)}
    require(ptr_edges == {0: 0x100000, 1: 0x100050, 10: 0x100320, 4096: 0x150000},
            'Pointer edges changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2a0eac',
                              padding_bytes=15, padding_stride_end=hex(PAD_END),
                              inferred_label='scaled-count helper'),
                arithmetic=dict(input='u32 count at [rsi], base pointer at [rsi + 8], callee result in rax',
                                stride=80, stride_formula='base + count * 80 (lea [rax + rax*4], shl 4)',
                                result_shift=4, magic=hex(MAGIC),
                                formula='low32(((callee_result - base) >> 4) * 0xcccccccd)',
                                aligned_identity='difference a multiple of 80 -> (difference / 80) mod 2**32',
                                aligned_identity_proof='5 * 0xcccccccd = 0x400000001 = 2**34 + 1',
                                aligned_edges={str(k): v for k, v in aligned.items()},
                                raw_edges={str(k): v for k, v in raw_edges.items()},
                                pointer_edges={str(k): hex(v) for k, v in ptr_edges.items()}),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=CALLEE_END - CALLEE,
                          target_claimed_here=False),
                incoming=dict(direct_e8_callers=[hex(c) for c in CALLERS],
                              validated_caller_fdes=['0x51c9710', '0x51c9d10', '0x51ca1f0'],
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
        print('Foundation scaled-count evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
