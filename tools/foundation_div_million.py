#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 divide-by-one-million evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The call target is out of scope: this packet claims only the caller window.
"""
import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x55243d0, 0x55243f6
PAD_END = 0x5524400
BODY = bytes.fromhex(
    'f30f1efa4883ec08e8236700004883c40848badb34b6d782de1b43'
    '48f7e24889d048c1e812c3')
PAD = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('140000003c992c00789557042600000000480e10490e0800')
FDE_SECTION_OFFSET = 0x2c9938
CALL_SITE = 0x55243d8
CALLEE, CALLEE_END = 0x552ab00, 0x552ab6e
SLOT = 0x5788170
MAGIC = 0x431bde82d7b634db
DIVISOR = 1000000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def div_million(x):
    """The window's rule: (x * MAGIC) >> 82, where MAGIC = ceil(2**82 / 10**6).

    The multiply is the window's 128-bit `mul rdx` (high half in rdx, then
    `shr rax, 0x12`), so the total shift is 64 + 18 = 82. Because MAGIC is
    the ceiling of 2**82 / 10**6, the over-approximation per input is below
    2**-18, which keeps the floor exact for every x below 2**64.
    """
    require(0 <= x < (1 << 64), 'Input outside u64')
    return (x * MAGIC) >> 82


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
    require(body == BODY, 'Divide-by-million instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_SECTION_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_SECTION_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    require(rels.get(SLOT) == (8, START), 'Incoming slot relocation changed')
    window_slots = [a for a, (info, addend) in rels.items() if info == 8 and addend == START]
    require(window_slots == [SLOT], 'Slot set mapping to window changed')
    # Call edges: the window calls its callee once, at CALL_SITE; no direct
    # e8 call reaches the window, and no ff15/ff25 site targets its slot.
    rel32 = struct.unpack_from('<i', body, 9)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Call target changed')
    require(body[19:27] == MAGIC.to_bytes(8, 'little'), 'Division magic changed')
    require(body[36] == 0x12, 'Division shift changed')
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct, indirect = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == START and opcode == b'\xe8':
                    direct.append(text['address'] + pos)
                elif opcode != b'\xe8' and destination == SLOT:
                    indirect.append(text['address'] + pos)
            pos += 1
    require(direct == [], 'Unexpected direct caller of window')
    require(indirect == [], 'Unexpected slot call site')
    # Division edges computed from the decoded formula, not assumed.
    edges = {x: div_million(x) for x in
             (0, 1, 999999, 1000000, 1000001, 1999999, 2000000, 123456789,
              (1 << 63) - 1, (1 << 64) - 1)}
    require(all(v == k // DIVISOR for k, v in edges.items()), 'Division edge changed')
    rng = random.Random(0x55243d0)
    sample = [rng.randrange(1 << 64) for _ in range(5000)]
    require(all(div_million(x) == x // DIVISOR for x in sample),
            'Division rule failed on sampled inputs')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2c9938',
                              padding_bytes=10, padding_stride_end=hex(PAD_END),
                              inferred_label='divide-by-one-million helper'),
                arithmetic=dict(input='u64 callee return in rax',
                                magic=hex(MAGIC), shift=82, divisor=DIVISOR,
                                formula='(x * 0x431bde82d7b634db) >> 82 (128-bit multiply, high half, then shr 0x12)',
                                magic_identity='0x431bde82d7b634db == ceil(2**82 / 1000000)',
                                edges={str(k): v for k, v in edges.items()},
                                checked_sample=5000),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=CALLEE_END - CALLEE,
                          target_claimed_here=False),
                incoming=dict(direct_e8_callers=[], relocation_slot=hex(SLOT), slot_type='R_X86_64_RELATIVE',
                              ff15_ff25_slot_call_sites=[], complete_xref_census=False),
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
        print('Foundation divide-by-million evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
