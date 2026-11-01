#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 TLS-table-index evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The slow-path initializer callee is out of scope: this packet claims only the
caller window and its index formula.
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
START, END = 0x54f3190, 0x54f31f2
PAD_END = 0x54f3200
BODY = bytes.fromhex(
    '534889fb48c7c760efffff6480bf3003000000753b488b15c4744a0031c04881fb001000007420b8010000004881fb0110000074128b4a088d4302be000000004839cb480f44c6488b44c2185bc366906448033c250000000031f6e870750600ebb3')
PAD = b'\xcc' * 14
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1c000000f4402c0080db54046200000000410e108302024c0a0e08430b000000')
FDE_SECTION_OFFSET = 0x2c40f0
CALLER_FDE = bytes.fromhex(
    '4800000014412c00d0db5404c002000000460e108f02490e188e03450e208d04450e288c05440e308606470e388307470e5002700a0e38430e30410e28420e20420e18420e10420e08490b00')
CALLER_FDE_SECTION_OFFSET = 0x2c4110
CALLER_START, CALLER_END = 0x54f3200, 0x54f34c0
CALL_SITE = 0x54f31eb
CALLEE, CALLEE_END = 0x555a760, 0x555aa22
CALLERS = [
    '0x54f32b4',
    '0x54f3574',
    '0x54f3834',
    '0x54f3af4',
    '0x54f3db4',
    '0x54f4084',
    '0x54f4354',
    '0x54f4624',
    '0x54f48f4',
    '0x54f4bc4',
    '0x54f4e94',
    '0x54f5154',
    '0x54f5414',
    '0x54f56d4',
    '0x54f5994',
    '0x54f5c54',
    '0x54f5f14',
    '0x54f61d4',
    '0x54f6494',
    '0x54f6754',
    '0x54f6a14',
    '0x54f6cd4',
    '0x54f6f94',
    '0x54f71f4',
    '0x54f74b4',
    '0x54f7774',
    '0x54f7a34',
    '0x54f7cf4',
    '0x54f7f54',
    '0x54f8214',
    '0x54f84d4',
    '0x54f8794',
    '0x54f8a54',
    '0x54f8cb4',
    '0x54f8f74',
    '0x54f9234',
    '0x54f94f4',
    '0x54f97b4',
    '0x54f9a14',
    '0x54f9cd4',
    '0x54f9f94',
    '0x54fa254',
    '0x54fa514',
    '0x54fa774',
    '0x54faa34',
    '0x54facf4',
    '0x54fafb4',
    '0x54fb274',
    '0x54fb4d4',
    '0x54fb794',
    '0x54fba54',
    '0x54fbd14',
    '0x54fbfd4',
    '0x54fc234',
    '0x54fc4f4',
    '0x54fc7b4',
    '0x54fca74',
    '0x54fcd34',
    '0x54fcf94',
    '0x54fd254',
    '0x54fd514',
    '0x54fd7d4',
    '0x54fda94',
    '0x54fdcf4',
    '0x54fdfb4',
    '0x54fe274',
    '0x54fe534',
    '0x54fe7f4',
    '0x54fea54',
    '0x54fed14',
    '0x54fefd4',
    '0x54ff294',
    '0x54ff554',
    '0x54ff7b4',
    '0x54ffa74',
    '0x54ffd34',
    '0x54ffff4',
    '0x55002b4',
    '0x5500514',
    '0x55007d4',
    '0x5500a94',
    '0x5500d54',
    '0x5501014',
    '0x55012e4',
    '0x55015b4',
    '0x5501884',
    '0x5501b54',
    '0x5501e24',
    '0x55020f4',
    '0x55023c4',
    '0x5502694',
    '0x5502964',
    '0x5502c35',
    '0x5502ed4',
    '0x55031a4',
    '0x5503474',
    '0x5503744',
    '0x5503a14',
    '0x5503ce4',
    '0x5503fb4',
    '0x5504284',
    '0x5504554',
    '0x5504824',
    '0x5504af4',
    '0x5504dc4',
    '0x5505094',
    '0x5505364',
    '0x5505634',
    '0x55058f4',
    '0x5505bb4',
    '0x5505e74',
    '0x5506134',
    '0x55063f4',
    '0x55066b4',
    '0x5506974',
    '0x5506c34',
    '0x5506ef4',
    '0x55071b4',
    '0x5507474',
    '0x5507734',
    '0x55079f4',
    '0x5507cb4',
    '0x5507f74',
    '0x5508234',
    '0x55084f4',
    '0x55087b4',
    '0x5508a74',
    '0x5508d34',
    '0x5508ff4',
    '0x55092b4',
    '0x5509574',
    '0x5509834',
    '0x5509af4',
    '0x5509db4',
    '0x550a074',
    '0x550a334',
    '0x550a5f4',
    '0x550a8b4',
    '0x550ab74',
    '0x550ae34',
    '0x550b0f4',
    '0x550b3b4',
    '0x550b5e3',
    '0x550b744',
    '0x550ba04',
    '0x550bcc4',
    '0x550bf84',
    '0x550c244',
    '0x550c504',
    '0x550c7c4',
    '0x550ca84',
    '0x550cd44',
    '0x550d004',
    '0x550d2c4',
    '0x550d584',
    '0x550d844',
    '0x550db04',
    '0x550ddc4',
    '0x550e084',
    '0x550e344',
    '0x550e604',
    '0x550e8c4',
    '0x550eb84',
    '0x550ee44',
    '0x550f104',
    '0x550f3c4',
    '0x550f684',
    '0x550f944',
    '0x550fc24',
    '0x550ff04',
    '0x55101c4',
    '0x551279c',
    '0x55134cb',
    '0x5513508'
]
TABLE_VA = 0x599a670


def require(condition, message):
    if not condition:
        raise ValueError(message)


def index_of(rbx, table1):
    """The window's table-index formula over a u64 input.

    0x1000 maps to entry 0, 0x1001 maps to entry 1, an input equal to the
    zero-extended low 32 bits of the table's second qword maps to entry 0
    (the window loads it with a 32-bit mov, so the qword's high 32 bits play
    no role), and every other input maps to input + 2 (mod 2**64). The two
    constant sentinels and the table-driven sentinel are read from the window
    bytes; the general case is the `lea eax, [rbx + 2]` step.
    """
    require(0 <= rbx < (1 << 64), 'Input outside u64')
    require(0 <= table1 < (1 << 64), 'Table sentinel outside u64')
    if rbx == 0x1000:
        return 0
    if rbx == 0x1001:
        return 1
    if rbx == (table1 & 0xFFFFFFFF):
        return 0
    return (rbx + 2) % (1 << 64)


def entry_addr(table_base, index):
    """The window's entry load address: base + 0x18 + index * 8."""
    require(0 <= table_base < (1 << 64), 'Table base outside u64')
    return (table_base + 0x18 + index * 8) % (1 << 64)


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
    require(body == BODY, 'TLS-table-index instruction window changed')
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
    require(bytes.fromhex('48c7c760efffff') in body, 'TLS offset immediate changed')
    require(struct.unpack_from('<i', body, 7)[0] == -0x10a0, 'TLS offset value changed')
    require(bytes.fromhex('6480bf3003000000') in body, 'TLS flag check changed')
    require(_find_once(body, bytes.fromhex('4881fb00100000'), 'Sentinel 0x1000') >= 0, 'Sentinel 0x1000 changed')
    require(_find_once(body, bytes.fromhex('4881fb01100000'), 'Sentinel 0x1001') >= 0, 'Sentinel 0x1001 changed')
    require(_find_once(body, bytes.fromhex('8d4302'), 'Plus-two step') >= 0, 'Plus-two step changed')
    require(_find_once(body, bytes.fromhex('488b44c218'), 'Indexed load') >= 0, 'Indexed load changed')
    lea = _find_once(body, bytes.fromhex('488b15'), 'Table load')
    disp = struct.unpack_from('<i', body, lea + 3)[0]
    require(START + lea + 7 + disp == TABLE_VA, 'Table address changed')
    rel32 = struct.unpack_from('<i', body, CALL_SITE - START + 1)[0]
    require(CALL_SITE + 5 + rel32 == CALLEE, 'Slow-path call target changed')
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
    require(read(int(CALLERS[0], 16), 5) == bytes.fromhex('e8d7feffff'), 'First caller call bytes changed')
    # Index formula edges computed from the decoded rule, not assumed.
    table1 = 0x1234
    index_edges = {k: index_of(k, table1) for k in (0x1000, 0x1001, table1, 0, 5, 0x1002, table1 + 1, (1 << 64) - 1)}
    require(index_edges == {0x1000: 0, 0x1001: 1, table1: 0, 0: 2, 5: 7, 0x1002: 0x1004,
                            table1 + 1: table1 + 3, (1 << 64) - 1: 1},
            'Index edges changed')
    addr_edges = {i: entry_addr(TABLE_VA, i) for i in (0, 1, 7)}
    require(addr_edges == {0: TABLE_VA + 0x18, 1: TABLE_VA + 0x20, 7: TABLE_VA + 0x50},
            'Entry address edges changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2c40f0',
                              padding_bytes=14, padding_stride_end=hex(PAD_END),
                              inferred_label='tls-table-index helper'),
                index=dict(input='u64 input in rbx, table sentinel qword at [table + 8]',
                           sentinels={'0x1000': 0, '0x1001': 1, 'table1': 0},
                           general='input + 2 (mod 2**64)',
                           formula='index = 0 if input in {0x1000, low32(table1)}; 1 if input == 0x1001; else input + 2',
                           entry_formula='table_base + 0x18 + index * 8',
                           table_va=hex(TABLE_VA),
                           index_edges={hex(k): v for k, v in index_edges.items()},
                           entry_edges={str(k): hex(v) for k, v in addr_edges.items()}),
                call=dict(site=hex(CALL_SITE), target=hex(CALLEE), target_bytes=CALLEE_END - CALLEE,
                          target_claimed_here=False),
                tls=dict(flag='fs byte at TLS offset, init-done flag; zero routes to slow path',
                         slow_path_target=hex(CALLEE)),
                incoming=dict(direct_e8_callers=CALLERS,
                              validated_caller_fdes=['0x54f3200'],
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
        print('Foundation TLS-table-index evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
