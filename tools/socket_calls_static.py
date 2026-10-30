#!/usr/bin/env python3
"""Static node #94 TCP socket-call census (socket, setsockopt, listen, accept4), checked from authenticated bytes.

Question: which socket types, socket options, listen backlogs and accept4
flags can node #94 pass to libc, and does the NodePort connect path reach a
non-blocking socket?

Only the Python standard library is used.  libc entry points are found as the
R_X86_64_GLOB_DAT/JUMP_SLOT relocations of named .dynsym symbols; every
`call [rip+slot]` in .text is counted, and the constant arguments loaded
immediately before each call are decoded from exact instruction sequences.
Relocations come from .rela.dyn.  Nothing is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
EXPECTED_CALLS = {'socket': 5, 'setsockopt': 18, 'listen': 2, 'accept4': 1, 'bind': 4, 'connect': 8}
OPTION_NAMES = {(1, 2): 'SO_REUSEADDR', (1, 7): 'SO_SNDBUF', (1, 8): 'SO_RCVBUF', (1, 9): 'SO_KEEPALIVE',
                (6, 1): 'TCP_NODELAY', (6, 4): 'TCP_KEEPIDLE', (6, 5): 'TCP_KEEPINTVL', (6, 6): 'TCP_KEEPCNT'}
SOCK_STREAM, SOCK_NONBLOCK, SOCK_CLOEXEC = 1, 0o4000, 0o2000000
CONNECT_HELPER_SLOT = 0x57737f8
CONNECT_HELPER = 0x3cd6330
NODE_PORT_CONNECTS = ((0x2037d9b, 0x20487f0), (0x43834bb, 0x439efe0))  # NodePort table site call -> future

SETSOCKOPT_ARGS = re.compile(rb'\xbe(....)\xba(....)\x41\xb8\x04\x00\x00\x00\Z', re.S)
SOCKET_ARGS = re.compile(rb'\xbe(....)(?:\xba(....)|\x31\xd2)\Z', re.S)
SOCKET_DOMAIN = re.compile(rb'(?:\xbf(....)|\x8d\x3c\xc5\x02\x00\x00\x00|\x42\x8d\x3c\xfd\x02\x00\x00\x00)', re.S)
LISTEN_ARGS = re.compile(rb'\xbe(....)\Z', re.S)
ACCEPT4_ARGS = re.compile(rb'\xb9(....)\Z', re.S)
OPTVAL_LEA = re.compile(rb'\x48\x8d(?:\x4c\x24(.)|\x8c\x24(....)|\x4d(.))', re.S)


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        by = {s['name']: s for s in self.secs if s['type'] != 8}
        for name in ('.text', '.rela.dyn', '.dynsym', '.dynstr'):
            require(name in by, f'no file-backed {name}')
        self.text = by['.text']
        rela, dynsym, dynstr = by['.rela.dyn'], by['.dynsym'], by['.dynstr']
        require(rela['size'] % 24 == 0 and dynsym['size'] % 24 == 0, 'malformed .rela.dyn/.dynsym')
        self.relative, self.named = {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            kind, sym = info & 0xffffffff, info >> 32
            if kind == 8:
                self.relative[where] = addend
            elif kind in (6, 7):
                require(sym * 24 < dynsym['size'], f'symbol index {sym} out of .dynsym')
                st_name = struct.unpack_from('<I', data, dynsym['offset'] + 24 * sym)[0]
                start = dynstr['offset'] + st_name
                name = data[start:data.index(b'\0', start)].decode()
                self.named.setdefault(name, []).append(where)
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde_of(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        require(len(hits) == 1, f'{va:#x} is not inside exactly one FDE')
        return hits[0]

    def text_bytes(self):
        t = self.text
        return t['address'], self.data[t['offset']:t['offset'] + t['size']]

    def slot_calls(self, slot):
        base, text = self.text_bytes()
        out = []
        for m in re.finditer(rb'\xff[\x15\x25]', text):
            o = m.start()
            if o + 6 <= len(text) and base + o + 6 + struct.unpack_from('<i', text, o + 2)[0] == slot:
                out.append(base + o)
        return out


def u32(raw):
    return struct.unpack('<I', raw)[0]


def libc_slot(img, name):
    slots = img.named.get(name, [])
    require(len(slots) == 1, f'{name}: {len(slots)} GLOB_DAT/JUMP_SLOT relocations')
    return slots[0]


def before(img, call, n):
    return img.read(call - n, n)


def optval(img, call, args_start):
    """Constant 4-byte store to the optval slot whose address is loaded into rcx shortly before the arguments."""
    win_lo = max(img.fde_of(call)[0], args_start - 0x30)
    win = img.read(win_lo, args_start - win_lo)
    leas = list(OPTVAL_LEA.finditer(win))
    if not leas:
        return None
    m = leas[-1]
    if m.group(3) is not None:
        disp, store = struct.unpack('<b', m.group(3))[0], rb'\xc7\x45' + re.escape(m.group(3)) + rb'(....)'
    elif m.group(1) is not None:
        disp, store = struct.unpack('<b', m.group(1))[0], rb'\xc7\x44\x24' + re.escape(m.group(1)) + rb'(....)'
    else:
        disp, store = struct.unpack('<i', m.group(2))[0], rb'\xc7\x84\x24' + re.escape(m.group(2)) + rb'(....)'
    stores = list(re.finditer(store, win[:m.start()], re.S))
    return {'optval_lea': hex(win_lo + m.start()), 'disp': disp,
            'constant': u32(stores[-1].group(1)) if stores else None,
            'constant_store': hex(win_lo + stores[-1].start()) if stores else None}


def check_setsockopt(img, call):
    m = SETSOCKOPT_ARGS.search(before(img, call, 16))
    require(m is not None, f'setsockopt {call:#x}: arguments are not mov esi,L; mov edx,O; mov r8d,4')
    level, opt = u32(m.group(1)), u32(m.group(2))
    require((level, opt) in OPTION_NAMES, f'setsockopt {call:#x}: unexpected option ({level}, {opt})')
    row = {'call': hex(call), 'fde': hex(img.fde_of(call)[0]), 'level': level, 'optname': opt,
           'option': OPTION_NAMES[(level, opt)], 'optlen': 4, 'args': hex(call - 16)}
    row['optval'] = optval(img, call, call - 16)
    return row


def check_socket(img, call):
    tail = before(img, call, 10)
    m = SOCKET_ARGS.search(tail)
    require(m is not None, f'socket {call:#x}: arguments are not mov esi,type; mov edx,proto|xor edx,edx')
    start = call - (len(tail) - m.start())
    stype = u32(m.group(1))
    proto = u32(m.group(2)) if m.group(2) else 0
    require(stype & 0xf == SOCK_STREAM and stype & ~(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC) == 0,
            f'socket {call:#x}: type {stype:#x}')
    dom = list(SOCKET_DOMAIN.finditer(img.read(start - 10, 10)))
    require(len(dom) >= 1, f'socket {call:#x}: domain not loaded immediately before')
    d = dom[-1]
    domain = u32(d.group(1)) if d.group(1) else 'flag*8+2 (AF_INET or AF_INET6)'
    require(domain in (2, 10) or isinstance(domain, str), f'socket {call:#x}: domain {domain}')
    return {'call': hex(call), 'fde': hex(img.fde_of(call)[0]), 'domain': domain, 'type': hex(stype),
            'nonblock': bool(stype & SOCK_NONBLOCK), 'cloexec': bool(stype & SOCK_CLOEXEC), 'protocol': proto}


def check_simple(img, call, rx, what):
    m = rx.search(before(img, call, 5))
    require(m is not None, f'{what} {call:#x}: constant argument not loaded immediately before')
    return {'call': hex(call), 'fde': hex(img.fde_of(call)[0]), 'value': u32(m.group(1))}


def check_connect_chain(img, socket_rows):
    require(img.relative.get(CONNECT_HELPER_SLOT) == CONNECT_HELPER, 'connect helper slot relocation changed')
    helper_fde = img.fde_of(CONNECT_HELPER)
    socks = [r for r in socket_rows if int(r['fde'], 16) == helper_fde[0]]
    conn = [c for c in img.slot_calls(libc_slot(img, 'connect')) if helper_fde[0] <= c < helper_fde[1]]
    require(len(socks) == 1 and socks[0]['nonblock'] and socks[0]['cloexec'] and len(conn) == 1,
            'connect helper is not one non-blocking socket() + one connect()')
    rows = []
    for site, fut in NODE_PORT_CONNECTS:
        require(img.read(site, 1) == b'\xe8' and site + 5 + struct.unpack('<i', img.read(site + 1, 4))[0] == fut,
                f'NodePort site call {site:#x} retargeted')
        lo, hi = img.fde_of(fut)
        require(lo == fut, f'{fut:#x} is not an FDE start')
        calls = [c for c in img.slot_calls(CONNECT_HELPER_SLOT) if lo <= c < hi]
        require(len(calls) == 1, f'{fut:#x}: {len(calls)} calls through the connect helper slot')
        rows.append({'node_port_site_call': hex(site), 'node_port_fde': hex(img.fde_of(site)[0]), 'future': hex(fut),
                     'helper_call': hex(calls[0])})
    return {'helper': hex(CONNECT_HELPER), 'slot': hex(CONNECT_HELPER_SLOT), 'socket_call': socks[0]['call'],
            'socket_type': socks[0]['type'], 'connect_call': hex(conn[0]), 'callers': rows,
            'all_slot_callers': [hex(img.fde_of(c)[0]) for c in img.slot_calls(CONNECT_HELPER_SLOT)]}


def analyse(data):
    img = Image(data)
    calls = {}
    for name, want in EXPECTED_CALLS.items():
        calls[name] = img.slot_calls(libc_slot(img, name))
        require(len(calls[name]) == want, f'{name}: {len(calls[name])} call sites, expected {want}')
    sockets = [check_socket(img, c) for c in calls['socket']]
    opts = [check_setsockopt(img, c) for c in calls['setsockopt']]
    listens = [check_simple(img, c, LISTEN_ARGS, 'listen') for c in calls['listen']]
    accepts = [check_simple(img, c, ACCEPT4_ARGS, 'accept4') for c in calls['accept4']]
    summary = {}
    for r in opts:
        summary[r['option']] = summary.get(r['option'], 0) + 1
    return {'call_counts': {k: len(v) for k, v in calls.items()},
            'libc_slots': {k: hex(libc_slot(img, k)) for k in EXPECTED_CALLS},
            'bind_calls': [hex(c) for c in calls['bind']], 'connect_calls': [hex(c) for c in calls['connect']],
            'socket': sockets, 'setsockopt': opts, 'setsockopt_by_option': summary,
            'listen': listens, 'accept4': accepts, 'node_port_connect': check_connect_chain(img, sockets)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--binary', type=Path, default=ROOT / TARGET)
    ap.add_argument('--out', type=Path)
    args = ap.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == TARGET)
    try:
        check(args.binary, identity)
        result = analyse(args.binary.read_bytes())
    except (EvidenceError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    result['target_sha256'] = identity['sha256']
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'records.json').write_text(text)
    print(json.dumps({'calls': result['call_counts'], 'options': result['setsockopt_by_option'],
                      'backlogs': [r['value'] for r in result['listen']]}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
