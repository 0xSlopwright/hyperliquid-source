#!/usr/bin/env python3
"""RE-002: bind the hyper-fork URL-to-address pin in HttpConnector to captured bytes.

Static only. It reads the digest-checked node #94 and #115 files and never executes them.
For #94 it checks each instruction anchor: the exact bytes at the virtual address, and the
resolved RIP-relative target, which must be a panic Location, a string, or a GOT slot
whose RELATIVE addend is the stated function. For #115 it checks that the same two fork
strings and the fork-only Location points exist and are referenced from .text.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import manifest_item
from bincode_varint import EvidenceError, bytes_in_section, relative_relocs, sections

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'research/work-items/RE-002-hyper-fork-url-pin'
TARGETS = {'94': 'artifacts/node/94/hl-node', '115': 'artifacts/node/115/hl-node'}
HTTP = {'94': '/home/ubuntu/hl/hyper-fork/src/client/connect/http.rs',
        '115': 'z_forks/hyper-fork/src/client/connect/http.rs'}
STRINGS = {'two_matching_urls': b'\x12two matching urls \xc0\x01 \xc0\x01 \xc0\x00',
           'only_trying': b'\x17hyper-fork only trying \xc0\x04 on \xc0\x01\n'}
FORK_ONLY_POINTS = [(494, 21), (515, 28), (546, 55), (558, 85)]

# FDE ranges from `make index` (work/index/node-94-unwind.tsv): start and next start.
FUNCTIONS = {
    'ConnectingTcp::new (fork)': (0x29c1930, 0x29c2e40),
    'ConnectingTcpRemote::new (fork)': (0x29c3190, 0x29c3300),
    'ConnectingTcpRemote::connect poll (one of six instances)': (0x22b64a0, 0x22b75b0),
    'HttpConnector::call_async poll (one of three instances)': (0x2428800, 0x242b110),
    'tokio::time::sleep': (0x4f65d40, 0x4f65ee0),
    'std::io::_print': (0x4edba50, 0x4edbb20),
    '<http::Uri as Display>::fmt': (0x299efd0, 0x299f1c0),
}

# (va, exact bytes, kind, expected target, meaning)
ANCHORS = [
    (0x29c1962, '66c78424b0010000 0200', 'bytes', None, 'pin slot starts as Option<SocketAddr>::None (tag 2)'),
    (0x29c1971, '83792001', 'bytes', None, 'map is used only when Config+0x20 == 1'),
    (0x29c1a32, '410fb78d72020000', 'bytes', None, 'B-tree node len (u16) at +0x272'),
    (0x29c1bf8, '4c8b84c578010000', 'bytes', None, 'key[i].len at node+0x178+24*i (String keys)'),
    (0x29c1c09, '488b9cc570010000', 'bytes', None, 'key[i].ptr at node+0x170+24*i'),
    (0x29c267a, '48837c242000', 'bytes', None, 'on a match: is a key already matched?'),
    (0x29c2680, '0f859b050000', 'jcc', 0x29c2c21, 'yes: go to the "two matching urls" panic'),
    (0x29c2686, '49c1e605', 'bytes', None, 'value index * 32 (SocketAddr values at node+0)'),
    (0x29c269a, 'f30f6f4500', 'bytes', None, 'load the matched SocketAddr'),
    (0x29c26a4, '660f7f8424b0010000', 'bytes', None, 'store it into the pin slot'),
    (0x29c2a12, 'e879070000', 'call_rel', 0x29c3190, 'build ConnectingTcpRemote with the pin'),
    (0x29c2a17, '488d0da2bad002', 'lea_location', (515, 28), 'fallback delay Location'),
    (0x29c2a2a, 'ff15f8ccda02', 'call_got', 0x4f65d40, 'tokio::time::sleep(fallback_timeout)'),
    (0x29c2c7b, '488d3d83a883fd', 'lea_string', 'two_matching_urls', 'panic template'),
    (0x29c2c82, '488d151fb8d002', 'lea_location', (494, 21), 'panic Location'),
    (0x29c2c8e, 'ff1504b4da02', 'call_got', 0x157b810, 'panic entry with fmt::Arguments and Location'),
    (0x29c329d, '488d3dd3bba3fd', 'lea_string', 'divide_by_zero', 't / (addrs.len() as u32) panic text'),
    (0x29c32a4, '488d1505b3d002', 'lea_location', (546, 55), 'connect_timeout division Location'),
    (0x29c325c, '0f114748', 'bytes', None, 'ConnectingTcpRemote+0x48: addrs'),
    (0x29c3264, '48894f18', 'bytes', None, 'ConnectingTcpRemote+0x18: connect_timeout secs'),
    (0x29c3268, '897720', 'bytes', None, 'ConnectingTcpRemote+0x20: connect_timeout nanos'),
    (0x29c326b, '410f1001', 'bytes', None, 'ConnectingTcpRemote+0x28: pin copied from r9'),
    (0x22b64fb, '6641837c242802', 'bytes', None, 'connect(): is self.pin None (tag 2)?'),
    (0x22b6502, '0f85eb000000', 'jcc', 0x22b65f3, 'Some: take the pin path'),
    (0x22b663f, '488d3d8e9ff4fd', 'lea_string', 'only_trying', 'print template'),
    (0x22b664e, 'ff1514834b03', 'call_got', 0x4edba50, 'std::io::_print (stdout)'),
    (0x22b6654, 'bf20000000', 'bytes', None, 'allocate one 32-byte SocketAddr: vec![pin]'),
    (0x22b678d, 'ff1505894b03', 'call_got', 0x29c3300, 'per-address socket connect helper'),
    (0x2428ee5, 'ff1585613403', 'call_got', 0x299efd0, 'dst.to_string() via <Uri as Display>'),
    (0x2428f6d, 'ff1505613403', 'call_got', 0x29c1930, 'ConnectingTcp::new(dst_string, addrs, config)'),
]
EXTRA_STRINGS = {'divide_by_zero': b'divide by zero error when dividing duration by scalar'}
# Strings each helper must reference (identifies the helper without symbols).
HELPER_STRINGS = {
    'tokio::time::sleep': b'A Tokio 1.x context was found, but timers are disabled',
    'std::io::_print': b'stdout',
    '<http::Uri as Display>::fmt': b'/*',
}


def checked(release):
    rel = TARGETS[release]
    data = (ROOT / rel).read_bytes()
    item = manifest_item(ROOT, rel)
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise EvidenceError(f'{rel}: size/SHA-256 mismatch')
    return data, item['sha256']


def location(data, secs, relocs, va):
    if va not in relocs:
        raise EvidenceError(f'Location {va:#x} has no RELATIVE relocation')
    length, line, col = struct.unpack_from('<QII', bytes_in_section(data, secs, va + 8, 16))
    path = bytes_in_section(data, secs, relocs[va], length).decode()
    return path, line, col


def rip_target(insn, va):
    """Target of a RIP-relative lea/call/jcc/rel32 call encoded in insn at va."""
    if insn[:1] == b'\xe8':
        return va + 5 + struct.unpack_from('<i', insn, 1)[0]
    if insn[:2] == b'\x0f\x85' or insn[:2] == b'\x0f\x84':
        return va + 6 + struct.unpack_from('<i', insn, 2)[0]
    if insn[:2] == b'\xff\x15':
        return va + 6 + struct.unpack_from('<i', insn, 2)[0]
    if insn[0] in (0x48, 0x4c) and insn[1] == 0x8d and insn[2] & 0xc7 == 0x05:
        return va + 7 + struct.unpack_from('<i', insn, 3)[0]
    raise EvidenceError(f'no RIP-relative operand at {va:#x}')


def check_anchor(data, secs, relocs, release, anchor):
    va, hexbytes, kind, want, meaning = anchor
    raw = bytes.fromhex(hexbytes.replace(' ', ''))
    got = bytes_in_section(data, secs, va, len(raw))
    if got != raw:
        raise EvidenceError(f'{va:#x}: bytes {got.hex()} != {raw.hex()}')
    rec = {'va': hex(va), 'bytes': raw.hex(), 'kind': kind, 'meaning': meaning}
    if kind == 'bytes':
        return rec
    tgt = rip_target(raw, va)
    if kind in ('jcc', 'call_rel'):
        if tgt != want:
            raise EvidenceError(f'{va:#x}: target {tgt:#x} != {want:#x}')
        rec['target'] = hex(tgt)
    elif kind == 'call_got':
        if relocs.get(tgt) != want:
            raise EvidenceError(f'{va:#x}: GOT {tgt:#x} -> {relocs.get(tgt)} != {want:#x}')
        rec['got'], rec['target'] = hex(tgt), hex(want)
    elif kind == 'lea_location':
        path, line, col = location(data, secs, relocs, tgt)
        if (path, line, col) != (HTTP[release], *want):
            raise EvidenceError(f'{va:#x}: Location {path}:{line}:{col} != {want}')
        rec['location'], rec['source'] = hex(tgt), f'{path}:{line}:{col}'
    elif kind == 'lea_string':
        text = STRINGS.get(want) or EXTRA_STRINGS[want]
        if bytes_in_section(data, secs, tgt, len(text)) != text:
            raise EvidenceError(f'{va:#x}: string at {tgt:#x} is not {want}')
        rec['string'], rec['text'] = hex(tgt), text.decode('latin-1')
    return rec


def references(text, text_va, start, end, target):
    """RIP-relative lea sites in [start, end) whose target is `target`."""
    out = []
    lo, hi = start - text_va, end - text_va
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text[lo:hi]):
        p = lo + m.start()
        if text_va + p + 7 + struct.unpack_from('<i', text, p + 3)[0] == target:
            out.append(text_va + p)
    return out


def helper_strings(data, secs, text, text_va):
    out = {}
    for name, needle in HELPER_STRINGS.items():
        start, end = FUNCTIONS[name]
        hits = []
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text[start - text_va:end - text_va]):
            p = start - text_va + m.start()
            tgt = text_va + p + 7 + struct.unpack_from('<i', text, p + 3)[0]
            try:
                if bytes_in_section(data, secs, tgt, len(needle)) == needle:
                    hits.append(hex(text_va + p))
            except EvidenceError:
                continue
        if not hits:
            raise EvidenceError(f'{name}: no reference to {needle!r}')
        out[name] = {'string': needle.decode(), 'lea_sites': hits}
    return out


def fork_points(data, secs, relocs, release):
    """Every Location record for the fork-only http.rs points and its .text LEA sites."""
    text_sec = secs['.text']
    text = data[text_sec['offset']:text_sec['offset'] + text_sec['size']]
    want = HTTP[release].encode()
    out = {f'{l}:{c}': [] for l, c in FORK_ONLY_POINTS}
    for where, addend in sorted(relocs.items()):
        try:
            if bytes_in_section(data, secs, addend, len(want)) != want:
                continue
            length, line, col = struct.unpack_from('<QII', bytes_in_section(data, secs, where + 8, 16))
        except EvidenceError:
            continue
        if length != len(want) or f'{line}:{col}' not in out:
            continue
        sites = references(text, text_sec['addr'], text_sec['addr'], text_sec['addr'] + text_sec['size'], where)
        out[f'{line}:{col}'].append({'location': hex(where), 'lea_sites': len(sites)})
    for k, v in out.items():
        if not v or not any(r['lea_sites'] for r in v):
            raise EvidenceError(f'#{release}: fork-only point {k} has no referenced Location')
    return out


# ---- who fills the pin map ----
# ArcInner<Config> is 0xa0 bytes; Config starts at +0x10, so the map tag Config+0x20 is Arc+0x30.
# Upstream HttpConnector::new_with_resolver writes connect_timeout None (nanos 1e9 at Arc+0x58)
# and happy_eyeballs_timeout Some(300 ms) (nanos 0x11e1a300 at Arc+0x68).
CONFIG_ALLOC = re.compile(rb'\xbf\xa0\x00\x00\x00')
CONFIG_NONE_TIMEOUT = re.compile(rb'\xc7[\x40-\x47]\x58\x00\xca\x9a\x3b')
TAG_STORE = re.compile(rb'\x48\xc7([\x40-\x47])\x30(....)', re.S)
POPULATION = {
    '94': {'clone': 0x14e6140, 'make_mut': None,
           'clone_checks': [(0x14e6202, '837b2001', 'cmpl $1,0x20(%rbx): map is Some?'),
                            (0x14e6258, 'e853 2dffff', 'call 0x14d8fb0: clone the BTreeMap<String, SocketAddr>')],
           'writes': [(0x14390f3, '41c6878000000000', 'movb $0,0x80(%r15): enforce_http(false)'),
                      (0x14574c7, '41c6842480000000 00', 'movb $0,0x80(%r12): enforce_http(false)'),
                      (0x147a063, '41c6842480000000 00', 'movb $0,0x80(%r12): enforce_http(false)'),
                      (0x14b278e, '41c6858000000000', 'movb $0,0x80(%r13): enforce_http(false)')]},
    '115': {'clone': 0x15c2b10, 'make_mut': 0x15ae6e0, 'clone_checks': [],
            'writes': [(0x158d220, '41c6858000000000', 'movb $0,0x80(%r13): enforce_http(false), inlined make_mut')]},
}


def direct_callers(text, text_va, target):
    out = []
    for m in re.finditer(rb'\xe8', text):
        p = m.start()
        if p + 5 <= len(text) and text_va + p + 5 + struct.unpack_from('<i', text, p + 1)[0] == target:
            out.append(text_va + p)
    return out


def population(data, secs, release):
    t = secs['.text']
    text, tva = data[t['offset']:t['offset'] + t['size']], t['addr']
    builds = []
    for m in CONFIG_ALLOC.finditer(text):
        w = text[m.start():m.start() + 260]
        if not CONFIG_NONE_TIMEOUT.search(w) or b'\x00\xa3\xe1\x11' not in w:
            continue
        tag = TAG_STORE.search(w)
        if tag is None:
            raise EvidenceError(f'#{release}: Config build at {tva + m.start():#x} has no tag store')
        builds.append({'alloc': hex(tva + m.start()), 'tag_store': hex(tva + m.start() + tag.start()),
                       'tag_value': struct.unpack('<i', tag.group(2))[0]})
    if not builds or any(b['tag_value'] != 0 for b in builds):
        raise EvidenceError(f'#{release}: a Config build stores a non-zero map tag')
    cfg = POPULATION[release]
    body = text[cfg['clone'] - tva:cfg['clone'] - tva + 0x200]
    if b'\xbf\xa0\x00\x00\x00' not in body or b'\x83\x7b\x20\x01' not in body:
        raise EvidenceError(f'#{release}: {cfg["clone"]:#x} is not the Config clone')
    rec = {'config_builds': builds, 'config_clone': hex(cfg['clone']),
           'config_clone_callers': [hex(a) for a in direct_callers(text, tva, cfg['clone'])]}
    if cfg['make_mut']:
        callers = direct_callers(text, tva, cfg['make_mut'])
        rec['make_mut'] = hex(cfg['make_mut'])
        rec['make_mut_callers'] = []
        for a in callers:
            nxt = bytes_in_section(data, secs, a + 5, 16)
            # first config write after make_mut returns &mut Config in rax
            m = re.search(rb'\xc6\x40(.)\x00', nxt, re.S)
            if m is None:
                raise EvidenceError(f'#{release}: no byte store after make_mut call {a:#x}')
            rec['make_mut_callers'].append({'call': hex(a), 'writes_config_offset': hex(m.group(1)[0]), 'value': 0})
    rec['checks'] = []
    for va, hexbytes, meaning in cfg['clone_checks'] + cfg['writes']:
        raw = bytes.fromhex(hexbytes.replace(' ', ''))
        if bytes_in_section(data, secs, va, len(raw)) != raw:
            raise EvidenceError(f'#{release}: {va:#x} bytes differ')
        rec['checks'].append({'va': hex(va), 'bytes': raw.hex(), 'meaning': meaning})
    return rec


def build():
    result = {'schema': 'hyperliquid-source/re-002-hyper-fork-url-pin/v1', 'targets': {}}
    for release in TARGETS:
        data, sha = checked(release)
        secs = sections(data)
        relocs = relative_relocs(data, secs)
        rec = {'path': TARGETS[release], 'sha256': sha, 'string_file_offsets': {}}
        for name, s in STRINGS.items():
            hits = [m.start() for m in re.finditer(re.escape(s), data)]
            if len(hits) != 1:
                raise EvidenceError(f'#{release}: {name} occurs {len(hits)} times')
            rec['string_file_offsets'][name] = hex(hits[0])
        rec['fork_only_points'] = fork_points(data, secs, relocs, release)
        rec['map_population'] = population(data, secs, release)
        if release == '94':
            t = secs['.text']
            text = data[t['offset']:t['offset'] + t['size']]
            rec['functions'] = {k: [hex(a), hex(b)] for k, (a, b) in FUNCTIONS.items()}
            rec['anchors'] = [check_anchor(data, secs, relocs, release, a) for a in ANCHORS]
            rec['helper_strings'] = helper_strings(data, secs, text, t['addr'])
        result['targets'][release] = rec
    return result


def render(result):
    return (json.dumps(result, indent=1, sort_keys=True) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=OUT)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args(argv)
    path = args.out / 'hyper-fork-url-pin.json'
    data = render(build())
    if args.check:
        if not path.is_file() or path.read_bytes() != data:
            print(f'{path}: differs from regenerated output', file=sys.stderr)
            return 1
        print(f'{path}: OK')
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
