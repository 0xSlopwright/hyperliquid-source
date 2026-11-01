#!/usr/bin/env python3
"""RE-002: bind patched-fork base versions and the overflow-check setting to captured bytes.

Offline mode reads only the digest-checked node #94, node #115 and visor ELF files.
It extracts every panic ``Location`` record (file, line, column) whose file path is
inside a patched fork, and every call site of the six ``panic_const_*_overflow``
helpers. Captured binaries are never executed.

``--upstream DIR`` additionally compares the fork Locations with upstream source
revisions. DIR must hold bare clones and crate tarball extractions made by
``research/work-items/RE-002-fork-bases/fetch-upstream.sh``. Without it the
committed ``upstream`` section is kept and only its point set is checked against
the regenerated binary points.
"""
import argparse
import collections
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import manifest_item

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'research/work-items/RE-002-fork-bases'
TARGETS = {'94': 'artifacts/node/94/hl-node', '115': 'artifacts/node/115/hl-node',
           'visor': 'artifacts/visor/captured/hl-visor'}
R_X86_64_RELATIVE = 8
# Fork directory prefixes as embedded in each capture (RE-002 provenance packet).
FORK_PREFIX = {'94': '/home/ubuntu/hl/', '115': 'z_forks/'}
FORKS = ('hyper-fork', 'hyper-tls-fork', 'bincode-fork', 'hyper-alloy-core-fork',
         'revm-precompile', 'reth-chainspec', 'reth-ethereum-forks', 'reth-rpc-eth-types',
         'reth-rpc-server-types')
STRONG = ('unwrap', 'expect', 'panic!', 'unreachable!', 'assert', 'todo!', 'unimplemented!',
          'trace!', 'debug!', 'info!', 'warn!', 'error!')
# panic_const helper: push rbp; mov rbp,rsp; mov rdx,rdi; lea rdi,[rip+msg]; mov esi,imm32; call [rip+got]
HELPER = re.compile(rb'\x55\x48\x89\xe5\x48\x89\xfa\x48\x8d\x3d(....)\xbe(....)\xff\x15', re.S)
# Location argument then indirect call: lea rdi,[rip+loc]; call [rip+got]
SITE = re.compile(rb'\x48\x8d\x3d(....)\xff\x15(....)', re.S)


class EvidenceError(ValueError):
    pass


class Elf:
    def __init__(self, data):
        if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
            raise EvidenceError('not a little-endian ELF64 file')
        shoff = struct.unpack_from('<Q', data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 58)
        if shentsize != 64 or shstrndx >= shnum or shoff + shnum * 64 > len(data):
            raise EvidenceError('malformed section header table')
        raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * 64) for i in range(shnum)]
        stro, strsize = raw[shstrndx][4], raw[shstrndx][5]
        if stro + strsize > len(data):
            raise EvidenceError('section name table extends past end of file')
        names = data[stro:stro + strsize]
        self.data, self.secs = data, {}
        for h in raw:
            if h[1] == 8 or not h[5]:
                continue
            end = names.find(b'\0', h[0])
            if end < 0:
                raise EvidenceError('unterminated section name')
            name = names[h[0]:end].decode('ascii', 'strict')
            if name in self.secs:
                raise EvidenceError(f'duplicate section {name}')
            if h[4] + h[5] > len(data):
                raise EvidenceError(f'section {name} extends past end of file')
            self.secs[name] = {'addr': h[3], 'offset': h[4], 'size': h[5]}
        for name in ('.text', '.rela.dyn'):
            if name not in self.secs:
                raise EvidenceError(f'missing section {name}')
        rd = self.secs['.rela.dyn']
        if rd['size'] % 24:
            raise EvidenceError('.rela.dyn size is not a multiple of 24')
        self.rel = {}
        for o in range(rd['offset'], rd['offset'] + rd['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, o)
            if info & 0xffffffff == R_X86_64_RELATIVE:
                if where in self.rel:
                    raise EvidenceError(f'duplicate RELATIVE relocation at {where:#x}')
                self.rel[where] = addend
        t = self.secs['.text']
        self.text, self.text_va = data[t['offset']:t['offset'] + t['size']], t['addr']

    def off(self, va):
        for s in self.secs.values():
            if s['addr'] and s['addr'] <= va < s['addr'] + s['size']:
                return s['offset'] + va - s['addr']
        return None

    def location(self, va):
        """Return (file, line, col) for a Location record at va, or None."""
        lo, ptr = self.off(va), self.rel.get(va)
        if lo is None or ptr is None or lo + 24 > len(self.data):
            return None
        length, line, col = struct.unpack_from('<QII', self.data, lo + 8)
        fo = self.off(ptr)
        if fo is None or not 0 < length < 4096 or fo + length > len(self.data):
            return None
        try:
            return self.data[fo:fo + length].decode('utf-8'), line, col
        except UnicodeDecodeError:
            return None


def checked(release):
    rel = TARGETS[release]
    data = (ROOT / rel).read_bytes()
    item = manifest_item(ROOT, rel)
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise EvidenceError(f'{rel}: size/SHA-256 mismatch')
    return data, item['sha256']


def fork_of(path, release):
    prefix = FORK_PREFIX[release]
    if not path.startswith(prefix):
        return None
    head, _, rest = path[len(prefix):].partition('/')
    return (head, rest) if head in FORKS and rest else None


def fork_locations(elf, release):
    """Map fork -> file -> sorted [line, col] for every RELATIVE-backed Location record."""
    out = collections.defaultdict(lambda: collections.defaultdict(set))
    records = 0
    for where in sorted(elf.rel):
        loc = elf.location(where)
        if loc is None:
            continue
        hit = fork_of(loc[0], release)
        if hit is None:
            continue
        records += 1
        out[hit[0]][hit[1]].add((loc[1], loc[2]))
    return records, {f: {p: sorted(map(list, v)) for p, v in sorted(files.items())}
                     for f, files in sorted(out.items())}


def origin(path):
    if '/registry/src/' in path:
        return 'crates.io'
    if '/z_vendor/' in path:
        return 'vendored'
    if path.startswith('/rustc/'):
        return 'std'
    if 'z_forks/' in path or any(f'/home/ubuntu/hl/{f}/' in path for f in FORKS):
        return 'fork'
    if '/.cargo/git/' in path:
        return 'git-dependency'
    return 'first-party' if not path.startswith('/') or '/code_Mainnet/' in path else 'other'


def overflow(elf):
    helpers = {}
    for m in HELPER.finditer(elf.text):
        va = elf.text_va + m.start()
        msg = va + 14 + struct.unpack('<i', m.group(1))[0]
        enc = struct.unpack('<I', m.group(2))[0]
        fo = elf.off(msg)
        if not enc & 1 or fo is None:
            continue
        text = elf.data[fo:fo + (enc >> 1)]
        if text.startswith(b'attempt to ') and text.endswith(b' with overflow'):
            helpers[va] = text.decode()
    if len(helpers) != 6 or len(set(helpers.values())) != 6:
        raise EvidenceError(f'expected six distinct overflow helpers, found {len(helpers)}')
    gots = {g: t for g, t in elf.rel.items() if t in helpers}
    by_origin, by_helper, crates = collections.Counter(), collections.Counter(), collections.defaultdict(set)
    first = {}
    for m in SITE.finditer(elf.text):
        p = elf.text_va + m.start()
        loc_va = p + 7 + struct.unpack('<i', m.group(1))[0]
        got = p + 13 + struct.unpack('<i', m.group(2))[0]
        if got not in gots:
            continue
        loc = elf.location(loc_va)
        if loc is None:
            raise EvidenceError(f'overflow call at {p:#x} has no Location argument')
        o = origin(loc[0])
        by_origin[o] += 1
        by_helper[helpers[gots[got]]] += 1
        first.setdefault(o, {'site': hex(p), 'location': f'{loc[0]}:{loc[1]}:{loc[2]}'})
        if o in ('crates.io', 'vendored'):
            crates[o].add(re.split(r'/(?:registry/src/[^/]+|z_vendor)/', loc[0])[1].split('/')[0])
    return {'helpers': {hex(k): v for k, v in sorted(helpers.items())},
            'helper_got_slots': {hex(k): hex(v) for k, v in sorted(gots.items())},
            'call_sites': sum(by_origin.values()),
            'call_sites_by_origin': dict(sorted(by_origin.items())),
            'call_sites_by_helper': dict(sorted(by_helper.items())),
            'distinct_crates_with_sites': {k: len(v) for k, v in sorted(crates.items())},
            'first_site_by_origin': dict(sorted(first.items()))}


# ---- upstream comparison (optional, needs fetch-upstream.sh output) ----

UPSTREAM = [
    # fork, capture, kind, source, subdir, base revisions, boundary/other revisions
    ('hyper-fork', '94', 'git', 'hyper.git', '', ['v0.14.16', 'bff977b7', 'e8cccce0'],
     ['84b78b6c', 'f44f7265', 'v0.14.15', 'v0.14.17', 'v0.14.18', 'v0.14.20']),
    ('hyper-fork', '115', 'git', 'hyper.git', '', ['v0.14.16'],
     ['84b78b6c', 'f44f7265', 'v0.14.15', 'v0.14.17', 'v0.14.18']),
    ('hyper-tls-fork', '94', 'git', 'hyper-tls.git', '', ['v0.5.0'], ['v0.6.0']),
    ('hyper-tls-fork', '115', 'git', 'hyper-tls.git', '', ['v0.5.0'], ['v0.6.0']),
    ('bincode-fork', '94', 'crate', 'crates', 'bincode-{}', ['2.0.0', '2.0.1'], ['2.0.0-rc.3', '3.0.0']),
    ('bincode-fork', '115', 'crate', 'crates', 'bincode-{}', ['2.0.0', '2.0.1'], ['2.0.0-rc.3', '3.0.0']),
    ('hyper-alloy-core-fork', '94', 'git', 'core.git', '', ['3f28b07', 'v0.8.20', 'v0.8.26'],
     ['7edc626', 'v0.8.19', 'v1.0.0']),
    ('revm-precompile', '115', 'git', 'revm.git', 'crates/precompile/', ['v108', 'v113', 'a4219239'],
     ['v107', 'v114', '2e72f176']),
]


def token_start(src, line, col):
    if not 1 <= line <= len(src):
        return False
    text = src[line - 1]
    if not 1 <= col <= len(text):
        return False
    before = text[col - 2] if col >= 2 else ' '
    return text[col - 1] == '[' or (not text[col - 1].isspace() and not (before.isalnum() or before == '_'))


def strong(src, line, col):
    return 1 <= line <= len(src) and src[line - 1][col - 1:].startswith(STRONG)


def read_source(root, kind, source, sub, rev, rel):
    if kind == 'crate':
        p = root / source / sub.format(rev) / rel
        return p.read_text(errors='replace').split('\n') if p.is_file() else None
    try:
        blob = subprocess.run(['git', '-C', str(root / source), 'show', f'{rev}:{sub}{rel}'],
                              capture_output=True, check=True).stdout
    except subprocess.CalledProcessError:
        return None
    return blob.decode(errors='replace').split('\n')


def resolve(root, kind, source, rev):
    if kind == 'crate':
        return rev
    return subprocess.run(['git', '-C', str(root / source), 'rev-parse', f'{rev}^{{commit}}'],
                          capture_output=True, check=True, text=True).stdout.strip()


def compare(root, points):
    """Score each listed revision; returns per-revision file results and base shifts."""
    rows = []
    for fork, rel_id, kind, source, sub, base, other in UPSTREAM:
        files = {k: v for k, v in points[rel_id].get(fork, {}).items()
                 if not (fork == 'hyper-alloy-core-fork' and not k.startswith('crates/'))}
        pts = {f: [p for p in v if p[0] > 2] for f, v in files.items()}
        revs = []
        for rev in base + other:
            per = {}
            for rel, P in sorted(pts.items()):
                src = read_source(root, kind, source, sub, rev, rel)
                if src is None:
                    per[rel] = {'present': False}
                    continue
                miss = [f'{l}:{c}' for l, c in P if not token_start(src, l, c)]
                entry = {'present': True, 'token_start': len(P) - len(miss), 'strong': sum(strong(src, l, c) for l, c in P),
                         'points': len(P), 'misses': miss}
                if rev in base:
                    def score(d):
                        return (sum(token_start(src, l - d, c) for l, c in P), sum(strong(src, l - d, c) for l, c in P))
                    # A shift is reported only when it explains strictly more points than shift 0.
                    best = max(range(-80, 81), key=lambda d: (score(d), -abs(d))) if miss else 0
                    if score(best)[0] <= score(0)[0]:
                        best = 0
                    entry['best_shift'] = best
                    entry['token_start_at_best_shift'] = sum(token_start(src, l - best, c) for l, c in P)
                per[rel] = entry
            revs.append({'revision': rev, 'resolved': resolve(root, kind, source, rev), 'role': 'base' if rev in base else 'control',
                         'token_start': sum(e.get('token_start', 0) for e in per.values()),
                         'strong': sum(e.get('strong', 0) for e in per.values()),
                         'points': sum(len(P) for P in pts.values()), 'files': per})
        rows.append({'fork': fork, 'capture': rel_id, 'source': source if kind == 'git' else f'crates.io {sub}',
                     'subdir': sub if kind == 'git' else '', 'revisions': revs})
    return rows


def check_upstream_points(upstream, points):
    """Offline control: committed upstream rows must cover exactly the regenerated fork points."""
    expected = {(fork, capture): base + controls
                for fork, capture, _, _, _, base, controls in UPSTREAM}
    keys = [(row['fork'], row['capture']) for row in upstream]
    if len(keys) != len(set(keys)) or set(keys) != set(expected):
        raise EvidenceError('upstream comparison row set differs')
    for row in upstream:
        revisions = [rev['revision'] for rev in row['revisions']]
        if len(revisions) != len(set(revisions)) or set(revisions) != set(expected[row['fork'], row['capture']]):
            raise EvidenceError('upstream comparison revision set differs')
        files = points[row['capture']].get(row['fork'], {})
        want = {f: len([p for p in v if p[0] > 2]) for f, v in files.items()
                if row['fork'] != 'hyper-alloy-core-fork' or f.startswith('crates/')}
        for rev in row['revisions']:
            got = {f: e['points'] for f, e in rev['files'].items() if e.get('present')}
            # Explicitly absent upstream files are valid controls; omitted
            # comparison entries are not equivalent to those observations.
            if set(rev['files']) != set(want) or any(got[f] != want[f] for f in got):
                raise EvidenceError(f"upstream {row['fork']} #{row['capture']} {rev['revision']}: point set differs")


def build(upstream_root=None, previous=None):
    result = {'schema': 'hyperliquid-source/re-002-fork-bases/v1', 'targets': {}, 'fork_locations': {}, 'overflow': {}}
    points = {}
    for release in TARGETS:
        data, sha = checked(release)
        elf = Elf(data)
        result['targets'][release] = {'path': TARGETS[release], 'sha256': sha}
        if release in FORK_PREFIX:
            records, locs = fork_locations(elf, release)
            points[release] = locs
            result['fork_locations'][release] = {'prefix': FORK_PREFIX[release], 'records': records,
                                                 'distinct_points': sum(len(v) for f in locs.values() for v in f.values()),
                                                 'forks': locs}
        result['overflow'][release] = overflow(elf)
    if upstream_root is not None:
        result['upstream'] = compare(Path(upstream_root), points)
    elif previous is not None and 'upstream' in previous:
        check_upstream_points(previous['upstream'], points)
        result['upstream'] = previous['upstream']
    return result


def render(result):
    return (json.dumps(result, indent=1, sort_keys=True) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=OUT)
    ap.add_argument('--upstream', type=Path, help='directory made by fetch-upstream.sh')
    ap.add_argument('--check', action='store_true', help='fail if the committed packet differs')
    args = ap.parse_args(argv)
    path = args.out / 'fork-bases.json'
    previous = json.loads(path.read_text()) if path.is_file() else None
    data = render(build(args.upstream, previous))
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
