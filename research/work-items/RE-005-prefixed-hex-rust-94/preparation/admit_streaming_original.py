from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess

ROOT = Path('/tmp/hl-re005-next-codec-intake-20261101')
OUT = ROOT / 'authenticated-native'
SOURCE = Path('/tmp/hl-main78-admission-20261101/checkout/artifacts/node/94/hl-node')
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
sha = lambda data: hashlib.sha256(data).hexdigest()
assert not os.path.lexists(OUT)
policy_path = Path('/tmp/hl-resource-policy-20261101/available.py')
assert sha(policy_path.read_bytes()) == '1f5b2d4ee820460377516a2649aa1b17565bcb6e2a767e7fd389cb5e7c51b9b3'
spec = importlib.util.spec_from_file_location('resource_policy', policy_path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
resources = policy.snapshot()
assert resources['available'] >= resources['reserve'] + (16 << 20)
probes = []
with SOURCE.open('rb') as stream:
    fd = stream.fileno()
    assert os.fstat(fd).st_size == SIZE

    def probe(offset, size, label):
        assert 0 <= offset <= SIZE and 0 <= size <= SIZE - offset
        raw = os.pread(fd, size, offset)
        assert len(raw) == size
        probes.append({'label': label, 'offset': offset, 'bytes': size,
                       'expected_sha256': sha(raw), 'actual_hash': hashlib.sha256()})
        return raw

    head = probe(0, 64, 'ELF header')
    assert head[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<HHI', head, 16) == (3, 62, 1)
    phoff, shoff = struct.unpack_from('<QQ', head, 32)
    phsize, phnum, shsize, shnum, nameindex = struct.unpack_from('<HHHHH', head, 54)
    assert phsize == 56 and shsize == 64 and nameindex < shnum
    ph = probe(phoff, phsize * phnum, 'complete program header table')
    sh = probe(shoff, shsize * shnum, 'complete section header table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', sh, i * 64) for i in range(shnum)]
    nh = headers[nameindex]
    names = probe(nh[4], nh[5], 'complete section-name table')
    sections = {}
    for h in headers:
        assert h[0] < len(names)
        e = names.index(0, h[0]); name = names[h[0]:e].decode('ascii')
        if name:
            assert name not in sections
            sections[name] = {'type': h[1], 'flags': h[2], 'va': h[3],
                              'offset': h[4], 'bytes': h[5], 'entsize': h[9]}
    loads = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', ph, i * 56)
        if kind == 1:
            loads.append({'flags': flags, 'offset': offset, 'va': va,
                          'filesz': filesz, 'memsz': memsz, 'alignment': alignment})

    def mapping(va, size, executable=False):
        ss = [(n, s) for n, s in sections.items() if s['type'] != 8 and
              s['va'] <= va and va + size <= s['va'] + s['bytes']]
        pp = [p for p in loads if p['va'] <= va and va + size <= p['va'] + p['filesz']]
        assert len(ss) == len(pp) == 1
        n, s = ss[0]; p = pp[0]
        offset = s['offset'] + va - s['va']
        assert offset == p['offset'] + va - p['va']
        if executable:
            assert s['flags'] & 4 and p['flags'] & 1
        return {'va': hex(va), 'bytes': size, 'offset': offset,
                'section': n, 'section_metadata': s, 'PT_LOAD': p}

    def read(va, size, label, executable=False):
        m = mapping(va, size, executable)
        return probe(m['offset'], size, label), m

    hdr = sections['.eh_frame_hdr']; frame = sections['.eh_frame']
    index = probe(hdr['offset'], hdr['bytes'], 'complete original unwind header/index')
    assert index[:4] == b'\x01\x1b\x03\x3b'
    count = struct.unpack_from('<I', index, 8)[0]
    assert 12 + 8 * count == len(index)
    all_starts = []; selected = {}
    wanted = {0x29ed380, 0x32478a0, 0x4670030}
    for i in range(count):
        startrel, fderel = struct.unpack_from('<ii', index, 12 + i * 8)
        begin = hdr['va'] + startrel
        all_starts.append(begin)
        if begin in wanted:
            assert begin not in selected
            fdeva = hdr['va'] + fderel
            prefix, _ = read(fdeva, 16, 'FDE prefix ' + hex(begin))
            length, ciedelta, coderel, span = struct.unpack('<IIiI', prefix)
            assert 12 <= length < 1024 and ciedelta > 0
            assert fdeva + 8 + coderel == begin
            assert frame['va'] <= fdeva and fdeva + 4 + length <= frame['va'] + frame['bytes']
            raw, _ = read(fdeva, length + 4, 'complete selected FDE ' + hex(begin))
            cieva = fdeva + 4 - ciedelta
            cl, _ = read(cieva, 4, 'CIE length ' + hex(begin))
            cielength = struct.unpack('<I', cl)[0]
            assert 8 <= cielength < 1024
            cie, _ = read(cieva, cielength + 4, 'complete selected CIE ' + hex(begin))
            assert cie[4:9] == bytes(4) + b'\x01'
            ce = cie.index(0, 9); aug = cie[9:ce]
            assert cie[ce + 1:ce + 4] == b'\x01\x78\x10'
            alen = cie[ce + 4]; adata = cie[ce + 5:ce + 5 + alen]
            assert alen < 128
            assert (aug == b'zR' and adata == b'\x1b') or (aug == b'zPLR' and len(adata) == 7 and adata[0] == 0x9b and adata[-2:] == b'\x1b\x1b')
            selected[begin] = {'start': hex(begin), 'end': hex(begin + span), 'index': i,
                               'fde_va': hex(fdeva), 'fde_raw': raw.hex(),
                               'cie_va': hex(cieva), 'cie_raw': cie.hex(),
                               'cie_augmentation': aug.decode()}
    assert all_starts == sorted(all_starts) and set(selected) == wanted
    assert selected[0x29ed380]['end'] == '0x29ed51e'
    assert selected[0x4670030]['end'] == '0x46700d9'
    primary, primarymap = read(0x29ed380, 414, 'primary complete body', True)
    table, tablemap = read(0x208620, 16, 'complete hex digit table')
    bridge, bridgemap = read(0x32479e1, 0x3247a26 - 0x32479e1, 'separate bridge setup/result-use cut', True)
    proposer, proposermap = read(0x4670030, 169, 'separate proposer caller boundary/context', True)
    assert primary == (ROOT / 'prefixed-hex-retained-414.bin').read_bytes()
    assert table == b'0123456789abcdef'
    relocation = sections['.rela.dyn']
    assert relocation['entsize'] == 24 and relocation['bytes'] % 24 == 0
    relaraw = probe(relocation['offset'], relocation['bytes'], 'complete original dynamic RELA section')
    matches = []
    for i in range(relocation['bytes'] // 24):
        slot, info, addend = struct.unpack_from('<QQq', relaraw, 24 * i)
        if slot == 0x5773120:
            matches.append({'record_offset': relocation['offset'] + i * 24,
                            'slot': hex(slot), 'type': info & 0xffffffff,
                            'symbol': info >> 32, 'addend': hex(addend),
                            'raw': relaraw[i * 24:(i + 1) * 24].hex()})
    assert len(matches) == 1 and matches[0]['type'] == 8 and matches[0]['symbol'] == 0 and matches[0]['addend'] == '0x29ed380'
    del relaraw
    # Preliminary reads are only coordinate/content candidates. Authenticate
    # every one against the SAME complete stream that produces expected SHA.
    digest = hashlib.sha256(); offset = 0
    while True:
        chunk = stream.read(1 << 20)
        if not chunk:
            break
        digest.update(chunk)
        for item in probes:
            lo = max(offset, item['offset'])
            hi = min(offset + len(chunk), item['offset'] + item['bytes'])
            if lo < hi:
                item['actual_hash'].update(chunk[lo - offset:hi - offset])
        offset += len(chunk)
    assert offset == SIZE and digest.hexdigest() == DIGEST
    for item in probes:
        item['authenticated_stream_sha256'] = item.pop('actual_hash').hexdigest()
        assert item['authenticated_stream_sha256'] == item['expected_sha256']

OUT.mkdir(mode=0o700)
tool = Path('/usr/bin/objdump').resolve(); toolhash = sha(tool.read_bytes())
exports = {}
for label, raw, base in [('primary', primary, 0x29ed380), ('bridge-caller-cut', bridge, 0x32479e1), ('proposer-caller-context', proposer, 0x4670030)]:
    q = OUT / (label + '.bin')
    with q.open('xb') as f:
        os.fchmod(f.fileno(), 0o600); f.write(raw)
    argv = [str(tool), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
            '--insn-width=16', '--adjust-vma=' + hex(base), str(q)]
    run = subprocess.run(argv, capture_output=True, check=True,
                         env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    rows = []; cursor = base
    for line in run.stdout.decode().splitlines():
        f = line.split('\t')
        if len(f) >= 3 and re.fullmatch(r'\s*[0-9a-f]+:', f[0]):
            at = int(f[0].strip()[:-1], 16); encoded = bytes.fromhex(f[1])
            assert at == cursor and encoded == raw[at - base:at - base + len(encoded)]
            assert '(bad)' not in f[2]
            rows.append({'va': hex(at), 'raw': encoded.hex(), 'assembly': f[2]})
            cursor += len(encoded)
    assert cursor == base + len(raw)
    (OUT / (label + '.stdout')).write_bytes(run.stdout)
    (OUT / (label + '.stderr')).write_bytes(run.stderr)
    (OUT / (label + '.rows.json')).write_text(json.dumps(rows, indent=2) + '\n')
    exports[label] = {'bytes': len(raw), 'sha256': sha(raw), 'rows': len(rows),
                      'argv': argv, 'stdout_sha256': sha(run.stdout),
                      'stderr_sha256': sha(run.stderr)}
assert sha(tool.read_bytes()) == toolhash
(OUT / 'digit-table.bin').write_bytes(table)
(OUT / 'digit-table.bin').chmod(0o600)
record = {'schema': 'stream-authenticated-selected-native-intake-v1', 'status': 'PASS',
          'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'target': str(SOURCE), 'target_sha256': DIGEST, 'target_bytes': SIZE,
          'admission': 'Preliminary bounded immutable bytes candidates are admitted only after their entire raw content hashes equal their corresponding regions in the single complete expected-SHA stream. No full-target bytes object or fixture exists. All selected metadata/table/code facts use those admitted bytes; GNU receives only tiny owned non-executable copies.',
          'complete_original_streams': 1, 'full_image_memory_or_fixture_copies': 0,
          'authenticated_probe_regions': probes, 'primary_mapping': primarymap,
          'table_mapping': tablemap, 'bridge_context_mapping': bridgemap,
          'proposer_context_mapping': proposermap, 'FDEs': {hex(k): v for k, v in selected.items()},
          'index_count_metadata_only': count, 'hex_slot_RELATIVE': matches[0],
          'digit_table_hex': table.hex(), 'native_exports': exports,
          'objdump': {'path': str(tool), 'sha256': toolhash},
          'resource_snapshot_before': resources,
          'script_sha256_observational': sha(Path(__file__).read_bytes()),
          'limits': '414 primary bytes only. Caller169/69 bytes are separate selected setup/result-use and boundary context, not complete caller semantics. Six panic paths and helper behavior remain unqualified; no captured/compiler/emulator execution or original source/ABI identity.'}
(OUT / 'ADMISSION.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': 'PASS', 'receipt_sha256': sha((OUT / 'ADMISSION.json').read_bytes()),
                  'primary': exports['primary'], 'FDEs': record['FDEs'],
                  'table': table.decode(), 'probe_count': len(probes)}, indent=2))
