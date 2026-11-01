# Later portable reproduction wrapper of the original pre-Rust streaming
# admission. CLI/resource/check-liveness changes only; frozen original proof
# and admission remain separately retained. No captured code executes.
def require(condition, message):
    if not condition:
        raise ValueError(message)

from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
parser = __import__('argparse').ArgumentParser(description='Authenticate only the selected node94 prefixed-hex native evidence, without a full-image copy.')
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
OUT = args.out.absolute()
SOURCE = args.binary.absolute()
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
sha = lambda data: hashlib.sha256(data).hexdigest()
require(not os.path.lexists(OUT), 'native evidence condition failed')
resource_root = Path('/sys/fs/cgroup')
maximum = (resource_root / 'memory.max').read_text().strip()
if maximum.isdigit():
    limit = int(maximum)
    current = int((resource_root / 'memory.current').read_text())
    stat = dict(((key, int(value)) for key, value in (line.split() for line in (resource_root / 'memory.stat').read_text().splitlines())))
    clean = max(0, stat['file'] - stat['shmem'] - stat.get('file_dirty', 0) - stat.get('file_writeback', 0))
    credit = max(0, min(stat['inactive_file'], clean))
    resources = {'maximum': limit, 'current': current, 'raw_headroom': max(0, limit - current), 'clean_inactive_file_credit': credit, 'available': max(0, limit - current) + credit, 'reserve': 256 << 20, 'slab_credit': 0, 'active_file_credit': 0, 'shmem_credit': 0}
    require(resources['available'] >= resources['reserve'] + (16 << 20), 'native evidence condition failed')
else:
    resources = {'finite_cgroup_limit_observed': False, 'small_streaming_reader_only': True}
probes = []
with SOURCE.open('rb') as stream:
    fd = stream.fileno()
    require(os.fstat(fd).st_size == SIZE, 'native evidence condition failed')

    def probe(offset, size, label):
        require(0 <= offset <= SIZE and 0 <= size <= SIZE - offset, 'native evidence condition failed')
        raw = os.pread(fd, size, offset)
        require(len(raw) == size, 'native evidence condition failed')
        probes.append({'label': label, 'offset': offset, 'bytes': size, 'expected_sha256': sha(raw), 'actual_hash': hashlib.sha256()})
        return raw
    head = probe(0, 64, 'ELF header')
    require(head[:6] == b'\x7fELF\x02\x01', 'native evidence condition failed')
    require(struct.unpack_from('<HHI', head, 16) == (3, 62, 1), 'native evidence condition failed')
    phoff, shoff = struct.unpack_from('<QQ', head, 32)
    phsize, phnum, shsize, shnum, nameindex = struct.unpack_from('<HHHHH', head, 54)
    require(phsize == 56 and shsize == 64 and (nameindex < shnum), 'native evidence condition failed')
    ph = probe(phoff, phsize * phnum, 'complete program header table')
    sh = probe(shoff, shsize * shnum, 'complete section header table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', sh, i * 64) for i in range(shnum)]
    nh = headers[nameindex]
    names = probe(nh[4], nh[5], 'complete section-name table')
    sections = {}
    for h in headers:
        require(h[0] < len(names), 'native evidence condition failed')
        e = names.index(0, h[0])
        name = names[h[0]:e].decode('ascii')
        if name:
            require(name not in sections, 'native evidence condition failed')
            sections[name] = {'type': h[1], 'flags': h[2], 'va': h[3], 'offset': h[4], 'bytes': h[5], 'entsize': h[9]}
    loads = []
    for i in range(phnum):
        kind, flags, offset, va, _, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', ph, i * 56)
        if kind == 1:
            loads.append({'flags': flags, 'offset': offset, 'va': va, 'filesz': filesz, 'memsz': memsz, 'alignment': alignment})

    def mapping(va, size, executable=False):
        ss = [(n, s) for n, s in sections.items() if s['type'] != 8 and s['va'] <= va and (va + size <= s['va'] + s['bytes'])]
        pp = [p for p in loads if p['va'] <= va and va + size <= p['va'] + p['filesz']]
        require(len(ss) == len(pp) == 1, 'native evidence condition failed')
        n, s = ss[0]
        p = pp[0]
        offset = s['offset'] + va - s['va']
        require(offset == p['offset'] + va - p['va'], 'native evidence condition failed')
        if executable:
            require(s['flags'] & 4 and p['flags'] & 1, 'native evidence condition failed')
        return {'va': hex(va), 'bytes': size, 'offset': offset, 'section': n, 'section_metadata': s, 'PT_LOAD': p}

    def read(va, size, label, executable=False):
        m = mapping(va, size, executable)
        return (probe(m['offset'], size, label), m)
    hdr = sections['.eh_frame_hdr']
    frame = sections['.eh_frame']
    index = probe(hdr['offset'], hdr['bytes'], 'complete original unwind header/index')
    require(index[:4] == b'\x01\x1b\x03;', 'native evidence condition failed')
    count = struct.unpack_from('<I', index, 8)[0]
    require(12 + 8 * count == len(index), 'native evidence condition failed')
    all_starts = []
    selected = {}
    wanted = {43963264, 52721824, 73859120}
    for i in range(count):
        startrel, fderel = struct.unpack_from('<ii', index, 12 + i * 8)
        begin = hdr['va'] + startrel
        all_starts.append(begin)
        if begin in wanted:
            require(begin not in selected, 'native evidence condition failed')
            fdeva = hdr['va'] + fderel
            prefix, _ = read(fdeva, 16, 'FDE prefix ' + hex(begin))
            length, ciedelta, coderel, span = struct.unpack('<IIiI', prefix)
            require(12 <= length < 1024 and ciedelta > 0, 'native evidence condition failed')
            require(fdeva + 8 + coderel == begin, 'native evidence condition failed')
            require(frame['va'] <= fdeva and fdeva + 4 + length <= frame['va'] + frame['bytes'], 'native evidence condition failed')
            raw, _ = read(fdeva, length + 4, 'complete selected FDE ' + hex(begin))
            cieva = fdeva + 4 - ciedelta
            cl, _ = read(cieva, 4, 'CIE length ' + hex(begin))
            cielength = struct.unpack('<I', cl)[0]
            require(8 <= cielength < 1024, 'native evidence condition failed')
            cie, _ = read(cieva, cielength + 4, 'complete selected CIE ' + hex(begin))
            require(cie[4:9] == bytes(4) + b'\x01', 'native evidence condition failed')
            ce = cie.index(0, 9)
            aug = cie[9:ce]
            require(cie[ce + 1:ce + 4] == b'\x01x\x10', 'native evidence condition failed')
            alen = cie[ce + 4]
            adata = cie[ce + 5:ce + 5 + alen]
            require(alen < 128, 'native evidence condition failed')
            require(aug == b'zR' and adata == b'\x1b' or (aug == b'zPLR' and len(adata) == 7 and (adata[0] == 155) and (adata[-2:] == b'\x1b\x1b')), 'native evidence condition failed')
            selected[begin] = {'start': hex(begin), 'end': hex(begin + span), 'index': i, 'fde_va': hex(fdeva), 'fde_raw': raw.hex(), 'cie_va': hex(cieva), 'cie_raw': cie.hex(), 'cie_augmentation': aug.decode()}
    require(all_starts == sorted(all_starts) and set(selected) == wanted, 'native evidence condition failed')
    require(selected[43963264]['end'] == '0x29ed51e', 'native evidence condition failed')
    require(selected[73859120]['end'] == '0x46700d9', 'native evidence condition failed')
    primary, primarymap = read(43963264, 414, 'primary complete body', True)
    table, tablemap = read(2131488, 16, 'complete hex digit table')
    bridge, bridgemap = read(52722145, 52722214 - 52722145, 'separate bridge setup/result-use cut', True)
    proposer, proposermap = read(73859120, 169, 'separate proposer caller boundary/context', True)
    require(sha(primary) == '4467f0fb09786fc39b97b1925a7dda43d82bee4ffd4fa6c66920d6a471e3672e', 'native evidence condition failed')
    require(table == b'0123456789abcdef', 'native evidence condition failed')
    relocation = sections['.rela.dyn']
    require(relocation['entsize'] == 24 and relocation['bytes'] % 24 == 0, 'native evidence condition failed')
    relaraw = probe(relocation['offset'], relocation['bytes'], 'complete original dynamic RELA section')
    matches = []
    for i in range(relocation['bytes'] // 24):
        slot, info, addend = struct.unpack_from('<QQq', relaraw, 24 * i)
        if slot == 91697440:
            matches.append({'record_offset': relocation['offset'] + i * 24, 'slot': hex(slot), 'type': info & 4294967295, 'symbol': info >> 32, 'addend': hex(addend), 'raw': relaraw[i * 24:(i + 1) * 24].hex()})
    require(len(matches) == 1 and matches[0]['type'] == 8 and (matches[0]['symbol'] == 0) and (matches[0]['addend'] == '0x29ed380'), 'native evidence condition failed')
    del relaraw
    digest = hashlib.sha256()
    offset = 0
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
    require(offset == SIZE and digest.hexdigest() == DIGEST, 'native evidence condition failed')
    for item in probes:
        item['authenticated_stream_sha256'] = item.pop('actual_hash').hexdigest()
        require(item['authenticated_stream_sha256'] == item['expected_sha256'], 'native evidence condition failed')
OUT.mkdir(mode=448)
tool = Path('/usr/bin/objdump').resolve()
toolhash = sha(tool.read_bytes())
exports = {}
for label, raw, base in [('primary', primary, 43963264), ('bridge-caller-cut', bridge, 52722145), ('proposer-caller-context', proposer, 73859120)]:
    q = OUT / (label + '.bin')
    with q.open('xb') as f:
        os.fchmod(f.fileno(), 384)
        f.write(raw)
    argv = [str(tool), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel', '--insn-width=16', '--adjust-vma=' + hex(base), str(q)]
    run = subprocess.run(argv, capture_output=True, check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    rows = []
    cursor = base
    for line in run.stdout.decode().splitlines():
        f = line.split('\t')
        if len(f) >= 3 and re.fullmatch('\\s*[0-9a-f]+:', f[0]):
            at = int(f[0].strip()[:-1], 16)
            encoded = bytes.fromhex(f[1])
            require(at == cursor and encoded == raw[at - base:at - base + len(encoded)], 'native evidence condition failed')
            require('(bad)' not in f[2], 'native evidence condition failed')
            rows.append({'va': hex(at), 'raw': encoded.hex(), 'assembly': f[2]})
            cursor += len(encoded)
    require(cursor == base + len(raw), 'native evidence condition failed')
    (OUT / (label + '.stdout')).write_bytes(run.stdout)
    (OUT / (label + '.stderr')).write_bytes(run.stderr)
    (OUT / (label + '.rows.json')).write_text(json.dumps(rows, indent=2) + '\n')
    exports[label] = {'bytes': len(raw), 'sha256': sha(raw), 'rows': len(rows), 'argv': argv, 'stdout_sha256': sha(run.stdout), 'stderr_sha256': sha(run.stderr)}
require(sha(tool.read_bytes()) == toolhash, 'native evidence condition failed')
(OUT / 'digit-table.bin').write_bytes(table)
(OUT / 'digit-table.bin').chmod(384)
record = {'schema': 'stream-authenticated-selected-native-intake-v1', 'status': 'PASS', 'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'target': str(SOURCE), 'target_sha256': DIGEST, 'target_bytes': SIZE, 'admission': 'Preliminary bounded immutable bytes candidates are admitted only after their entire raw content hashes equal their corresponding regions in the single complete expected-SHA stream. No full-target bytes object or fixture exists. All selected metadata/table/code facts use those admitted bytes; GNU receives only tiny owned non-executable copies.', 'complete_original_streams': 1, 'full_image_memory_or_fixture_copies': 0, 'authenticated_probe_regions': probes, 'primary_mapping': primarymap, 'table_mapping': tablemap, 'bridge_context_mapping': bridgemap, 'proposer_context_mapping': proposermap, 'FDEs': {hex(k): v for k, v in selected.items()}, 'index_count_metadata_only': count, 'hex_slot_RELATIVE': matches[0], 'digit_table_hex': table.hex(), 'native_exports': exports, 'objdump': {'path': str(tool), 'sha256': toolhash}, 'resource_snapshot_before': resources, 'script_sha256_observational': sha(Path(__file__).read_bytes()), 'limits': '414 primary bytes only. Caller169/69 bytes are separate selected setup/result-use and boundary context, not complete caller semantics. Six panic paths and helper behavior remain unqualified; no captured/compiler/emulator execution or original source/ABI identity.'}
(OUT / 'ADMISSION.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': 'PASS', 'receipt_sha256': sha((OUT / 'ADMISSION.json').read_bytes()), 'primary': exports['primary'], 'FDEs': record['FDEs'], 'table': table.decode(), 'probe_count': len(probes)}, indent=2))
