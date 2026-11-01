from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess

SOURCE = Path('/tmp/hl-main78-admission-20261101/checkout/artifacts/node/94/hl-node')
OUT = Path('/tmp/hl-three-digit-rust-intake-20261101/native-admission-1')
EXPECTED = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
PRIMARY = (0x1683670, 0x16836c5)
CALLER = (0x1682220, 0x1682735)
SELECTED = (0x16825fe, 0x168261d)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

assert not OUT.exists()
maximum = Path('/sys/fs/cgroup/memory.max').read_text().strip()
if maximum.isdigit():
    headroom = int(maximum) - int(Path('/sys/fs/cgroup/memory.current').read_text())
    assert headroom > (512 << 20) + SIZE
else:
    headroom = None
data = SOURCE.read_bytes()
assert type(data) is bytes and len(data) == SIZE and sha(data) == EXPECTED
assert data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 62
phoff, shoff = struct.unpack_from('<QQ', data, 32)
phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHH', data, 54)
assert phentsize == 56 and shentsize == 64 and shstrndx < shnum
assert phoff + phnum * 56 <= len(data) and shoff + shnum * 64 <= len(data)
headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * i) for i in range(shnum)]
string_header = headers[shstrndx]
strings = data[string_header[4]:string_header[4] + string_header[5]]
sections = {}
for h in headers:
    end = strings.find(b'\0', h[0]); assert end >= h[0]
    name = strings[h[0]:end].decode()
    if name:
        assert name not in sections
        sections[name] = {'type': h[1], 'flags': h[2], 'va': h[3], 'offset': h[4], 'bytes': h[5]}
segments = []
for i in range(phnum):
    kind, flags, off, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + 56 * i)
    if kind == 1:
        segments.append({'flags': flags, 'offset': off, 'va': va, 'filesz': filesz, 'memsz': memsz, 'align': align})

def mapping(va, size, executable=False):
    sec = [(name, s) for name, s in sections.items()
           if s['type'] != 8 and s['va'] <= va and va + size <= s['va'] + s['bytes']]
    load = [s for s in segments if s['va'] <= va and va + size <= s['va'] + s['filesz']]
    assert len(sec) == len(load) == 1
    name, s = sec[0]; segment = load[0]
    offset = s['offset'] + va - s['va']
    assert offset == segment['offset'] + va - segment['va'] and offset + size <= len(data)
    if executable:
        assert s['flags'] & 4 and segment['flags'] & 1
    return {'section': name, 'section_metadata': s, 'PT_LOAD': segment, 'va': hex(va), 'bytes': size, 'file_offset': offset}

def read(va, size, executable=False):
    m = mapping(va, size, executable)
    return data[m['file_offset']:m['file_offset'] + size], m

hdr = sections['.eh_frame_hdr']; frame = sections['.eh_frame']
assert data[hdr['offset']:hdr['offset'] + 4] == b'\x01\x1b\x03\x3b'
count = struct.unpack_from('<I', data, hdr['offset'] + 8)[0]
assert 12 + 8 * count <= hdr['bytes']
wanted = {PRIMARY[0]: [], CALLER[0]: [], 0x16836d0: []}
for i in range(count):
    begin_rel, fde_rel = struct.unpack_from('<ii', data, hdr['offset'] + 12 + i * 8)
    begin = hdr['va'] + begin_rel
    if begin in wanted:
        fde = hdr['va'] + fde_rel
        raw, _ = read(fde, 16)
        length, cie_pointer, code_rel, size = struct.unpack('<IIiI', raw)
        assert length >= 12 and cie_pointer > 0 and fde + 8 + code_rel == begin
        assert frame['va'] <= fde and fde + 4 + length <= frame['va'] + frame['bytes']
        fde_raw, _ = read(fde, length + 4)
        cie = fde + 4 - cie_pointer
        cie_len = struct.unpack('<I', read(cie, 4)[0])[0]
        cie_raw, _ = read(cie, cie_len + 4)
        assert cie_raw[4:8] == bytes(4)
        assert cie_raw[8:17] == b'\x01zR\x00\x01\x78\x10\x01\x1b'
        wanted[begin].append({'start': hex(begin), 'end': hex(begin + size), 'index': i,
                              'fde_va': hex(fde), 'fde_raw': fde_raw.hex(),
                              'cie_va': hex(cie), 'cie_raw': cie_raw.hex()})
assert all(len(rows) == 1 for rows in wanted.values())
assert int(wanted[PRIMARY[0]][0]['end'], 16) == PRIMARY[1]
assert int(wanted[CALLER[0]][0]['end'], 16) == CALLER[1]
primary, primary_map = read(PRIMARY[0], PRIMARY[1] - PRIMARY[0], True)
caller, caller_map = read(CALLER[0], CALLER[1] - CALLER[0], True)
selected, selected_map = read(SELECTED[0], SELECTED[1] - SELECTED[0], True)
padding, _ = read(PRIMARY[1], 11, True)
assert sha(primary) == '90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca'
assert sha(selected) == 'b354b34f5f55e91227691765ab6bb5336995de1cbfbb91d6fa109dc504887555'
assert padding == b'\xcc' * 11
del data

OUT.mkdir(mode=0o700)
objdump = Path('/usr/bin/objdump').resolve()
tool_before = sha(objdump.read_bytes())
version = subprocess.run([str(objdump), '--version'], check=True, capture_output=True).stdout.decode().splitlines()[0]
assert 'GNU objdump' in version
exports = {}
for label, raw, base in [('primary', primary, PRIMARY[0]), ('caller-boundary-only', caller, CALLER[0]), ('selected-caller-context', selected, SELECTED[0])]:
    path = OUT / (label + '.bin')
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw)
    argv = [str(objdump), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
            '--insn-width=16', '--adjust-vma=' + hex(base), str(path)]
    run = subprocess.run(argv, check=True, capture_output=True)
    native = run.stdout.decode().replace(str(path), '<owned-' + label + '-raw>')
    rows = []; cursor = base
    for line in native.splitlines():
        fields = line.split('\t')
        if len(fields) >= 3 and re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            va = int(fields[0].strip()[:-1], 16); encoded = bytes.fromhex(fields[1])
            assert va == cursor and encoded == raw[va - base:va - base + len(encoded)] and '(bad)' not in fields[2]
            rows.append({'va': hex(va), 'raw': encoded.hex(), 'assembly': fields[2]})
            cursor += len(encoded)
    assert cursor == base + len(raw) and path.read_bytes() == raw
    (OUT / (label + '.objdump.txt')).write_text(native)
    (OUT / (label + '.rows.json')).write_text(json.dumps(rows, indent=2) + '\n')
    exports[label] = {'bytes': len(raw), 'sha256': sha(raw), 'rows': rows,
                      'argv': argv, 'stdout_sha256': sha(run.stdout), 'stderr_sha256': sha(run.stderr)}
assert len(exports['primary']['rows']) == 30 and len(exports['selected-caller-context']['rows']) == 7
caller_by_va = {r['va']: r for r in exports['caller-boundary-only']['rows']}
assert all(caller_by_va[r['va']] == r for r in exports['selected-caller-context']['rows'])
assert sha(objdump.read_bytes()) == tool_before
record = {'schema': 'three-digit-independent-native-intake-v1', 'status': 'PASS',
          'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'target_sha256': EXPECTED, 'target_bytes': SIZE,
          'immutable_admission': 'All target content/section/PT_LOAD/FDE/cuts derive from one full-digest-admitted immutable bytes object. GNU receives only owned tiny copies; original target pathname is not reopened.',
          'primary_mapping': primary_map, 'caller_boundary_mapping': caller_map,
          'selected_caller_mapping': selected_map, 'selected_FDE_records': {hex(k): v[0] for k, v in wanted.items()},
          'index_entry_count_metadata_not_function_denominator': count,
          'padding_bytes_excluded_from_primary': padding.hex(), 'native_exports': exports,
          'objdump': {'path': str(objdump), 'sha256': tool_before, 'version': version},
          'headroom_before': headroom, 'captured_target_emulator_compiler_or_public_execution': False,
          'limits': '85-byte primary semantics only. Full1301-byte caller decode is boundary evidence for seven selected31-byte instructions, not caller semantics/closure or a function census. No original Rust identity, runtime or machine-code reconstruction.'}
(OUT / 'ADMISSION.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': 'PASS', 'primary_bytes': 85, 'primary_rows': 30,
                  'separate_context_bytes': 31, 'boundary_only_caller_bytes': len(caller),
                  'admission_sha256': sha((OUT / 'ADMISSION.json').read_bytes())}))
