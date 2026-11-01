#!/usr/bin/env python3
"""RE-002: two fixed, build-only published-bitcode PadAdapter probes.

Only the wrapper is independently authored Rust. Objects are parsed, never
loaded/executed. Existing-output inspection does not authenticate build origin.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import time

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-libcore-pad-codegen'
SOURCE = ROOT / 'src/libcore-pad-codegen/pad_probe.rs'
SOURCE_SHA = 'f3f7a9bee3726a4244561f5334caf85bcca7761c42eed1e7e0fd38aa5067f9ac'
PINS_SHA = 'b5117c601b68d621b5c5957c49c7df7b093b866e8c318766a95709aabcd65d22'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
CORE_SHA = 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
MEMBER = 'core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o'
MEMBER_SHA = '57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13'
CORE_PATH = 'lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'
SIZE, START = 622, 0x157d000
COMMON = ['--edition=2021', '--crate-type=cdylib', '--crate-name=pad_probe',
          '--target=x86_64-unknown-linux-gnu', '-Copt-level=3', '-Ccodegen-units=1',
          '-Cembed-bitcode=yes', '-Csave-temps=yes', '-Clinker=/usr/bin/cc']
LIMITS = [
    'Published LLVM bitcode regeneration; not a libcore Rust-source build.',
    'Only the fixed wrapper is independently authored Rust.',
    'No original compiler/flags/fork/ABI/runtime/whole-ELF or recovery-gate claim.',
    'Original native artifact comparison and its two LEA gaps remain separate.',
    'Linked ELF comparisons are raw only; only actual ET_REL fields are excluded.',
    'No captured or produced object is loaded or executed.',
    'Provider/path hashes observe a trusted local host, not hostile concurrent writes.',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class Elf:
    """Small symbol/RELA augmentation of the maintained section parser."""

    def __init__(self, data):
        require(type(data) is bytes, 'ELF must be immutable bytes')
        self.data = data
        self.sections = sections(data)
        self.kind, machine, version = struct.unpack_from('<HHI', data, 16)
        require(self.kind in (1, 2, 3) and machine == 62 and version == 1,
                'Unsupported ELF type/machine/version')
        shoff = struct.unpack_from('<Q', data, 40)[0]
        stride = struct.unpack_from('<H', data, 58)[0]
        for i, row in enumerate(self.sections):
            row.update(index=i, link=struct.unpack_from('<I', data, shoff+i*stride+40)[0],
                       info=struct.unpack_from('<I', data, shoff+i*stride+44)[0],
                       entsize=struct.unpack_from('<Q', data, shoff+i*stride+56)[0])
        self.segments = []
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phcount = struct.unpack_from('<HH', data, 54)
        require(not phcount or phsize == 56 and phoff+phsize*phcount <= len(data),
                'Invalid ELF program-header table')
        for i in range(phcount):
            values = struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize)
            row = dict(zip(('type', 'flags', 'offset', 'address', 'paddr',
                            'filesz', 'memsz', 'align'), values))
            require(row['filesz'] <= row['memsz'] and row['offset']+row['filesz'] <= len(data)
                    and row['address']+row['memsz'] <= 1 << 64, 'Invalid ELF segment extent')
            self.segments.append(row)

    def section(self, index):
        require(0 <= index < len(self.sections), 'ELF section index out of bounds')
        return self.sections[index]

    def contents(self, row):
        require(row['type'] != 8, 'NOBITS has no source bytes')
        return self.data[row['offset']:row['offset']+row['size']]

    def symbols(self):
        result = []
        for table in self.sections:
            if table['type'] not in (2, 11):
                continue
            require(table['entsize'] == 24 and table['size'] % 24 == 0,
                    'Invalid ELF symbol entry size')
            strings = self.section(table['link'])
            require(strings['type'] == 3, 'Symbol table does not link STRTAB')
            names = self.contents(strings)
            for i, off in enumerate(range(table['offset'], table['offset']+table['size'], 24)):
                name, info, other, sec, value, size = struct.unpack_from('<IBBHQQ', self.data, off)
                require(name < len(names), 'Symbol string offset out of bounds')
                end = names.find(b'\0', name)
                require(end >= name, 'Unterminated symbol string')
                result.append(dict(index=i, table=table['index'], name=names[name:end].decode('utf-8'),
                                   info=info, other=other, section=sec, value=value, size=size,
                                   record_file_offset=off))
        return result

    def candidates(self):
        found = {}
        for sym in self.symbols():
            if 'PadAdapter' not in sym['name'] or 'write_str' not in sym['name'] or sym['section'] == 0:
                continue
            require(sym['info'] & 15 == 2, 'Matching defined symbol is not STT_FUNC')
            sec = self.section(sym['section'])
            require(sec['type'] == 1 and sec['flags'] & 4 and sym['size'] > 0,
                    'Matching function is not nonempty executable PROGBITS')
            relative = sym['value'] if self.kind == 1 else sym['value'] - sec['address']
            require(0 <= relative and relative+sym['size'] <= sec['size'],
                    'Complete function symbol exceeds section bounds')
            key = (sym['section'], sym['value'], sym['size'])
            if key not in found:
                off = sec['offset']+relative
                body = self.data[off:off+sym['size']]
                found[key] = dict(section=sym['section'], value=sym['value'], size=sym['size'],
                                  relative=relative, file_offset=off, names=[],
                                  body_hex=body.hex(), body_sha256=sha(body))
            found[key]['names'].append(dict(name=sym['name'], table=sym['table'], index=sym['index']))
        return [found[k] for k in sorted(found)]

    def relocations(self, candidate):
        symbols = {(s['table'], s['index']): s for s in self.symbols()}
        result = []
        for table in self.sections:
            if table['info'] != candidate['section'] or table['type'] not in (4, 9):
                continue
            require(table['type'] == 4 and table['entsize'] == 24 and table['size'] % 24 == 0,
                    'Unsupported REL/RELA table on candidate section')
            require(self.section(table['link'])['type'] == 2, 'RELA does not link SYMTAB')
            for off in range(table['offset'], table['offset']+table['size'], 24):
                position, info, addend = struct.unpack_from('<QQq', self.data, off)
                # An earlier field could cross the body boundary; do not silently drop it.
                begin, end = candidate['relative'], candidate['relative']+candidate['size']
                if position < end and position+8 > begin:
                    sym = symbols.get((table['link'], info >> 32))
                    require(sym is not None, 'RELA symbol index out of bounds')
                    result.append(dict(offset=position-begin, kind=info & 0xffffffff,
                                       addend=addend, symbol=sym, record_file_offset=off))
        return result

    def address_bytes(self, address, count, executable=False):
        require(address >= 0 and count > 0, 'Invalid address extent')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and
                   (not executable or s['flags'] & 4) and
                   s['address'] <= address and address+count <= s['address']+s['size']]
        require(len(matches) == 1, 'Address has no unique allocated source section')
        row = matches[0]
        off = row['offset']+address-row['address']
        loads = [p for p in self.segments if p['type'] == 1 and
                 p['address'] <= address and address+count <= p['address']+p['filesz']]
        require(len(loads) == 1, 'Address has no unique file-backed PT_LOAD mapping')
        load = loads[0]
        require(load['offset']+address-load['address'] == off and
                bool(load['flags'] & 1) == bool(row['flags'] & 4),
                'Section/PT_LOAD file offset or executable flag differs')
        return self.data[off:off+count], off


def candidate_functions(data):
    return Elf(data).candidates()


def captured(data):
    require(type(data) is bytes and len(data) == 91774280 and sha(data) == TARGET_SHA,
            'Captured node94 size/SHA differs')
    elf = Elf(data)
    require(elf.kind == 3, 'Captured node is not ET_DYN')
    _, fdes = eh_frame_records(data)
    matches = [f for f in fdes if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == START+SIZE, 'Captured FDE extent differs')
    body, off = elf.address_bytes(START, SIZE, executable=True)
    require(body[555:558] == bytes.fromhex('488d35'), 'Captured four-space RIP instruction differs')
    literal_va = START+562+struct.unpack_from('<i', body, 558)[0]
    literal, literal_off = elf.address_bytes(literal_va, 4)
    require(literal == b'    ', 'Captured four-space referent differs')
    return dict(body=body, start=START, end=START+SIZE, file_offset=off,
                fde=matches[0], body_sha256=sha(body), four_spaces=dict(
                    address=literal_va, file_offset=literal_off, hex=literal.hex()))


def core_member(data):
    require(type(data) is bytes and len(data) == 2917630 and sha(data) == CORE_SHA,
            'Published libcore size/SHA differs')
    require(data[:8] == b'!<arch>\n', 'Expected GNU ar')
    pos, names, selected = 8, None, []
    while pos < len(data):
        head = data[pos:pos+60]
        require(len(head) == 60 and head[58:] == b'`\n', 'Invalid ar header')
        label, length = head[:16].decode('ascii').strip(), head[48:58].decode('ascii').strip()
        require(length.isdigit(), 'Invalid ar member length')
        end = pos+60+int(length)
        require(end <= len(data), 'Truncated ar member')
        raw = data[pos+60:end]
        if label == '//':
            require(names is None, 'Duplicate ar name table')
            names = raw
        elif label != '/':
            if label.startswith('/'):
                require(label[1:].isdigit() and names is not None, 'Unsupported ar name')
                name_off = int(label[1:]); stop = names.find(b'/\n', name_off)
                require(0 <= name_off < len(names) and stop >= name_off, 'Invalid ar long name')
                name = names[name_off:stop].decode('utf-8')
            else:
                name = label.removesuffix('/')
            if name == MEMBER:
                selected.append(raw)
        pos = end+(int(length) & 1)
    require(pos == len(data) and len(selected) == 1 and sha(selected[0]) == MEMBER_SHA,
            'Published libcore selected member differs')
    return selected[0]


def compare_candidate(data, candidate, target_body):
    require(type(target_body) is bytes and len(target_body) == SIZE, 'Expected complete captured body')
    elf = Elf(data)
    actual = [c for c in elf.candidates() if c == candidate]
    require(len(actual) == 1, 'Candidate is not bound to this ELF')
    body = bytes.fromhex(candidate['body_hex'])
    record = dict(size=len(body), body_sha256=sha(body), complete_comparable=len(body) == SIZE,
                  raw_difference_offsets=[i for i in range(max(len(body), SIZE))
                                          if body[i:i+1] != target_body[i:i+1]],
                  LEA_hex=body[464:468].hex(), actual_relocations=[], comparison='raw_only')
    if len(body) != SIZE:
        return record
    if elf.kind != 1:
        # A linked displacement is not an actual code relocation field.
        require(body[555:558] == bytes.fromhex('488d35'), 'Linked literal instruction differs')
        address = candidate['value']+562+struct.unpack_from('<i', body, 558)[0]
        literal, off = elf.address_bytes(address, 4)
        require(literal == b'    ', 'Linked four-space referent differs')
        record['linked_referent'] = dict(address=address, file_offset=off, hex=literal.hex())
        return record
    fields = elf.relocations(candidate)
    require(len(fields) == 1, 'Expected exactly one actual code RELA on complete adapter')
    field = fields[0]
    require((field['offset'], field['kind'], field['addend']) == (558, 2, -4),
            'Actual PC32 field offset/type/addend differs')
    symbol = field['symbol']; section = elf.section(symbol['section'])
    require(symbol['info'] & 15 == 1 and symbol['size'] == 4 and section['type'] == 1 and
            section['flags'] & 2 and not section['flags'] & 4 and
            0 <= symbol['value'] and symbol['value']+4 <= section['size'],
            'PC32 referent is not a bounded four-byte allocated data OBJECT')
    literal = elf.contents(section)[symbol['value']:symbol['value']+4]
    require(literal == b'    ', 'Actual RELA four-space referent differs')
    require(body[555:558] == bytes.fromhex('488d35'), 'Actual RELA instruction family differs')
    field.update(width=4, referent_hex=literal.hex(), referent_sha256=sha(literal))
    masked = set(range(558, 562))
    differences = [i for i in range(SIZE) if i not in masked and body[i] != target_body[i]]
    record.update(comparison='actual_ET_REL_fields_only', actual_relocations=fields,
                  field_bytes=4, non_RELA_bytes=618, equal_non_RELA_bytes=618-len(differences),
                  non_RELA_difference_offsets=differences)
    return record


def inspect_existing(default_dir, thin_dir, target, core):
    bound = captured(target); member = core_member(core)
    original = candidate_functions(member)
    require(len(original) == 1, 'Published native adapter symbol is ambiguous')
    output = dict(build_provenance='UNQUALIFIED', target_sha256=sha(target),
                  captured={k: v for k, v in bound.items() if k != 'body'},
                  original_native=dict(archive_sha256=sha(core), member_sha256=sha(member),
                                       candidate=original[0], comparison=compare_candidate(member, original[0], bound['body'])),
                  recipes={}, limitations=LIMITS)
    for name, directory in [('default', Path(default_dir)), ('thin', Path(thin_dir))]:
        files, candidates, elf_files = [], [], []
        require(directory.is_dir(), 'Missing recipe output directory')
        for path in sorted(directory.rglob('*')):
            require(not path.is_symlink(), 'Output contains a symlink')
            if not path.is_file():
                continue
            data = path.read_bytes(); rel = str(path.relative_to(directory))
            files.append(dict(path=rel, bytes=len(data), sha256=sha(data)))
            if data[:4] != b'\x7fELF':
                continue
            elf = Elf(data); rows = elf.candidates()
            elf_files.append(dict(path=rel, kind=elf.kind, candidate_count=len(rows)))
            for row in rows:
                candidates.append(dict(path=rel, artifact_sha256=sha(data), ELF_type=elf.kind,
                                       candidate=row, comparison=compare_candidate(data, row, bound['body'])))
        output['recipes'][name] = dict(files=files, ELF_files=elf_files, candidates=candidates)
    return output


def recipes(rustc, source, output):
    return [dict(name=name, argv=[str(rustc), *COMMON, str(source), *extra,
                                  '--out-dir', str(Path(output)/name)])
            for name, extra in [('default', []), ('thin', ['-Clto=thin'])]]


def provider(prefix):
    raw = (PACKET/'provider-pins.json').read_bytes()
    require(sha(raw) == PINS_SHA, 'Provider pin manifest differs')
    rows = []
    for item in json.loads(raw)['records']:
        path = Path(prefix)/item['path'] if item['scope'] == 'prefix' else Path(item['path'])
        data = path.read_bytes()
        actual = dict(item, bytes=len(data), sha256=sha(data), mode=oct(path.stat().st_mode & 0o777))
        require(actual == item, 'Pinned provider input differs: '+str(path))
        rows.append(actual)
    return rows


def headroom():
    limit = Path('/sys/fs/cgroup/memory.max').read_text().strip()
    require(limit.isdigit(), 'A finite cgroup memory limit is required')
    return int(limit)-int(Path('/sys/fs/cgroup/memory.current').read_text())


def run_recipe(recipe, directory, environment):
    directory.mkdir()
    argv = ['/usr/bin/strace', '-f', '-qq', '-e', 'trace=openat,execve', '-o',
            str(directory/'open-exec.trace'), '/usr/bin/taskset', '--cpu-list', '0', *recipe['argv']]
    require(headroom() > 1 << 30, 'Build requires more than1GiB cgroup headroom')
    started = time.monotonic(); minimum = headroom(); stopped = False; stop_reason = None
    with (directory/'stdout').open('xb') as stdout, (directory/'stderr').open('xb') as stderr:
        process = subprocess.Popen(argv, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        while process.poll() is None:
            minimum = min(minimum, headroom())
            if minimum < 1 << 30 or time.monotonic()-started > 60:
                stop_reason = 'memory_headroom' if minimum < 1 << 30 else '60_second_wall_time'
                stopped = True; os.killpg(process.pid, signal.SIGTERM); break
            time.sleep(.1)
        try:
            code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); code = process.wait()
    result = dict(name=recipe['name'], argv=argv, exit=code, stopped=stopped, stop_reason=stop_reason,
                  seconds=round(time.monotonic()-started, 3), minimum_headroom=minimum)
    write_json(directory/'build-result.json', result)
    require(code == 0 and not stopped, 'Fixed recipe failed; stop without tuning or retry')
    return result


def trace_observation(directory, prefix, pins):
    """Retain observed tool/input identities, not an adversarial sandbox claim."""
    raw = (directory/'open-exec.trace').read_bytes(); text = raw.decode('utf-8')
    executed, opened = set(), set()
    for line in text.splitlines():
        match = re.search(r'execve\(("(?:[^"\\]|\\.)*"),.*= 0$', line)
        if match:
            executed.add(json.loads(match.group(1)))
        match = re.search(r'openat\([^,]+, ("(?:[^"\\]|\\.)*"), .*?= (\d+)', line)
        if match:
            value = json.loads(match.group(1)); path = Path(value)
            if path.is_absolute() and path.is_file() and not path.is_relative_to(directory):
                if value.startswith(('/usr/', '/lib/', '/etc/')) or path.is_relative_to(prefix):
                    opened.add(str(path))
    allowed = {str(prefix/'bin/rustc'), str(prefix/'lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld'),
               str(prefix/'lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld'),
               '/usr/bin/cc', '/usr/bin/taskset', '/usr/libexec/gcc/x86_64-linux-gnu/14/collect2'}
    require(executed <= allowed, 'Unexpected executed program in compiler trace')
    admitted = {}
    for item in pins:
        path = prefix/item['path'] if item['scope'] == 'prefix' else Path(item['path'])
        admitted[str(path.resolve())] = (item['bytes'], item['sha256'])
    inputs = []
    for value in sorted(opened):
        path = Path(value); data = path.read_bytes()
        require(admitted.get(str(path.resolve())) == (len(data), sha(data)),
                'Observed runtime/link input lacks a matching prebuild pin: '+value)
        inputs.append(dict(path=value, bytes=len(data), sha256=sha(data)))
    return dict(raw_trace_sha256=sha(raw), executed=sorted(executed), observed_open_inputs=inputs,
                scope='Successful recorded openat/execve only; no file contents/environment captured; trusted host')


def build(prefix, node, output):
    prefix, output = Path(prefix).resolve(), Path(output).resolve()
    require(not output.exists(), 'Output already exists; no inputs read or files overwritten')
    require(output.is_relative_to(Path('/tmp')), 'Build output must be a private physical /tmp path')
    require(sha(SOURCE.read_bytes()) == SOURCE_SHA, 'Fixed wrapper source differs')
    source_inputs = [Path(__file__).resolve(), ROOT/'tools/elf_index.py', ROOT/'tools/fde_extents.py',
                     SOURCE, PACKET/'provider-pins.json']
    source_before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in source_inputs}
    before = provider(prefix)
    target, core = Path(node).read_bytes(), (prefix/CORE_PATH).read_bytes()
    captured(target); core_member(core)
    require(headroom() > 1 << 30 and 0 in os.sched_getaffinity(0), 'Resource/CPU preflight differs')
    output.mkdir(); (output/'tmp').mkdir()
    environment = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', TZ='UTC', TMPDIR=str(output/'tmp'))
    commands = recipes(prefix/'bin/rustc', SOURCE, output)
    freeze = dict(source_sha256=SOURCE_SHA, source=str(SOURCE), commands=commands, environment=environment,
                  target_sha256=sha(target), core_sha256=sha(core), provider=before,
                  source_inputs=source_before, wall_time_limit_per_recipe_seconds=60)
    write_json(output/'freeze.json', freeze)
    try:
        results = [run_recipe(command, output/command['name'], environment) for command in commands]
        report = inspect_existing(output/'default', output/'thin', target, core)
        after = provider(prefix)
        require(before == after and source_before == {
            str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in source_inputs}, 'Build inputs changed')
        observations = {name: trace_observation(output/name, prefix, before) for name in ('default', 'thin')}
        report.update(build_provenance='CONTROLLED_FIXED_RECIPES_TRUSTED_HOST', build_results=results,
                      freeze_sha256=sha((output/'freeze.json').read_bytes()),
                      provider_before_after_equal=True, link_observations=observations)
        write_json(output/'report.json', report)
        return report
    except Exception as error:
        write_json(output/'failure.json', dict(error=str(error), source_sha256=SOURCE_SHA))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    builder = modes.add_parser('build')
    builder.add_argument('--prefix', type=Path, required=True)
    inspector = modes.add_parser('inspect')
    inspector.add_argument('--default-dir', type=Path, required=True)
    inspector.add_argument('--thin-dir', type=Path, required=True)
    inspector.add_argument('--core', type=Path, required=True)
    for command in (builder, inspector):
        command.add_argument('--node', type=Path, required=True)
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == 'build':
        result = build(args.prefix, args.node, args.output)
    else:
        require(not args.output.exists(), 'Output already exists; no inputs read or files overwritten')
        result = inspect_existing(args.default_dir, args.thin_dir, args.node.read_bytes(), args.core.read_bytes())
        write_json(args.output, result)
    print(json.dumps(dict(build_provenance=result['build_provenance'],
                          candidates={k: len(v['candidates']) for k, v in result['recipes'].items()})))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, UnicodeError, struct.error) as error:
        print('libcore_pad_codegen: '+str(error), file=sys.stderr)
        raise SystemExit(1)
