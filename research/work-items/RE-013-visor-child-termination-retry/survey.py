#!/usr/bin/env python3
"""Authenticate and export four bounded static Visor ranges. No target execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

TARGET = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
RANGES = {
    'termination': (0x5e2d70, 0x5e334e),
    'tagged-error-drop': (0x5d8610, 0x5d86e1),
    'duration': (0x330360, 0x330581),
    'wait-wrapper': (0x67f160, 0x67f290),
}
SLOTS = {
    0x7e4f38: 'close', 0x7e5490: 'syscall',
    0x7e5900: '__errno_location', 0x7e6628: 'clock_nanosleep',
    0x7e7740: 'kill', 0x7e7df8: 'waitpid',
    0x7e53c8: 0x330360, 0x7e5f88: 0x3d8d70,
}

class InvalidEvidence(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

class Image:
    def __init__(self, data):
        require(len(data) == SIZE and sha(data) == TARGET, 'Wrong full Visor identity')
        self.data = data
        require(data[:7] == b'\x7fELF\x02\x01\x01', 'Expected ELF64 little endian')
        require(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64')
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
        require(phsize == 56 and shsize == 64, 'Unexpected ELF table sizes')
        self.loads = []
        for i in range(phnum):
            entry = struct.unpack('<IIQQQQQQ', self.cut(phoff + i * phsize, phsize))
            if entry[0] == 1:
                self.loads.append((entry[2], entry[3], entry[5]))
        self.sections = [struct.unpack('<IIQQQQIIQQ', self.cut(shoff + i * shsize, shsize))
                         for i in range(shnum)]

    def cut(self, offset, length):
        require(offset >= 0 and length >= 0 and offset + length <= len(self.data),
                'ELF byte extent outside the admitted image')
        return self.data[offset:offset + length]

    def at(self, address, length):
        offsets = [offset + address - va for offset, va, size in self.loads
                   if va <= address and address + length <= va + size]
        require(len(offsets) == 1, 'VA lacks one file-backed PT_LOAD mapping')
        return self.cut(offsets[0], length)

    def relocations(self):
        result = {slot: [] for slot in SLOTS}
        for section in self.sections:
            if section[1] != 4:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'Unexpected RELA records')
            for offset in range(section[4], section[4] + section[5], 24):
                slot, info, addend = struct.unpack('<QQq', self.cut(offset, 24))
                if slot not in result:
                    continue
                symbol_index, kind = info >> 32, info & 0xffffffff
                symbol = ''
                if symbol_index:
                    symbols = self.sections[section[6]]
                    require(symbols[9] == 24, 'Unexpected ELF symbol size')
                    symbol_offset = symbols[4] + symbol_index * 24
                    require(symbol_offset + 24 <= symbols[4] + symbols[5], 'Symbol outside table')
                    name = struct.unpack('<I', self.cut(symbol_offset, 4))[0]
                    strings = self.sections[symbols[6]]
                    require(name < strings[5], 'Symbol name outside string table')
                    table = self.cut(strings[4], strings[5])
                    end = table.find(b'\0', name)
                    require(end >= 0, 'Unterminated ELF symbol')
                    symbol = table[name:end].decode('utf-8')
                result[slot].append({'slot': hex(slot), 'type': kind, 'symbolIndex': symbol_index,
                                     'symbol': symbol, 'addend': addend})
        records = []
        for slot, expected in SLOTS.items():
            require(len(result[slot]) == 1, 'Relocation slot is absent or ambiguous')
            row = result[slot][0]
            if isinstance(expected, str):
                require(row['type'] == 6 and row['symbol'] == expected and row['addend'] == 0,
                        'Imported symbol binding differs')
            else:
                require(row['type'] == 8 and row['symbolIndex'] == 0 and row['addend'] == expected,
                        'Relative callee binding differs at ' + hex(slot))
            records.append(row)
        return records

def command(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60,
                            env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0, 'Native provider failed: ' + args[0])
    return result.stdout.decode('utf-8')

def native_rows(text, image, start, end):
    rows = []
    cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
        if not match:
            continue
        address = int(match[1], 16)
        raw = bytes.fromhex(match[2])
        require(address == cursor and raw and cursor + len(raw) <= end,
                'Native export is not a complete contiguous range')
        require(raw == image.at(address, len(raw)), 'Native instruction bytes differ')
        require('(bad)' not in match[3], 'Native decoder reports a bad instruction')
        rows.append({'va': hex(address), 'bytes': raw.hex(), 'instruction': match[3].strip()})
        cursor += len(raw)
    require(cursor == end and rows, 'Native export leaves missing bytes')
    return rows

def collect(binary):
    image = Image(Path(binary).read_bytes())
    relocations = image.relocations()
    require(image.at(0x6e5f8, 8) == bytes.fromhex('000000000000f03f'), 'Fixed duration differs')
    require(image.at(0x6df30, 16) == b'pkill run-client', 'Command-context literal differs')
    files = {}
    with tempfile.TemporaryDirectory(prefix='visor-retry-static-') as temporary:
        root = Path(temporary)
        snapshot = root / 'visor.elf'
        snapshot.write_bytes(image.data)
        snapshot.chmod(0o400)
        versions = {tool: command([tool, '--version'], root).splitlines()[0]
                    for tool in ['readelf', 'objdump']}
        require(all('2.42' in value for value in versions.values()), 'Use retained GNU 2.42 recipe')
        frames = command(['readelf', '-W', '--debug-dump=frames', 'visor.elf'], root)
        blocks = re.split(r'\n\s*\n', frames)
        ranges = []
        for label, (start, end) in RANGES.items():
            matched = []
            for block in blocks:
                match = re.search(r'FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)', block)
                if match and int(match[2], 16) == start:
                    matched.append((int(match[3], 16), match[1], block))
            require(len(matched) == 1 and matched[0][0] == end, 'Exact FDE extent differs')
            _, cie, fde = matched[0]
            cies = [block for block in blocks if re.match(r'^\s*' + cie + r'\s+.*\bCIE\b', block)]
            require(len(cies) == 1, 'CIE record is missing or ambiguous')
            listing = command(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                               '--start-address=' + hex(start), '--stop-address=' + hex(end),
                               'visor.elf'], root)
            rows = native_rows(listing, image, start, end)
            files['records/' + label + '.txt'] = listing.encode()
            files['records/' + label + '.fde.txt'] = (fde + '\n').encode()
            files['records/cie-' + cie + '.txt'] = (cies[0] + '\n').encode()
            ranges.append({'label': label, 'start': hex(start), 'end': hex(end), 'bytes': end - start,
                           'sha256': sha(image.at(start, end - start)), 'cieOffset': cie, 'rows': rows})
        readelf_relocations = command(['readelf', '-Wr', 'visor.elf'], root)
        selected = []
        for slot in SLOTS:
            found = [line for line in readelf_relocations.splitlines()
                     if re.match(r'^0*' + f'{slot:x}' + r'\s', line)]
            require(len(found) == 1, 'Native relocation record is missing or ambiguous')
            selected.extend(found)
        files['records/relocations.txt'] = ('\n'.join(selected) + '\n').encode()
        require(snapshot.read_bytes() == image.data, 'Private snapshot changed during analysis')
    summary = {'schema': 'visor-child-retry-static-1', 'targetSha256': TARGET, 'targetBytes': SIZE,
               'versions': versions, 'ranges': ranges, 'relocations': relocations,
               'durationLiteral': {'va': '0x6e5f8', 'bytes': image.at(0x6e5f8, 8).hex(), 'binary64': 1.0},
               'commandContext': {'va': '0x6df30', 'bytes': image.at(0x6df30, 16).hex(), 'length': 16},
               'rangeBytes': sum(row['bytes'] for row in ranges),
               'instructionRows': sum(len(row['rows']) for row in ranges),
               'scope': 'Static native exports and bindings; no instruction evaluator, target execution, recovered function count or gate.'}
    files['summary.json'] = json_bytes(summary)
    return files

def write_new(output, files):
    output = Path(output)
    require(not output.exists(), 'Existing output must be preserved')
    output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Existing output must be preserved')
        files = collect(args.binary)
        write_new(args.output, files)
        print(json.dumps({'files': len(files), 'output': str(args.output)}))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
