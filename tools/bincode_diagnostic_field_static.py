#!/usr/bin/env python3
"""Static conditional call/state contract of one node94 diagnostic helper.

This extracts byte operands and CFG paths. It does not execute or emulate
target instructions, callbacks or a renderer. See ASSUMPTIONS in the packet.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import bincode_varint as bv

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = bv.SHA256
BASE, END = 0x1571F50, 0x15720D6
MODE = 0x1571F9B
COMMON = 0x1571F6D
CAPTURE = 0x15720CE
CALL_ROLES = {0x1571FC5: 'prefix', 0x1571FD9: 'name', 0x1571FF3: 'colon', 0x1572009: 'value'}
GUARDS = {0x1571F6B: 'entry_error', MODE: 'mode_bit', 0x1571FCA: 'prefix_AL',
          0x1571FDE: 'name_AL', 0x1571FF8: 'colon_AL'}
PRETTY = {0x1572011, 0x1572015, 0x1572045, 0x1572082, 0x15720A0, 0x15720B7}
WITNESS_PCS = {0x1571F61, 0x1571F64, 0x1571F67, COMMON, 0x1571F71, 0x1571F75,
               0x1571F87, 0x1571F8B, 0x1571F8F, 0x1571F92, 0x1571F97,
               0x1571F9D, 0x1571FA0, 0x1571FA3, 0x1571FA6, 0x1571FAA,
               0x1571FB1, 0x1571FB8, 0x1571FBA, 0x1571FBE, 0x1571FC1,
               0x1571FC5, 0x1571FC8, 0x1571FCC, 0x1571FCF, 0x1571FD3,
               0x1571FD6, 0x1571FD9, 0x1571FDC, 0x1571FE0, 0x1571FE3,
               0x1571FE7, 0x1571FEE, 0x1571FF3, 0x1571FF6, 0x1571FFE,
               0x1572002, 0x1572005, 0x1572009, CAPTURE}


class ContractError(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise ContractError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def native_rows(body):
    version = subprocess.run(['objdump', '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    require('GNU objdump' in version, 'GNU objdump is required')
    with tempfile.TemporaryDirectory(prefix='diagnostic-field-') as folder:
        raw = Path(folder) / 'helper.bin'
        with raw.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(BASE), str(raw)]
        text = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
        require(raw.read_bytes() == body, 'Owned raw span changed')
        text = text.replace(str(raw), '<node94-390-byte-helper>')
    rows, cursor = [], BASE
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) < 3 or not fields[0].strip().endswith(':'):
            continue
        try:
            address, value = int(fields[0].strip()[:-1], 16), bytes.fromhex(fields[1])
        except ValueError:
            continue
        require(value and address == cursor and '(bad)' not in fields[2], 'Native row tiling changed')
        require(body[address - BASE:address - BASE + len(value)] == value, 'Native row bytes changed')
        rows.append({'va': address, 'bytes': value.hex(), 'width': len(value), 'assembly': fields[2]})
        cursor += len(value)
    require(cursor == END, 'Native rows do not cover the complete390-byte helper')
    return rows, text, version, argv[:-1] + ['<owned-390-byte-helper>']


def cfg(rows):
    """Decode relative branch edges only; calls are opaque normal-return events."""
    starts = {row['va'] for row in rows}
    branches, calls, returns = {}, {}, set()
    leaders = {BASE}
    for row in rows:
        va, b = row['va'], bytes.fromhex(row['bytes'])
        conditional, kind, target = False, None, None
        if b[0] in (0x74, 0x75):
            kind, conditional = ('je' if b[0] == 0x74 else 'jne'), True
            target = va + 2 + struct.unpack('<b', b[1:2])[0]
        elif b[:2] in (b'\x0f\x84', b'\x0f\x85'):
            kind, conditional = ('je' if b[1] == 0x84 else 'jne'), True
            target = va + 6 + struct.unpack('<i', b[2:6])[0]
        elif b[0] == 0xE9:
            kind, target = 'jmp', va + 5 + struct.unpack('<i', b[1:5])[0]
        if kind:
            require(target in starts, 'Relative branch target is not an instruction boundary')
            branches[va] = {'opcode': kind, 'target': target, 'fallthrough': va + len(b) if conditional else None}
            leaders.add(target)
            if va + len(b) < END:
                leaders.add(va + len(b))
        if b[0] == 0xFF and ((b[1] >> 3) & 7) == 2:
            calls[va] = {'role': CALL_ROLES.get(va, 'opaque-pretty-route'), 'bytes': b.hex()}
        if b == b'\xc3':
            returns.add(va)
            if va + 1 < END:
                leaders.add(va + 1)
    ordered = sorted(leaders)
    blocks = {}
    for i, start in enumerate(ordered):
        stop = ordered[i + 1] if i + 1 < len(ordered) else END
        contents = [r for r in rows if start <= r['va'] < stop]
        require(contents, 'Empty basic block')
        last = contents[-1]['va']
        edges = []
        if last in branches:
            branch = branches[last]
            edges.append({'to': branch['target'], 'taken': True})
            if branch['fallthrough'] is not None:
                edges.append({'to': branch['fallthrough'], 'taken': False})
        elif last not in returns:
            require(stop < END, 'Unclosed terminal block')
            edges.append({'to': stop, 'taken': None})
        blocks[start] = {'end': stop, 'last': last, 'rows': [r['va'] for r in contents],
                         'calls': [r['va'] for r in contents if r['va'] in calls], 'edges': edges}
    return {'branches': branches, 'calls': calls, 'returns': sorted(returns), 'blocks': blocks}


def operand_facts(body, read_literal):
    def at(va, n):
        return body[va - BASE:va - BASE + n]

    def fixed(va, value, role):
        require(at(va, len(value)) == value, role + ' operand relation changed')

    def immediate(va, prefix, n=1, signed=False):
        fixed(va, prefix, f'{va:#x}')
        return int.from_bytes(at(va + len(prefix), n), 'little', signed=signed)

    def lea(va, prefix):
        return va + 7 + immediate(va, prefix, 4, True)

    fixed(0x1571F61, bytes.fromhex('4889fb'), 'Incoming state saved in rbx')
    fixed(0x1571F87, bytes.fromhex('48894dc04c8945c84c8b3b'), 'Value arguments/frame and formatter pointer')
    fixed(0x1571F9D, bytes.fromhex('4989f64989d50fb6d0'), 'Saved field name/length and H zero extension')
    for va in [0x1571FBE, 0x1571FCC, 0x1571FE0]:
        fixed(va, bytes.fromhex('498b3f498b4708'), 'Fresh formatter destination/vtable load')
    fixed(0x1571FD3, bytes.fromhex('4c89f64c89ea'), 'Name call uses saved incoming slice')
    fixed(0x1571FFE, bytes.fromhex('488b7dc04c89fe488b45c8'), 'Value callback data/formatter/descriptor arguments')
    for va in [0x1571FC8, 0x1571FDC, 0x1571FF6]:
        fixed(va, b'\x84\xc0', 'Writer return AL test')
    fixed(0x1571F75, bytes.fromhex('4889d8'), 'Return original state pointer')
    fixed(0x1571F97, bytes.fromhex('0fb643'), 'Field-present byte load')
    fixed(0x1571F92, bytes.fromhex('41f647'), 'Formatter mode-byte test')
    fixed(0x1571FBA, bytes.fromhex('480f'), 'Prefix conditional move')
    fixed(0x1571FB8, b'\x84\xc0', 'Prefix condition tests the loaded H byte')
    require(at(0x1571FBD, 1) == b'\xf1', 'Prefix conditional-move source/destination changed')
    condition = {0x44: 'eq', 0x45: 'ne'}.get(at(0x1571FBC, 1)[0], 'unsupported')
    first, later = lea(0x1571FB1, bytes.fromhex('488d35')), lea(0x1571FAA, bytes.fromhex('488d0d'))
    xor = immediate(0x1571FA6, bytes.fromhex('4883f2'), 1, True)
    choices = []
    for h in [0, 1]:
        select_later = (h != 0) if condition == 'ne' else (h == 0)
        pointer, length = (later if select_later else first), h ^ xor
        require(0 <= length <= 8, 'Prefix slice length is outside inspected control domain')
        choices.append({'H': h, 'pointer': pointer, 'length': length, 'bytes_hex': read_literal(pointer, length).hex()})
    colon = lea(0x1571FE7, bytes.fromhex('488d35'))
    colon_len = immediate(0x1571FEE, b'\xba', 4)
    require(colon_len <= 8, 'Colon slice length is outside inspected control domain')
    slots = {}
    for va in CALL_ROLES:
        fixed(va, b'\xff\x50', 'Callback target-base register')
        slots[va] = at(va + 2, 1)[0]
    fixed(CAPTURE, b'\x41\x89', 'Status result capture')
    capture = at(CAPTURE + 2, 1)[0]
    require(capture & 0xC7 == 0xC4, 'Status capture destination is not r12d')
    return {'entry_error_offset': immediate(0x1571F67, b'\x80\x7f'),
            'entry_compare': at(0x1571F6A, 1)[0],
            'initial_status': immediate(0x1571F64, b'\x41\xb4'),
            'field_present_offset': at(0x1571F9A, 1)[0],
            'mode_offset': at(0x1571F95, 1)[0], 'mode_mask': at(0x1571F96, 1)[0],
            'prefix_xor': xor, 'prefix_cmov': condition, 'prefix_choices': choices,
            'colon': {'pointer': colon, 'length': colon_len, 'bytes_hex': read_literal(colon, colon_len).hex()},
            'method_offsets': slots,
            'error_store_offset': immediate(COMMON, bytes.fromhex('448863')),
            'field_store_offset': immediate(0x1571F71, bytes.fromhex('c643')),
            'field_store_value': at(0x1571F74, 1)[0],
            'capture_source_register_index': (capture >> 3) & 7}


def flat_paths(graph, facts):
    """Enumerate acyclic CFG edges with predicates, never concrete machine state."""
    output = []

    def walk(pc, blocks, guards, calls):
        require(pc not in blocks, 'Counterfactual flat CFG contains a cycle')
        if pc in PRETTY:
            output.append({'blocks': blocks + [pc], 'guards': guards, 'calls': calls, 'scope_exit': 'pretty-route'})
            return
        block = graph['blocks'][pc]
        blocks, calls = blocks + [pc], calls + block['calls']
        last = block['last']
        if last in graph['returns']:
            # Annotate only actual path-member witnesses. A RET alone does not
            # imply that common stores or the pointer-return MOV were reached.
            pcs = [va for start in blocks for va in graph['blocks'][start]['rows']]
            origin, stores, witnesses = {'kind': 'unclosed_status_byte'}, [], []
            preceding_calls = []
            result = 'unclosed RAX value at RET'
            for va in pcs:
                if va in graph['calls']:
                    preceding_calls.append(va)
                    result = 'opaque callback result at RET'
                if va == 0x1571F64:
                    origin = {'kind': 'constant', 'value': facts['initial_status']}
                    witnesses.append(va)
                elif va == CAPTURE:
                    origin = ({'kind': 'last_callback_AL', 'call_site': preceding_calls[-1] if preceding_calls else None}
                              if facts['capture_source_register_index'] == 0 else
                              {'kind': 'unclosed_register_byte', 'register_index': facts['capture_source_register_index']})
                    witnesses.append(va)
                elif va == COMMON:
                    stores.append({'offset': facts['error_store_offset'], 'source': origin})
                    witnesses.append(va)
                elif va == 0x1571F71:
                    stores.append({'offset': facts['field_store_offset'], 'constant': facts['field_store_value']})
                    witnesses.append(va)
                elif va == 0x1571F75:
                    result = 'original state pointer'
                    witnesses.append(va)
            output.append({'blocks': blocks, 'guards': guards, 'calls': calls, 'error_origin': origin,
                           'path_rows': pcs, 'output_witness_pcs': witnesses,
                           'ordered_state_stores': stores, 'return': result})
            return
        for edge in block['edges']:
            extra = guards
            branch = graph['branches'].get(last)
            if branch and branch['opcode'] != 'jmp':
                require(last in GUARDS, 'Flat path reaches an uncharacterized conditional branch')
                zero = edge['taken'] == (branch['opcode'] == 'je')
                if last == MODE and not zero:
                    continue  # Stated domain: entry formatter mode bit is clear.
                extra = guards + [{'site': last, 'value': GUARDS[last], 'zero': zero}]
            walk(edge['to'], blocks, extra, calls)

    walk(BASE, [], [], [])
    return output


def check_contract(facts, paths):
    for key, expected in [('entry_error_offset', 8), ('entry_compare', 0), ('initial_status', 1),
                          ('field_present_offset', 9), ('mode_offset', 0x12), ('mode_mask', 0x80),
                          ('prefix_xor', 3), ('prefix_cmov', 'ne'), ('error_store_offset', 8),
                          ('field_store_offset', 9), ('field_store_value', 1), ('capture_source_register_index', 0)]:
        require(facts[key] == expected, key + ' contract changed')
    require([(v['pointer'], v['length'], v['bytes_hex']) for v in facts['prefix_choices']] ==
            [(0x252BFB, 3, '207b20'), (0x252BEF, 2, '2c20')], 'Prefix H0/H1 slice association changed')
    require(facts['colon'] == {'pointer': 0x252BFE, 'length': 2, 'bytes_hex': '3a20'}, 'Colon slice association changed')
    require(all(n == 0x18 for n in facts['method_offsets'].values()), 'Callback method slot changed')
    seen = set()
    ordered = list(CALL_ROLES)
    for path in paths:
        require('scope_exit' not in path, 'Bit-clear flat domain unexpectedly enters pretty route')
        pcs = path['path_rows']
        required = [0x1571F61, 0x1571F64, COMMON, 0x1571F71, 0x1571F75, 0x1571F86]
        require(all(va in pcs for va in required) and
                [pcs.index(va) for va in required] == sorted(pcs.index(va) for va in required),
                'Flat path output witnesses or incoming-state preservation are absent/out of order')
        require(path['ordered_state_stores'] == [{'offset': 8, 'source': path['error_origin']},
                                                 {'offset': 9, 'constant': 1}] and
                path['return'] == 'original state pointer', 'Flat path output witnesses do not establish the state/return contract')
        guards = {g['value']: g['zero'] for g in path['guards']}
        if not guards['entry_error']:
            require(path['calls'] == [] and 0x1571F87 not in path['blocks'], 'Prior error no-callback/no-formatter-read obligation changed')
            require(path['error_origin'] == {'kind': 'constant', 'value': 1}, 'Prior error normalization changed')
            seen.add('prior-error')
            continue
        require(guards.get('mode_bit') is True, 'Missing flat-mode guard')
        failure = next((i for i, name in enumerate(['prefix_AL', 'name_AL', 'colon_AL'])
                        if guards.get(name) is False), None)
        if failure is not None:
            require(path['calls'] == ordered[:failure + 1], 'First-error call ordering/short-circuit changed')
            require(path['error_origin'] == {'kind': 'constant', 'value': 1}, 'Writer error normalization changed')
            seen.add(['prefix-error', 'name-error', 'colon-error'][failure])
        else:
            require(all(guards.get(name) is True for name in ['prefix_AL', 'name_AL', 'colon_AL']), 'A writer success check was bypassed')
            require(path['calls'] == ordered, 'Successful flat call ordering changed')
            require(path['error_origin'] == {'kind': 'last_callback_AL', 'call_site': ordered[-1]}, 'Value callback AL propagation changed')
            seen.add('value-normal-return')
    require(seen == {'prior-error', 'prefix-error', 'name-error', 'colon-error', 'value-normal-return'},
            'A required normal-return/error trace is absent')


def extract_span(body, read_literal):
    """Extract static relations, including counterfactual ones; no admission claim."""
    rows, listing, version, argv = native_rows(body)
    require(WITNESS_PCS <= {row['va'] for row in rows}, 'A dataflow witness is not a native instruction boundary')
    graph = cfg(rows)
    facts = operand_facts(body, read_literal)
    paths = flat_paths(graph, facts)
    return {'span_sha256': sha(body), 'native_instruction_rows': len(rows), 'cfg': graph,
            'operand_facts': facts, 'flat_paths': paths, 'native_tool': version,
            'native_command': argv, 'concrete_instruction_execution': False}, listing


def prove_span(body, read_literal):
    proof, listing = extract_span(body, read_literal)
    check_contract(proof['operand_facts'], proof['flat_paths'])
    return proof, listing


def analyze(data):
    require(len(data) == 91774280 and sha(data) == SHA256, 'Input is not authenticated node94')
    secs = bv.sections(data)

    def off(va, n=1):
        entries = [s for s in secs.values() if s['addr'] and s['addr'] <= va and va + n <= s['addr'] + s['size']]
        require(len(entries) == 1, 'Selected VA range is not uniquely file-bound')
        return entries[0]['offset'] + va - entries[0]['addr']

    require(bv.fde_extents(data, secs).get(BASE) == END, 'Helper FDE extent changed')
    hdr = secs['.eh_frame_hdr']
    count = struct.unpack_from('<I', data, hdr['offset'] + 8)[0]
    metadata = []
    for i in range(count):
        start, record = struct.unpack_from('<ii', data, hdr['offset'] + 12 + i * 8)
        if hdr['addr'] + start != BASE:
            continue
        fde_va = hdr['addr'] + record
        fp = off(fde_va, 16)
        length, cie_pointer = struct.unpack_from('<II', data, fp)
        cie_va = fde_va + 4 - cie_pointer
        cp = off(cie_va, 8)
        cie_size = struct.unpack_from('<I', data, cp)[0] + 4
        metadata.append({'fde_va': hex(fde_va), 'fde_file_offset': hex(fp),
                         'fde_bytes': data[fp:fp + length + 4].hex(),
                         'cie_va': hex(cie_va), 'cie_bytes': data[cp:cp + cie_size].hex()})
    require(len(metadata) == 1, 'Helper FDE header binding is not unique')
    relocation_section = secs['.rela.dyn']
    selected_slots = {0x576E2C8: [], 0x576E330: [], 0x5674228: []}
    for rp in range(relocation_section['offset'], relocation_section['offset'] + relocation_section['size'], 24):
        place, info, addend = struct.unpack_from('<QQq', data, rp)
        if place in selected_slots:
            selected_slots[place].append({'record_file_offset': hex(rp), 'info': info, 'addend_va': hex(addend)})
    for slot, target in [(0x576E2C8, BASE), (0x576E330, 0x157D000), (0x5674228, 0x157D000)]:
        rows = selected_slots[slot]
        require(len(rows) == 1 and rows[0]['info'] == 8 and int(rows[0]['addend_va'], 16) == target,
                f'Selected RELATIVE binding {slot:#x} changed')
    pos = off(BASE, END - BASE)
    body = data[pos:pos + END - BASE]
    proof, listing = prove_span(body, lambda va, n: data[off(va, n):off(va, n) + n])
    proof.update({'schema': 're005-diagnostic-field-static/1',
                  'target_sha256': SHA256, 'range': [hex(BASE), hex(END)], 'file_offset': hex(pos),
                  'unwind_metadata': metadata[0],
                  'used_and_opaque_pretty_bindings': {hex(slot): rows[0] for slot, rows in selected_slots.items()},
                  'call_arguments': {
                      'prefix': {'site': '0x1571fc5', 'destination': 'fresh load64(F+0)',
                                 'target': 'fresh load64(load64(F+8)+0x18)', 'slice': 'H-dependent prefix_choices'},
                      'name': {'site': '0x1571fd9', 'destination': 'fresh load64(F+0)',
                               'target': 'fresh load64(load64(F+8)+0x18)',
                               'slice': 'incoming rsi/rdx preserved in r14/r13'},
                      'colon': {'site': '0x1571ff3', 'destination': 'fresh load64(F+0)',
                                'target': 'fresh load64(load64(F+8)+0x18)', 'slice': 'colon operand fact'},
                      'value': {'site': '0x1572009', 'data': 'incoming rcx via rbp-0x40',
                                'formatter': 'original F pointer in r15',
                                'target': 'load64(saved incoming r8 via rbp-0x38 +0x18)'}},
                  'domain': {'entry_error': 'zero/nonzero raw byte, not a recovered bool type',
                             'field_present': [0, 1], 'formatter_mode_bit': 'byte(F+0x12)&0x80 clear'},
                  'state_window_is_not_nominal_layout': True, 'pretty_route_unqualified': True,
                  'callback_alias_frame_preservation_conditions_required': True,
                  'conditions': ['Normal callback returns only; unwinding, faults, nonreturn and concurrent mutation excluded.',
                                 'Observed memory must remain valid; state writes must not corrupt helper frame/control slots.',
                                 'Callbacks preserve rbp/rbx/r12/r13/r14/r15, stack and saved value-argument slots.',
                                 'Primitive destination facts use fresh loads; a same-writer specialization additionally requires formatter/method-slot and value-descriptor preservation.',
                                 'Field-present byte0/1 is an explicit local domain, not an original Rust bool/layout claim.',
                                 'Pretty route, arbitrary callback aliases/clobbers and physical output remain unqualified.'],
                  'runtime_rendering_or_gate_claimed': False})
    return proof, listing


def generate(binary, output):
    require(not output.exists(), 'Existing evidence output is preserved')
    proof, listing = analyze(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'records.json').open('x') as stream:
        stream.write(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    with (output / 'helper.objdump.txt').open('x') as stream:
        stream.write(listing)
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        proof = generate(args.input, args.output)
    except (ContractError, bv.EvidenceError, OSError, struct.error, subprocess.SubprocessError) as error:
        print(f'bincode_diagnostic_field_static: {error}', file=sys.stderr)
        return 1
    print(json.dumps({'target_sha256': SHA256, 'flat_normal_return_paths': len(proof['flat_paths']),
                      'concrete_instruction_execution': False, 'gate_claimed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
