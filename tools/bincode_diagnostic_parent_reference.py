#!/usr/bin/env python3
"""Independent certificate-derived observer for the chosen field callback API.

This evaluates finite normal-callback contracts, not CPU instructions, registers,
native memory or a renderer.  The parent call-prefix choices come from the
authenticated producer's five flat and nine pretty certificates.  The supplied
test callbacks have explicit effects; their returned bytes, including ignored
inner request failures, are inputs.  No production Rust is imported or read.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_SIZE = 91774280
MASK = (1 << 64) - 1
WIRE_VERSION = 'field-parent-observable/1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _load_producer(repo):
    tools = Path(repo) / 'tools'
    # The preserved producer has ordinary project-authored sibling imports.
    # There is no loading of the new Rust controller/driver or any target code.
    sys.path.insert(0, str(tools))
    try:
        spec = importlib.util.spec_from_file_location(
            '_parent_certificate_producer', tools / 'bincode_diagnostic_field_static.py')
        require(spec is not None and spec.loader is not None, 'Missing original producer')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def certificate(binary, *, repo=None):
    """Read once; every native-parser/literal fact uses the same admitted bytes.

    The preserved collector writes only its selected390/622-byte raw spans to
    native tools. No captured image is executed or made into a fixture. Admission
    is for the exact immutable object, not an atomic pathname-stability claim.
    """
    repo = Path(repo) if repo is not None else ROOT
    with Path(binary).open('rb') as stream:
        data = stream.read()
    require(type(data) is bytes and len(data) == TARGET_SIZE
            and digest(data) == TARGET_SHA256, 'Unauthenticated immutable node94 image')
    producer = _load_producer(repo)
    proof, _native = producer._analyze(data)
    selected = {
        'flat': proof['flat_paths'],
        'pretty': proof['pretty_contract']['normal_return_paths'],
        'facts': proof['operand_facts'],
        'pretty_facts': proof['pretty_contract']['operand_facts'],
        'adapter_facts': proof['used_adapter_contract']['operand_facts'],
        'adapter_certificates': proof['used_adapter_contract']['certificates'],
        'adapter_protocol': proof['used_adapter_contract']['write_protocol'],
    }
    require(len(selected['flat']) == 5 and len(selected['pretty']) == 9,
            'Changed parent certificate inventory')
    require(set(selected['adapter_facts']['delimiters'].values()) == {10},
            'Changed native LF delimiter')
    selected['call_roles'] = {
        str(k): v for k, v in (producer.CALL_ROLES | producer.PRETTY_CALL_ROLES).items()}
    return selected


def _uint(text, bits):
    require(text.isascii() and text.isdecimal(), 'Expected unsigned decimal')
    value = int(text)
    require(value < 1 << bits, 'Unsigned field out of range')
    return value


def _hex(text):
    require(len(text) % 2 == 0 and all(c in '0123456789abcdef' for c in text),
            'Expected lowercase byte hex')
    return bytes.fromhex(text)


def _map(text):
    if not text:
        return {}
    pairs = [tuple(_uint(v, 64) for v in item.split(':')) for item in text.split(',')]
    require(all(len(p) == 2 for p in pairs) and len(dict(pairs)) == len(pairs),
            'Malformed or duplicate method map')
    return dict(pairs)


def _action(text):
    require(bool(text), 'Empty callback action')
    code = text[0]
    if code in 'EHFN':
        value = _uint(text[1:], 8)
        require(code != 'F' or value < 3, 'Formatter identity out of range')
        return code, value
    require(code in 'DTUMV' and '=' in text, 'Unknown callback action')
    key, value = text[1:].split('=')
    key, value = _uint(key, 64), _uint(value, 64)
    require(code not in 'DTU' or key < 3, 'Formatter identity out of range')
    return code, key, value


def _writer_plan(text):
    status, actions = text.split('/')
    return {'al': _uint(status, 8),
            'actions': [_action(a) for a in actions.split(',')] if actions else []}


def _value_plan(text):
    status, operations = text.split('/')
    result = 'l' if status == 'l' else _uint(status, 8)
    ops = []
    for op in operations.split('!') if operations else []:
        ops.append(('Q', _hex(op[1:])) if op.startswith('Q') else _action(op))
    return {'return': result, 'ops': ops}


def parse_stimulus(line):
    """Decode only supplied environment values; no expected trace/phase tags."""
    fields = line.split('|')
    require(len(fields) == 10, 'Expected ten stimulus fields')
    ident, state, formatters, methods, descriptors, calls, writers, wd, values, gd = fields
    require(ident and ident.isascii() and all(c.isalnum() or c in '_-' for c in ident),
            'Invalid stimulus identifier')
    state = tuple(_uint(v, 8) for v in state.split(':'))
    require(len(state) == 3 and state[2] < 3, 'Invalid initial state')
    words = [list(_uint(v, 64) for v in f.split(':')) for f in formatters.split(',')]
    require(len(words) == 3 and all(len(f) == 3 for f in words), 'Need three writer objects')
    invocations = []
    for item in calls.split(';'):
        name, data, desc = item.split(':')
        invocations.append((_hex(name), _uint(data, 64), _uint(desc, 64)))
    return {
        'id': ident, 'state': list(state), 'formatters': words,
        'methods': _map(methods), 'descriptors': _map(descriptors), 'calls': invocations,
        'writers': [_writer_plan(p) for p in writers.split(';')] if writers else [],
        'writer_default': _writer_plan(wd),
        'values': [_value_plan(p) for p in values.split(';')] if values else [],
        'value_default': _value_plan(gd),
    }


def _none(value):
    return '-' if value is None else str(value)


class Observer:
    """Observable logical callback effects under certified finite call prefixes.

    These are chosen API cells and supplied proxy operations.  There is no PC,
    native register file, address memory, instruction stepping or target run.
    """

    def __init__(self, cert, stimulus):
        self.cert = cert
        self.case = copy.deepcopy(stimulus)
        self.state = self.case['state']
        self.words = self.case['formatters']
        self.methods = self.case['methods']
        self.descriptors = self.case['descriptors']
        self.events = []
        self.wi = self.gi = 0
        self.paths = []

    def _apply(self, action, flag):
        code = action[0]
        if code in 'EHF':
            self.state['EHF'.index(code)] = action[1]
        elif code == 'N':
            if flag is not None:
                flag[0] = action[1]
        elif code in 'DTU':
            self.words[action[1]]['DTU'.index(code)] = action[2]
        elif code in 'MV':
            (self.methods if code == 'M' else self.descriptors)[action[1]] = action[2]
        else:
            raise ValueError('Unsupported supplied callback effect')

    def _writer(self, destination, table, payload, flag):
        index = self.wi
        self.wi += 1
        plan = (self.case['writers'][index] if index < len(self.case['writers'])
                else self.case['writer_default'])
        method = self.methods.get(table, 0)
        before = self.state.copy()
        n_before = flag[0] if flag is not None else None
        for action in plan['actions']:
            self._apply(action, flag)
        n_after = flag[0] if flag is not None else None
        parts = ['w', index, destination, table, method, payload.hex(),
                 _none(n_before), plan['al'], _none(n_after), *before, *self.state]
        self.events.append(':'.join(map(str, parts)))
        return plan['al']

    def _adapter(self, payload, context):
        """LF-index cuts, from admitted native delimiter and PRE-store facts.

        Deliberately not the Rust split_inclusive implementation. All chunks
        are explicit index intervals; terminal LF has no empty trailing piece.
        """
        facts = self.cert['adapter_facts']
        delimiter = next(iter(facts['delimiters'].values()))
        ends = [i + 1 for i, byte in enumerate(payload) if byte == delimiter]
        if not ends or ends[-1] != len(payload):
            ends.append(len(payload))
        start = 0
        flag = context['flag']
        destination, table = context['words'][:2]
        for end in ends:
            if start == end:
                continue
            if flag[0] != facts['flag_compare']:
                indentation = bytes.fromhex(facts['indentation']['bytes_hex'])
                if self._writer(destination, table, indentation, flag) != 0:
                    return facts['failure_AL']
            # The native flag-store certificate is PRE payload callback.
            flag[0] = int(payload[end - 1] == delimiter)
            if self._writer(destination, table, payload[start:end], flag) != 0:
                return facts['failure_AL']
            start = end
        return 0

    def _snapshot(self, context):
        flat = context['kind'] == 'f'
        words = self.words[context['old_f']] if flat else context['words']
        return [context['kind'], context['old_f'] if flat else '-', *words,
                _none(None if flat else context['flag'][0]), *self.state]

    def _request(self, payload, context):
        if context['kind'] == 'f':
            destination, table = self.words[context['old_f']][:2]
            return self._writer(destination, table, payload, None)
        return self._adapter(payload, context)

    def _value(self, data, descriptor, context):
        index = self.gi
        self.gi += 1
        plan = (self.case['values'][index] if index < len(self.case['values'])
                else self.case['value_default'])
        method = self.descriptors.get(descriptor, 0)
        self.events.append(':'.join(map(str, ['g', index, data, descriptor, method,
                                             *self._snapshot(context)])))
        last = qi = 0
        for operation in plan['ops']:
            if operation[0] == 'Q':
                payload = operation[1]
                last = self._request(payload, context)
                self.events.append(':'.join(map(str, ['q', index, qi, payload.hex(), last,
                                                     *self._snapshot(context)])))
                qi += 1
            else:
                self._apply(operation, context.get('flag'))
        result = last if plan['return'] == 'l' else plan['return']
        self.events.append(':'.join(map(str, ['v', index, result, *self._snapshot(context)])))
        return result

    @staticmethod
    def _compatible(path, known):
        return all(g['value'] not in known or known[g['value']] == g['zero']
                   for g in path['guards'])

    def _finish(self, path, results, call_index):
        for store in path['ordered_state_stores']:
            if store['offset'] == self.cert['facts']['error_store_offset']:
                origin = store['source']
                self.state[0] = (origin['value'] if origin['kind'] == 'constant'
                                 else results[origin['call_site']])
            else:
                require(store['offset'] == self.cert['facts']['field_store_offset'],
                        'Unbound state-store role')
                self.state[1] = store['constant']
        require(path['return'] == 'original state pointer', 'Changed return certificate')
        self.events.append(':'.join(map(str, ['r', call_index, 1, *self.state])))

    def _call(self, invocation, call_index):
        name, data, descriptor = invocation
        entry_error = self.state[0]
        known = {'entry_error': entry_error == self.cert['facts']['entry_compare']}
        old_f = sampled_h = None
        if known['entry_error']:
            old_f = self.state[2]
            sampled_h = self.state[1]
            if sampled_h not in (0, 1):
                # Chosen safe API refusal, not a target certificate/error path.
                self.paths.append('chosen-domain-refusal')
                self.events.append(':'.join(map(str, ['r', call_index, 0, *self.state])))
                return
            f = self.cert['facts']
            bit = (f['mode_offset'] - 16) * 8
            known['mode_bit'] = self.words[old_f][2] & (f['mode_mask'] << bit) == 0
            known['pretty_H'] = sampled_h == 0
        candidates = self.cert['flat'] + self.cert['pretty']
        prefix, results, context = [], {}, None
        guard_after = {'prefix': 'prefix_AL', 'name': 'name_AL', 'colon': 'colon_AL',
                       'opening': 'pretty_opening_AL', 'adapter-name': 'pretty_name_AL',
                       'adapter-colon': 'pretty_colon_AL',
                       'value-local-formatter': 'pretty_value_AL'}
        while True:
            candidates = [p for p in candidates if self._compatible(p, known)
                          and p['calls'][:len(prefix)] == prefix]
            require(candidates, 'No admitted certificate for callback prefix')
            terminals = [p for p in candidates if p['calls'] == prefix
                         and all(g['value'] in known for g in p['guards'])]
            if terminals:
                require(len(candidates) == len(terminals) == 1, 'Ambiguous terminal certificate')
                self.paths.append(digest(canonical(terminals[0])))
                self._finish(terminals[0], results, call_index)
                return
            next_sites = {p['calls'][len(prefix)] for p in candidates
                          if len(p['calls']) > len(prefix)}
            require(len(next_sites) == 1, 'Certificates disagree on next callback contract')
            site = next_sites.pop()
            role = self.cert['call_roles'][str(site)]
            if role in ('prefix', 'name', 'colon', 'opening'):
                if role == 'prefix':
                    choices = self.cert['facts']['prefix_choices']
                    payload = bytes.fromhex(next(c['bytes_hex'] for c in choices
                                                 if c['H'] == sampled_h))
                elif role == 'name':
                    payload = name
                elif role == 'colon':
                    payload = bytes.fromhex(self.cert['facts']['colon']['bytes_hex'])
                else:
                    payload = bytes.fromhex(self.cert['pretty_facts']['opening']['bytes_hex'])
                destination, table = self.words[old_f][:2]
                result = self._writer(destination, table, payload, None)
            elif role in ('adapter-name', 'adapter-colon', 'adapter-suffix'):
                if context is None:
                    context = {'kind': 'p', 'old_f': old_f, 'words': self.words[old_f].copy(),
                               'flag': [self.cert['pretty_facts']['flag_initial_value']]}
                payload = (name if role == 'adapter-name' else bytes.fromhex(
                    self.cert['pretty_facts']['colon' if role == 'adapter-colon'
                                              else 'suffix']['bytes_hex']))
                result = self._adapter(payload, context)
            elif role in ('value', 'value-local-formatter'):
                if role == 'value':
                    context = {'kind': 'f', 'old_f': old_f}
                require(context is not None, 'Missing certified pretty setup')
                result = self._value(data, descriptor, context)
            else:
                raise ValueError('Unbound callback-contract role')
            results[site] = result
            prefix.append(site)
            if role in guard_after:
                known[guard_after[role]] = result == 0

    def observe(self):
        for index, invocation in enumerate(self.case['calls']):
            self._call(invocation, index)
        def mapping(value):
            return ','.join(f'{key}:{value[key]}' for key in sorted(value))
        words = ','.join(':'.join(map(str, f)) for f in self.words)
        return ';'.join([self.case['id'], 'S=' + ':'.join(map(str, self.state)),
                         'F=' + words, 'M=' + mapping(self.methods),
                         'V=' + mapping(self.descriptors), 'X=' + ','.join(self.events)])


def expected_stimulus(cert, stimulus):
    observer = Observer(cert, parse_stimulus(stimulus))
    trace = observer.observe()
    return trace, {'certificate_paths': observer.paths,
                   'writer_calls': observer.wi, 'value_calls': observer.gi}


def _new_case(ident, *, pretty=False, h=0, name=b'n'):
    return {'id': ident, 'state': [0, h, 0],
            'formatters': [[10, 100, (1 << 23) if pretty else 0],
                           [20, 200, 1 << 23], [30, 300, 0]],
            'methods': {100: 1000, 200: 2000, 300: 3000},
            'descriptors': {900: 9000, 901: 9010},
            'calls': [(name, 800, 900)], 'writers': [], 'writer_default': (0, []),
            'values': [], 'value_default': (0, ['Q76616c7565'])}


def stimulus_line(case):
    def methods(value):
        return ','.join(f'{k}:{value[k]}' for k in sorted(value))
    def writer(plan):
        return str(plan[0]) + '/' + ','.join(plan[1])
    def value(plan):
        return str(plan[0]) + '/' + '!'.join(plan[1])
    return '|'.join([
        case['id'], ':'.join(map(str, case['state'])),
        ','.join(':'.join(map(str, f)) for f in case['formatters']),
        methods(case['methods']), methods(case['descriptors']),
        ';'.join(f'{name.hex()}:{data}:{desc}' for name, data, desc in case['calls']),
        ';'.join(writer(p) for p in case['writers']), writer(case['writer_default']),
        ';'.join(value(p) for p in case['values']), value(case['value_default'])])


def stimuli(cert):
    """Finite semantic corpus, not an estimate of all callback/environment states."""
    cases = []
    def add(case):
        cases.append(case)
    names = [b'', b'n', b'    ', b'\n', b'a\nb\n', b'\x00\x80\xff\r\n']
    for pretty in (False, True):
        for h in (0, 1):
            for ni, name in enumerate(names):
                ident = f'base_{int(pretty)}_{h}_{ni}'
                base = _new_case(ident, pretty=pretty, h=h, name=name)
                add(base)
                trace, counts = expected_stimulus(cert, stimulus_line(base))
                require(bool(trace), 'Missing baseline trace')
                # Each actual callback cut receives noncanonical raw AL values.
                for wi in range(counts['writer_calls']):
                    for al in (2, 128, 255):
                        case = copy.deepcopy(base)
                        case['id'] = f'cut_{int(pretty)}_{h}_{ni}_{wi}_{al}'
                        case['writers'] = [(0, [])] * wi + [(al, [])]
                        add(case)
                for al in (1, 2, 128, 255):
                    case = copy.deepcopy(base)
                    case['id'] = f'value_al_{int(pretty)}_{h}_{ni}_{al}'
                    case['value_default'] = (al, ['Q76616c7565'])
                    add(case)
    for e in (1, 2, 128, 255):
        for h in (0, 1, 2, 255):
            case = _new_case(f'prior_{e}_{h}', pretty=True, h=h)
            case['state'][0] = e
            case['writer_default'] = (255, ['F2', 'E0', 'H0'])
            case['value_default'] = (128, ['Qff', 'N255'])
            add(case)
    for pretty in (False, True):
        for h in (2, 128, 255):
            case = _new_case(f'chosen_refusal_{int(pretty)}_{h}', pretty=pretty, h=h)
            add(case)
    # Changes on opening/flat prefix: cached old F, mode decision, E/H snapshots,
    # post-opening copies, fresh flat words and fresh table method resolution.
    mutations = [
        ['E255', 'H255'], ['F1'], ['D0=41', 'T0=200', 'U0=0'],
        ['D0=42', 'T0=300', 'U0=8388608'],
        ['F1', 'D0=43', 'T0=200', 'U0=0', 'D1=99', 'T1=300'],
        ['M100=77', 'V900=88'], ['M200=79', 'T0=200', 'V900=89'],
        ['E2', 'H0', 'F2', 'U0=18446744073709551615'],
    ]
    for pretty in (False, True):
        for h in (0, 1):
            for mi, actions in enumerate(mutations):
                for position in (0, 1, 2):
                    case = _new_case(f'mutate_{int(pretty)}_{h}_{mi}_{position}',
                                     pretty=pretty, h=h, name=b'x\ny')
                    case['writers'] = [(0, [])] * position + [(0, actions)]
                    case['value_default'] = (0, ['Q71', 'Q0a', 'Q720a'])
                    add(case)
    plans = [
        (0, []), (0, ['Q']), (0, ['Q20202020']), (0, ['Q0a']),
        (0, ['Q610a620a']), (0, ['Qff00800a', 'Q']),
        (0, ['N255', 'Q78', 'N255']), (0, ['Q78', 'N255']),
        (0, ['Q78', 'Q79', 'Q0a']), ('l', ['Q78', 'Q79']),
        (0, ['E255', 'H255', 'F2', 'D0=99', 'T0=200', 'U0=0',
             'M100=78', 'M200=79', 'V900=91', 'Q78', 'N255']),
    ]
    for pretty in (False, True):
        for h in (0, 1):
            for pi, plan in enumerate(plans):
                base = _new_case(f'context_{int(pretty)}_{h}_{pi}', pretty=pretty, h=h)
                base['value_default'] = plan
                add(base)
                # G may ignore a real nested error, continue, and still reach suffix.
                _, counts = expected_stimulus(cert, stimulus_line(base))
                for wi in range(counts['writer_calls']):
                    case = copy.deepcopy(base)
                    case['id'] += f'_err{wi}'
                    case['writers'] = [(0, [])] * wi + [(128, ['N255'])]
                    add(case)
    for pretty in (False, True):
        for h in (0, 1):
            for n in (0, 1, 2, 128, 255):
                case = _new_case(f'raw_n_{int(pretty)}_{h}_{n}', pretty=pretty, h=h,
                                 name=b'\n\nq\n')
                case['writer_default'] = (0, [f'N{n}'])
                case['value_default'] = (0, ['Q610a62', f'N{n}'])
                add(case)
    # Repeated invocations share real cells, object identities and action indices.
    for pretty in (False, True):
        for h in (0, 1):
            for al in (0, 2, 128, 255):
                case = _new_case(f'sequential_{int(pretty)}_{h}_{al}', pretty=pretty, h=h)
                case['calls'] = [(b'a', 800, 900), (b'', 801, 901), (b'\n', 802, 900)]
                case['values'] = [(al, ['F1', 'E255', 'H255', 'Q78'])]
                case['value_default'] = (0, ['F2', 'Q0a', 'Q79'])
                add(case)
    # Cases in different pool objects must not accidentally assume F==object0.
    for fi in (1, 2):
        for pretty in (False, True):
            case = _new_case(f'initial_identity_{fi}_{int(pretty)}', pretty=pretty)
            case['state'][2] = fi
            case['formatters'][fi][2] = (1 << 23) if pretty else 0
            case['value_default'] = (0, ['F0', f'D{fi}=18446744073709551615',
                                         f'T{fi}=300', 'Qff', 'N255'])
            add(case)
    lines = [stimulus_line(case) for case in cases]
    require(len(lines) == len(set(lines)), 'Duplicate stimulus record')
    require(len({case['id'] for case in cases}) == len(cases), 'Duplicate case identifier')
    return lines


def oracle(binary, *, repo=None):
    cert = certificate(binary, repo=repo)
    lines = stimuli(cert)
    records, outputs = [], []
    coverage = set()
    for line in lines:
        output, counts = expected_stimulus(cert, line)
        outputs.append(output)
        records.append({'id': line.split('|', 1)[0], **counts})
        coverage.update(counts['certificate_paths'])
    inputs = ('\n'.join(lines) + '\n').encode('ascii')
    expected = ('\n'.join(outputs) + '\n').encode('ascii')
    fixture = ('\n'.join(a + '\t' + b for a, b in zip(lines, outputs)) + '\n').encode('ascii')
    metadata = {
        'schema': WIRE_VERSION, 'target_sha256': TARGET_SHA256,
        'certificate_sha256': digest(canonical(cert)),
        'flat_certificates': len(cert['flat']), 'pretty_certificates': len(cert['pretty']),
        'case_count': len(lines), 'inputs_sha256': digest(inputs),
        'expected_sha256': digest(expected), 'fixture_sha256': digest(fixture),
        'used_certificate_paths': sorted(coverage),
        'expected_writer_calls': sum(r['writer_calls'] for r in records),
        'expected_value_calls': sum(r['value_calls'] for r in records),
        'domain_refusals_are_chosen_api_only': True,
        'native_execution_or_emulation': False,
        'references_production_rust': False,
    }
    require(len(coverage - {'chosen-domain-refusal'}) == 14, 'Not all native certificates covered')
    return {'metadata': metadata, 'cases': records, 'inputs': inputs,
            'expected': expected, 'fixture': fixture}
