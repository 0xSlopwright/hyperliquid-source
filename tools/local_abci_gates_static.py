#!/usr/bin/env python3
"""Static node #94 local abci_state startup gates, checked from authenticated bytes.

Question: when node #94 starts from a local abci_state, which constants decide
(a) that the local height is "too far behind" or "from stale hardfork",
(b) the `tolerance` value it logs, and (c) the abci_state freshness check
behind `use an abci state within ... seconds`?  Where does the can1357 lead
(`node/local_abci_state.rs`, `node/startup.rs`) differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, RIP-relative LEA /
movsd / call targets, rustc format templates and the panic Location are
decoded here, with relocations taken from .rela.dyn.  Nothing from the binary
is executed.
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
STARTUP_FDE = 0x22689f0
FRESH_FDE = 0x2271d00
PANIC_SHIM = 0x157b810
ORCHESTRATOR_FDE = 0x22ae8a0
POLL_TABLE = 0x3d5f10
FUTURE_STRINGS = {0x2271f1e: b'check_reachability_firewall_ips', 0x22722c1: b'failed to load firewall ips'}

WINDOWS = {
    'gate': (STARTUP_FDE, 0x226ab0a,
             '488b8424d8000000' '483de0b1ffff' '7238' '4889c2' '4881c2204e0000' '48c7c1ffffffff' '480f43ca'
             '488db388000000' '483b8c24d0000000' '772a' '4989ee' '41bd1e000000' '488d2d62ce16fe' 'eb36'
             '488d88204e0000' '488db388000000' '483b8c24d0000000' '76d6' '483b8424c8000000' '0f8339020000'
             '4989ee' '41bd23000000' '488d2d07ce16fe'),
    'select_540': (STARTUP_FDE, 0x226900c,
                   'f20f1005c413fafd' '83bb180c000001' '0f8543010000' '483983200c0000' '0f8232070000' '0f8530010000'),
    'hardfork_log': (STARTUP_FDE, 0x226911b, '488d3d1440f8fd' '488db424103c0000' 'ff1538585003'),
    'select_840': (STARTUP_FDE, 0x226915c, 'f20f1005cc10fafd' '488d4360' 'f20f118424e0000000'),
    'tolerance_log': (STARTUP_FDE, 0x226928a,
                      '488d8424e0000000' '4889442448' '48895c2408' '4c89742420' '4c89bc2420010000'
                      '488d05301e7100' '4889842428010000' '488d842400770000' '4889842430010000'
                      '488d05c1e0f4ff' '4889842438010000' '488d442448' '4889842440010000'
                      '488d0565134400' '4889842448010000' '488d442408' '4889842450010000'
                      '488d05d91c4400' '4889842458010000' '488d4c2420' '48898c2460010000' '4889842468010000'
                      '488d3dfdc0f8fd' '488db42420010000' 'ff152f565003'),
    'freshness': (FRESH_FDE, 0x2271d52,
                  '4c8bbb40070000' '48b80000000000c08240' '4889842438010000' '498b4760' '4889842440010000'
                  '418b4768' '89842448010000' '418b4768' '898424c8000000' '498b4760' '48898424c0000000'
                  '488db424c4000000' '488d7c2410' 'ba58020000' '31c9' 'ff15f5ca4f03' '488b442418'
                  '48b9000000004057ffff' '4801c1' '48ba81aefeff7faefeff' '4839d1' '0f8295050000'
                  '448b642410' '448b742414' '8bbc24c0000000' '48b9572951cea0c8451848' 'f7e9' '4889d6'
                  '48c1ee3f' '48c1ea0d' '01d6' 'ff15a7ca4f03' '89c5' '85c0' '0f845a050000' '488d7c2410'
                  'ff1582ca4f03' '3b6c2410' '0f9dc0' '7561' '443b642414' '0f93c0' '7557' '443b742418' '7354'
                  '488d842438010000' '4889442410' '488b05cccb4f03' '4889442418' '488d842440010000'
                  '4889442420' '488b05c3d64f03' '4889442428' '488d3d23b3f7fd' '488d15d0ca4203' '488d742410'
                  'ff1515c24f03' 'e9b5090000' '84c0' '74ac'),
    'poll_entry': (FRESH_FDE, 0x2271d17,
                   '49bd0000000000000080' '0fb68756070000' '488d0de14116fe' '48630481' '4801c8' 'ffe0'
                   '4889ac2430010000' 'c6835407000000' '0fb68355070000' '8844240f'),
    'after_panic': (FRESH_FDE, 0x227283d, '0f0b'),
    'call_a': (ORCHESTRATOR_FDE, 0x22aef54, '4c89ee' '4c8db5f8210000' '4c89f7' 'e89a2dfcff' '84c0' '7409' 'b001' 'b10a' 'e96a130000'),
    'call_b': (ORCHESTRATOR_FDE, 0x22affbf,
               '0fb685e8010000' '48899d70290000' '888585290000' 'c6858629000000' '4c8db530220000' '4c89f7' '4989f5'
               'e8141dfcff' '84c0' '7409' 'b001' 'b10b' 'e9e4020000'),
    'panic_shim': (PANIC_SHIM, PANIC_SHIM,
                   '55' '4889e5' '4883ec30' '48897df0' '488975f8' '488d45f0' '488945d8' '488955e0'
                   '66c745e80100' '488d7dd8' 'ff15a44e1f04'),
}
MESSAGES = {'too_far_behind': b'local height is too far behind', 'stale_hardfork': b'local height is from stale hardfork'}
TEMPLATE_MARKERS = {
    'hardfork': b' @@ applying hardfork to frozen local abci_state @@ [abci_state.height(): ',
    'tolerance': b' @@ initializing with local abci_state @@ [tolerance: ',
    'freshness': b'use an abci state within ',
}
LOCATION_FILE = b'/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs'
TOLERANCES = (540.0, 840.0)
RSP_E0 = re.compile(rb'[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]\x24\xe0\x00\x00\x00')


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
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

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def rip(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]

    def i32(self, va):
        return struct.unpack('<i', self.read(va, 4))[0]


def windows(img):
    """Check every window's bytes and FDE containment; return VA -> bytes."""
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
    return out


def template(img, va):
    """Decode a rustc packed format template: literal-length bytes and 0xc0 placeholders, ending at 0x00."""
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            return pieces
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            lit = img.read(pos, n)
            require(all(0x20 <= c < 0x7f or c == 0x0a for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit)
            pos += n
        elif pieces and pieces[-1] is None and img.read(pos, 1)[0] != 0xc0:
            return pieces
    raise EvidenceError(f'template {va:#x}: no terminator')


def placeholder_before(pieces, literal):
    """Index of the placeholder immediately preceding `literal`."""
    idx = 0
    for i, p in enumerate(pieces):
        if p is None:
            idx += 1
        elif p == literal:
            require(i > 0 and pieces[i - 1] is None, f'literal {literal!r} is not preceded by a placeholder')
            return idx - 1
    raise EvidenceError(f'literal {literal!r} not in template')


def check_gate(img):
    va = WINDOWS['gate'][1]
    add = img.i32(va + 0x16)
    require(add == 0x4e20, f'saturating add constant is {add:#x}')
    require(img.i32(va + 0x0a) == -add, 'saturation guard is not -add')
    require(img.i32(va + 0x4b) == add, 'non-saturating add is not the same constant')
    msgs = {}
    for key, len_at, lea_at in (('too_far_behind', va + 0x3b, va + 0x3f), ('stale_hardfork', va + 0x73, va + 0x77)):
        length = img.i32(len_at)
        target = img.rip(lea_at, 7)
        text = img.read(target, length)
        require(text == MESSAGES[key], f'{key} message at {target:#x} is {text!r}')
        msgs[key] = dict(lea=hex(lea_at), va=hex(target), len=length, text=text.decode())
    return dict(fde=hex(STARTUP_FDE), window=hex(va), local='[rsp+0xd8]', target='[rsp+0xd0]',
                initial='[rsp+0xc8]', tolerance=add, saturating=True, messages=msgs,
                ok_branch=hex(img.rip(va + 0x68, 6)))


def check_tolerance(img):
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    v540 = img.rip(WINDOWS['select_540'][1], 8)
    v840 = img.rip(WINDOWS['select_840'][1], 8)
    join = WINDOWS['select_840'][1] + 8
    require((img.f64(v540), img.f64(v840)) == TOLERANCES, f'tolerance constants are {img.f64(v540)}, {img.f64(v840)}')
    branches = [img.rip(WINDOWS['select_540'][1] + off, 6) for off in (0x0f, 0x22)]
    require(branches == [join, join], f'540 branches go to {[hex(b) for b in branches]}, not the join {join:#x}')
    into_join = []
    for m in re.finditer(rb'\x0f[\x80-\x8f]|\xe9', body):
        o = m.start()
        n = 2 if body[o] == 0x0f else 1
        if o + n + 4 <= len(body) and start + o + n + 4 + struct.unpack_from('<i', body, o + n)[0] == join:
            into_join.append(hex(start + o))
    for m in re.finditer(rb'[\x70-\x7f\xeb]', body):
        o = m.start()
        if o + 2 <= len(body) and start + o + 2 + struct.unpack_from('<b', body, o + 1)[0] == join:
            into_join.append(hex(start + o))
    want = [hex(WINDOWS['select_540'][1] + 0x0f), hex(WINDOWS['select_540'][1] + 0x22)]
    require(sorted(into_join) == want, f'branches into join {join:#x}: {sorted(into_join)}')
    slot_refs = [hex(start + m.start()) for m in RSP_E0.finditer(body)]
    require(slot_refs == ['0x226916b', '0x226928c'], f'[rsp+0xe0] references are {slot_refs}')
    hf = img.rip(WINDOWS['hardfork_log'][1], 7)
    hf_pieces = template(img, hf)
    require(TEMPLATE_MARKERS['hardfork'] in hf_pieces, f'hardfork template {hf:#x} changed')
    log = WINDOWS['tolerance_log'][1]
    tpl = img.rip(log + 0x9a, 7)
    pieces = template(img, tpl)
    tol_index = placeholder_before(pieces, b'] @ [pre_fork_context: ')
    require(TEMPLATE_MARKERS['tolerance'] in pieces, f'log template {tpl:#x} changed')
    require(pieces[pieces.index(TEMPLATE_MARKERS['tolerance']) + 1] is None, 'tolerance literal not followed by a placeholder')
    # argument array at [rsp+0x120]: (value ptr, formatter) pairs, 16 bytes each; arg 2's value is [rsp+0x48] -> [rsp+0xe0]
    require(img.read(log + 0x4d, 13) == bytes.fromhex('488d442448' '4889842440010000'), 'argument 2 is not &[rsp+0x48]')
    return dict(fde=hex(STARTUP_FDE), slot='[rsp+0xe0]', default=img.f64(v540), default_const=hex(v540),
                hardfork=img.f64(v840), hardfork_const=hex(v840), join=hex(join), branches_into_join=sorted(into_join),
                slot_refs=slot_refs, hardfork_template=hex(hf), log_template=hex(tpl),
                log_placeholders=sum(p is None for p in pieces), tolerance_arg_index=tol_index,
                hardfork_condition='[rbx+0xc18] == 1 and [rbx+0xc20] == rax (jb -> 0x2269760)')


def days_86400(x):
    """The 0x2271de9 sequence on signed 64-bit x: imul by M; esi = (rdx >> 63) + (rdx >> 13), low 32 bits."""
    m = 0x1845c8a0ce512957
    rdx = ((x * m) >> 64) & (2 ** 64 - 1)
    return ((rdx >> 63) + (rdx >> 13)) & 0xffffffff


def check_freshness(img):
    va = WINDOWS['freshness'][1]
    secs_f64 = struct.unpack('<d', img.read(va + 9, 8))[0]
    add_secs = struct.unpack('<I', img.read(va + 0x55, 4))[0]
    require(secs_f64 == float(add_secs), f'message seconds {secs_f64} != added seconds {add_secs}')
    magic = struct.unpack('<q', img.read(va + 0x99, 8))[0]
    require(magic == 0x1845c8a0ce512957, 'day-division multiplier changed')
    slots = {}
    for name, at in (('add_time', va + 0x5b), ('add_days', va + 0xb1), ('now', va + 0xc6), ('panic', va + 0x12b)):
        slot = img.rip(at, 6)
        require(slot in img.relative, f'{name} slot {slot:#x} has no RELATIVE entry')
        slots[name] = (hex(slot), hex(img.relative[slot]))
    require(int(slots['panic'][1], 16) == PANIC_SHIM, 'panic slot does not reach the panic shim')
    tpl = img.rip(va + 0x118, 7)
    pieces = template(img, tpl)
    require(pieces[0] == TEMPLATE_MARKERS['freshness'] and sum(p is None for p in pieces) == 2,
            f'freshness template {tpl:#x} changed')
    loc = img.rip(va + 0x11f, 7)
    require(loc in img.relative, f'Location {loc:#x} has no RELATIVE file pointer')
    flen, line, col = struct.unpack('<QII', img.read(loc + 8, 16))
    file_ = img.read(img.relative[loc], flen)
    require(file_ == LOCATION_FILE, f'Location file is {file_!r}')
    after = img.rip(va + 0x131, 5)
    require(after == WINDOWS['after_panic'][1], f'jump after the panic call goes to {after:#x}')
    shim = img.rip(PANIC_SHIM + 0x26, 6)
    require(img.fde(PANIC_SHIM)[1] == PANIC_SHIM + 0x2c, 'panic shim FDE does not end at its slot call')
    require(shim in img.relative, 'panic shim slot has no RELATIVE entry')
    return dict(fde=hex(FRESH_FDE), state_time='[[rbx+0x740]+0x60] (12 bytes)', added_seconds=add_secs,
                message_seconds=secs_f64, day_divisor=86400, slots={k: list(v) for k, v in slots.items()},
                template=hex(tpl), template_placeholders=2, location=hex(loc), location_file=file_.decode(),
                location_line=line, location_column=col, after_panic=hex(after), panic_shim=hex(PANIC_SHIM),
                panic_shim_slot=hex(shim), panic_shim_target=hex(img.relative[shim]),
                compare='panic iff (date, secs, frac) of state_time + 600 s < now (lexicographic)')


def check_callers(img):
    entry = WINDOWS['poll_entry'][1]
    require(img.rip(entry + 0x11, 7) == POLL_TABLE, 'poll dispatch table moved')
    arm0 = POLL_TABLE + img.i32(POLL_TABLE)
    require(arm0 == entry + 0x21, f'state-0 arm is {arm0:#x}')
    require(entry + len(bytes.fromhex(WINDOWS['poll_entry'][2])) == WINDOWS['freshness'][1],
            'state-0 arm does not run straight into the freshness window')
    text = next(x for x in img.secs if x['name'] == '.text' and x['type'] != 8)
    body = img.data[text['offset']:text['offset'] + text['size']]
    calls = []
    for m in re.finditer(rb'[\xe8\xe9]', body):
        o = m.start()
        if o + 5 <= len(body) and text['address'] + o + 5 + struct.unpack_from('<i', body, o + 1)[0] == FRESH_FDE:
            calls.append(hex(text['address'] + o))
    want = [hex(WINDOWS['call_a'][1] + 0x0d), hex(WINDOWS['call_b'][1] + 0x28)]
    require(calls == want, f'direct calls to {FRESH_FDE:#x}: {calls}')
    states = [img.read(WINDOWS['call_a'][1] + 0x19, 1)[0], img.read(WINDOWS['call_b'][1] + 0x34, 1)[0]]
    strings = {}
    for lea, text_ in FUTURE_STRINGS.items():
        start, end = img.fde(FRESH_FDE)
        require(start <= lea < end, f'LEA {lea:#x} outside {FRESH_FDE:#x}')
        target = img.rip(lea, 7)
        require(img.read(target, len(text_)) == text_, f'string at {target:#x} is not {text_!r}')
        strings[hex(lea)] = text_.decode()
    return dict(poll_table=hex(POLL_TABLE), state0_arm=hex(arm0), direct_calls=calls, caller_fde=hex(ORCHESTRATOR_FDE),
                caller_states_when_al_set=states, future_strings=strings)


def too_far_behind(local, target):
    return min(local + 0x4e20, 2 ** 64 - 1) <= target


def freshness_panics(deadline, now):
    return deadline < now


def analyse(data):
    img = Image(data)
    return dict(target=TARGET, windows={k: hex(v) for k, v in windows(img).items()},
                height_gate=check_gate(img), tolerance_log=check_tolerance(img), freshness=check_freshness(img),
                callers=check_callers(img))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    g, t, f = result['height_gate'], result['tolerance_log'], result['freshness']
    print(f"height gate: too far behind iff local.saturating_add({g['tolerance']}) <= target; "
          f"else stale hardfork iff local < initial")
    print(f"logged tolerance: {t['default']} (default) / {t['hardfork']} (after hardfork branch)")
    print(f"freshness: panic at {f['location_file']}:{f['location_line']}:{f['location_column']} "
          f"iff state_time + {f['added_seconds']} s < now")
    return 0


if __name__ == '__main__':
    sys.exit(main())
