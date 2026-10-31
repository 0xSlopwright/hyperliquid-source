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
    'peer_loop_head': (STARTUP_FDE, 0x2269c63, '488b83303c0000488b00488983c8490000488d8bda49000048898c24a8000000c683da49000000488d8b703c000048898c24b000000048c783b04900000000000048c783c049000000000000488b08488b4108488b4910488d0c894801c1488983703c000048898b783c00004839c80f8442070000488d480548898b703c00008b08898bd04900000fb640048883d4490000488d7c2420ff15a04b5003'),
    'query_log': (STARTUP_FDE, 0x2269d00, '4c8db3d04900008b4424208984246c010000c784246001000001000000488b44242448898424640100004c89a42420010000488d05c9d616fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b05fd0d510385c00f8509120000660f1005dd0d5103660f118424007700004c89742408488d84242001000048898424103c0000488d054013710048898424183c0000488d84240077000048898424203c0000488d05d1d5f4ff48898424283c0000488d44240848898424303c0000488d058509440048898424383c0000488d3d823bf7fd488db424103c0000ff15704b5003'),
    'query_call': (STARTUP_FDE, 0x2269e1a, '8b8bd04900000fb693d4490000488d83d54900008893d9490000898bd5490000488983803c0000488d8ba849000048898c2480000000c683a84900000048c783883c000002000000488983a03c0000c683a049000000488db3883c0000488dbc2420010000488b9424c0000000e8941c00004c8bbc2420010000498d4424414939c70f841a0a0000488bac24280100004c8bac2430010000488b84243801000048894424184c8ba424400100000f108424480100000f298424103c0000660f10842458010000660f298424203c0000488b84246801000048898424303c000080bba049000003753b0fb68398490000bf0801000085c0741e83f80375260fb6839249000083f8030f849a020000bf1005000085c0750d4803bc2498000000e8134bfdff'),
    'reply_dispatch': (STARTUP_FDE, 0x2269f3d, '48b800000000000000804883c0404939c70f85a602000048896c24204c896c2428488b44241848894424304c896424384883fd02757e488b842480000000c60001660f28842400770000660f288c2410770000660f29442450660f294c2460488b842420770000488944247041f6c5010f8498000000488db3b04900008b83d04900008b93d449000048c1e2204809c2488dbc2420010000488b4c24184d89e0e8ce835e0049bc0000000000000080e912040000bf1e000000ff15dc3f50034885c00f846d1100004989c6488d7c24280f1005e9d916fe0f11400e660f1005cfd916fe660f11004885ed49bf00000000000000800f84500100004883fd010f8556010000e8aa976400e961010000'),
    'no_heights_log': (STARTUP_FDE, 0x226a04b, '488d7c2420ff154a4850038b4424208984246c010000c784246001000001000000488b442424488984246401000049bc00000000000000804c89a42420010000488d0570d316fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b05a40a510385c04c8db424200100000f85340f0000660f10057c0a5103660f11842400770000488d83d049000048894424084c89b424103c0000488d05e00f710048898424183c0000488d84240077000048898424203c0000488d0571d2f4ff48898424283c0000488d44240848898424303c0000488d052506440048898424383c0000488d3d6c1cf8fd488db424103c0000ff1510485003488bb424200100004c39e60f849a0200004885f60f8491020000488bbc242801000031d2ff158e3e5003e97c020000'),
    'query_error': (STARTUP_FDE, 0x226a1ac, '4983c72bb81e0000004889442418bd1e000000eb704c8db318450000488dbb90450000e87c48fdff4c89f7e8743afeffc683914900000048b800000000000000804883c0404939c70f845afdffff660f288424103c0000660f288c24203c0000660f29842400770000660f298c2410770000488b8424303c000048898424207700004d89ee488b842480000000c60001660f28842400770000660f288c2410770000660f29442450660f294c2460488b84242077000048894424704c89bc24103c00004889ac24183c00004c89b424203c0000488b4c241848898c24283c00004c89a424303c0000660f118424383c0000660f118c24483c000048898424583c0000488d7c2408ff15e74550038b4424088984246c010000c784246001000001000000488b44240c488984246401000049bc00000000000000804c89a42420010000488d050dd116fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b054108510385c04c8db424200100000f85ff0b0000660f100519085103660f11442420488d83d049000048894424484c89b42400770000488d05800d71004889842408770000488d4424204889842410770000488d0514d0f4ff4889842418770000488d8424103c00004889842420770000488b05659250034889842428770000488d4424484889842430770000488d05a90344004889842438770000488d3d9141f8fd488db42400770000ff1594455003488bb424200100004c39e674154885f67410488bbc242801000031d2ff151a3c5003488dbc24103c0000e86d0bfeff488b83703c0000488b8b783c00004839c80f85bef8ffff'),
    'got_heights_log': (STARTUP_FDE, 0x226a4a2, '4c8dabb04900004c896c2408488d84242001000048898424103c0000488d051b0c710048898424183c0000488d84240077000048898424203c0000488d2daccef4ff4889ac24283c0000488d44240848898424303c0000488d05f00b440048898424383c0000488d3d32d1f7fd488db424103c0000ff154b445003488bb424200100004c39e674154885f67410488bbc242801000031d2ff15d13a5003'),
    'select_guard_loop': (STARTUP_FDE, 0x226a53f, '488b83c04900004883f8014c896c2418771b0f857b010000488b8bc8490000488b0948837910010f8566010000488b8bb0490000488b93b849000031f64885c9400f95c6480f44c14889b424103c000048c78424183c00000000000048898c24203c000048899424283c00004889b424303c000048c78424383c00000000000048898c24403c000048899424483c000048898424503c0000488dbc24103c0000e80c4f57004885c00f84730b00004885d20f846a0b00004c8b3a4c8b7208488b8424503c00004889842460010000660f108424103c0000660f108c24203c00000f109424303c00000f109c24403c00000f299c24500100000f29942440010000660f298c2430010000660f29842420010000488dbc2420010000e8924e57004885c00f94c04885d20f94c108c1754a4c8da42420010000662e0f1f840000000000488b2a4c8b6a084c89e7e8614e570031c94d39ee0f97c131f64939ef400f97c60f44f14084f64c0f44fd4d0f44f54885c074054885d275c848b800000000000000804c8d684041b401488d2dc0ccf4ffeb47'),
    'select_error': (STARTUP_FDE, 0x226a6d2, '41bf2b000000bf2b000000ff15f53850034885c00f849b0a00004989c60f100589d216fe0f11401b0f100573d216fe0f114010660f100557d216fe660f11004d8d6c242b4531e4488b7c2418e8cd906400c683da490000014c89abd83b00004c89bbe03b00004c89b3e83b000048c783f03b00002b0000004584e40f85bf010000'),
    'select_retry': (STARTUP_FDE, 0x226a753, '488d83d83b0000488d8b883c00000f1040400f1183c83c0000660f1000660f1048100f1050200f1058300f119bb83c00000f1193a83c0000660f118b983c0000660f1183883c0000488b83303c00004883c008488d93583c000048898424200100004889ac24280100004889942430010000488b05c4385003488984243801000048898c2440010000488b051d8e50034889842448010000488d35647af8fd488dbc24103c0000488d942420010000ff153838500349bc0000000000000080488b8424203c0000488b8c24b0000000488941100f108424103c00000f1101c683683c0000000f1001488b411048898424300100000f298424200100004c8db3403c0000488bb3403c00004c39e674144885f6740f488bbb483c000031d2ff159a375003c683693c000001488b842430010000498946100f28842420010000410f1106488b83303c0000f20f104020f20f1183d83c00004c8db3703d0000c683703d000000e910f3ffff'),
    'select_ok': (STARTUP_FDE, 0x226a912, '488bb3403c000049bc00000000000000804c39e674144885f6740f488bbb483c000031d2ff15d4365003c683693c00000031ed488b8424a0000000c60001488bbc2498000000e86300feff4084ed0f85e8060000c683e049000001c683e849000001'),
    'status_log': (STARTUP_FDE, 0x226a974, '4c89bc24c80000004c89b424d0000000488b83b000000048898424d80000004c8d7c24504c89ffff15ff3e50038b4424508984245c3c0000c78424503c000001000000488b44245448898424543c00004c89a424103c0000488d052fca16fe48898424303c000048c78424383c00001600000048c78424403c00000800000048c78424483c0000000000008b056301510385c00f8576060000660f100543015103660f11842400770000488d8424d80000004889442448488d8424c80000004889442408488d8424d00000004889442420488d8424103c00004889842420010000488d2d840671004889ac2428010000488d84240077000048898424300100004c8d3515c9f4ff4c89b42438010000488d4424484889842440010000488d05790844004889842448010000488d4c240848898c245001000048898424580100004c8d6424204c89a424600100004889842468010000488d3d0d4cf8fd488db42420010000ff158a3e5003488bb424103c000048b800000000000000804839c674154885f67410488bbc24183c000031d2ff1506355003'),
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
STATUS_TEMPLATE = 0x1ef6dd
GOT_HEIGHTS_TEMPLATE = 0x1e7641
# (branch VA, instruction length, expected target)
SELECT_BRANCHES = {
    'len_gt_1_to_loop': (0x226a54f, 2, 0x226a56c), 'len_0_to_error': (0x226a551, 6, 0x226a6d2),
    'single_other_not_1_to_error': (0x226a566, 6, 0x226a6d2), 'loop_back': (0x226a6b6, 2, 0x226a680),
    'ok_to_result': (0x226a6d0, 2, 0x226a719), 'ok_to_slots': (0x226a74d, 6, 0x226a912),
    'error_retry_back': (0x226a8b7, 5, 0x2269bcc),
}
ITER_NEXT = 0x27df4f0
# (branch or call VA, instruction length, expected target)
QUERY_FLOW = {
    'empty_list_to_got_heights': (0x2269cd2, 6, 0x226a41a), 'request_call': (0x2269e87, 5, 0x226bb20),
    'pending_to_yield': (0x2269e9c, 6, 0x226a8bc), 'not_ok_to_error': (0x2269f4e, 6, 0x226a1fa),
    'variant_not_2_to_error': (0x2269f71, 2, 0x2269ff1), 'none_to_no_heights': (0x2269fad, 6, 0x226a04b),
    'insert_call': (0x2269fdd, 5, 0x28523b0), 'insert_to_next': (0x2269fec, 5, 0x226a403),
    'no_heights_to_next': (0x226a182, 5, 0x226a403), 'variant_error_to_log': (0x226a1bf, 2, 0x226a231),
    'next_peer': (0x226a414, 6, 0x2269cd8),
}
QUERY_TEMPLATES = {0x2269de3: (0x1dd96c, b' @@ querying height @@ [rpc_ip: '),
                   0x226a143: (0x1ebdb6, b' @@ no heights from node @@ [rpc_ip: '),
                   0x226a3bf: (0x1ee557, b' @@ unable to query height: '),
                   0x226a508: (GOT_HEIGHTS_TEMPLATE, b' @@ got heights @@ [ip_to_heights: ')}
REQUEST_FDE, RPC_TIMEOUT_WINDOW = 0x226bb20, 0x226bb82
VARIANT_ERROR = b'incorrect rpc response variant'
LOOP_RANGE = (0x2269cd8, 0x226a41a)
BACK_EDGE_R12 = (0x2269fe2, 0x226a079, 0x226a2dc)
ITER_CALLS = (0x226a5df, 0x226a659, 0x226a68a)
SELECT_ERROR = b'unable to find at least 2 valid rpc heights'
RETRY_TEMPLATE = 0x1f2256
# argument k of the status log -> (slot, pointer-to-slot store, argument-array store)
STATUS_ARGS = {
    2: ('[rsp+0xd8]', '488d8424d8000000' '4889442448', '488d442448' '4889842440010000'),
    3: ('[rsp+0xc8]', '488d8424c8000000' '4889442408', '488d4c2408' '48898c2450010000'),
    4: ('[rsp+0xd0]', '488d8424d0000000' '4889442420', '4c8d642420' '4c89a42460010000'),
}
SLOT_REFS = {0xc8: ['0x226a976', '0x226aa2d', '0x226ab6c'], 0xd0: ['0x226a97e', '0x226aa3a', '0x226ab38', '0x226ab62'],
             0xd8: ['0x226a98d', '0x226aa20', '0x226ab0c']}
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


def flow_target(img, va, n):
    return va + 2 + struct.unpack('<b', img.read(va + 1, 1))[0] if n == 2 else img.rip(va, n)


def check_queries(img):
    for name, (va, n, want) in QUERY_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
    for lea, (want, literal) in QUERY_TEMPLATES.items():
        tpl = img.rip(lea, 7)
        require(tpl == want and literal in template(img, tpl), f'template at LEA {lea:#x} changed')
    require(img.i32(0x2269e57 + 7) == 2, 'request tag is not 2')
    start, end = img.fde(REQUEST_FDE)
    require(start < RPC_TIMEOUT_WINDOW < end, f'0x226bb82 is not inside FDE {REQUEST_FDE:#x}')
    pieces = {0x0e: img.rip(0x226a00d, 7), 0x00: img.rip(0x226a018, 8)}
    buf = bytearray(30)
    for off, src in sorted(pieces.items(), reverse=True):
        buf[off:off + 16] = img.read(src, 16)
    require(bytes(buf) == VARIANT_ERROR and img.i32(0x2269ff1 + 1) == 30, f'variant error rebuilt as {bytes(buf)!r}')
    for va in BACK_EDGE_R12:
        require(img.read(va, 10) == bytes.fromhex('49bc0000000000000080'), f'r12 reset at {va:#x} changed')
    lo, hi = LOOP_RANGE
    code = img.read(lo, hi - lo)
    local = [hex(lo + i - 1) for i in range(1, len(code) - 4)
             if code[i] & 0xc7 == 0x83 and code[i + 1:i + 5] == b'\xb0\x00\x00\x00']
    require(not local, f'[rbx+0xb0] operands in the query loop: {local}')
    return dict(peer_list='[[rbx+0x3c30]] stored to [rbx+0x49c8]; data [+0x8], length [+0x10], 5-byte entries',
                current_peer='[rbx+0x49d0] (4 bytes) and [rbx+0x49d4] (1 byte)', request_tag=2,
                request_fde=[hex(start), hex(end)], ok_reply_variant=2,
                insert='[rsp+0x138], [rsp+0x140] into [rbx+0x49b0] keyed by the current peer, when [rsp+0x130] bit 0 is set',
                variant_error=dict(text=VARIANT_ERROR.decode(), pieces={hex(k): hex(v) for k, v in pieces.items()}),
                templates={hex(k): hex(v[0]) for k, v in QUERY_TEMPLATES.items()},
                flow={k: hex(v[2]) for k, v in QUERY_FLOW.items()},
                local_height_operands_in_loop=0, r12_reset_on_back_edges=[hex(v) for v in BACK_EDGE_R12])


def check_selection(img):
    for name, (va, n, want) in SELECT_BRANCHES.items():
        got = img.rip(va, n) if n != 2 else va + 2 + struct.unpack('<b', img.read(va + 1, 1))[0]
        require(got == want, f'{name} branch at {va:#x} goes to {got:#x}')
    for va in ITER_CALLS:
        require(img.rip(va, 5) == ITER_NEXT, f'iterator call at {va:#x} changed')
    err = WINDOWS['select_error'][1]
    loads = {0x1b: img.rip(err + 0x1d, 7), 0x10: img.rip(err + 0x28, 7), 0x00: img.rip(err + 0x33, 8)}
    buf = bytearray(43)
    for off, src in sorted(loads.items()):
        buf[off:off + 16] = img.read(src, 16)
    require(bytes(buf) == SELECT_ERROR and img.i32(err + 2) == len(SELECT_ERROR),
            f'error string rebuilt as {bytes(buf)!r}')
    got = template(img, GOT_HEIGHTS_TEMPLATE)
    require(b' @@ got heights @@ [ip_to_heights: ' in got, 'got-heights template changed')
    retry = WINDOWS['select_retry'][1]
    retry_raw = bytes.fromhex(WINDOWS['select_retry'][2])
    lea = retry + retry_raw.index(bytes.fromhex('488d35'))
    tpl = img.rip(lea, 7)
    require(tpl == RETRY_TEMPLATE and img.read(tpl + 1, 29) == b'AsyncSleepRetry::retry desc=[',
            f'retry template at {tpl:#x} changed')
    return dict(map='[rbx+0x49b0] (root, height, len at +0x10)', got_heights_template=hex(GOT_HEIGHTS_TEMPLATE),
                proceed_when='len > 1, or len == 1 and the queried peer list length [[[rbx+0x49c8]]+0x10] == 1',
                iterator_next=hex(ITER_NEXT), value_fields={'+0x0': 'initial_height (r15)', '+0x8': 'latest_height (r14)'},
                keep='lexicographic max of (initial_height, latest_height); a later equal pair replaces',
                error=dict(text=SELECT_ERROR.decode(), len=len(SELECT_ERROR), pieces={hex(k): hex(v) for k, v in loads.items()}),
                retry_template=hex(tpl), retry_template_lea=hex(lea),
                branches={k: hex(v[2]) for k, v in SELECT_BRANCHES.items()})


def check_status_log(img):
    va = WINDOWS['status_log'][1]
    raw = bytes.fromhex(WINDOWS['status_log'][2])
    require(va + len(raw) == WINDOWS['gate'][1], 'status log window does not end at the gate')
    require(raw.count(bytes.fromhex('488d3d')) == 1, 'status log template LEA is not unique')
    tpl = img.rip(va + raw.index(bytes.fromhex('488d3d')), 7)
    require(tpl == STATUS_TEMPLATE, f'status template is {tpl:#x}')
    pieces = template(img, tpl)
    names = {}
    for k, (slot, ptr, arg) in STATUS_ARGS.items():
        require(raw.count(bytes.fromhex(ptr)) == 1 and raw.count(bytes.fromhex(arg)) == 1,
                f'argument {k} is not a pointer to {slot}')
        before = [i for i, p in enumerate(pieces) if p is None]
        require(len(before) > k and before[k] > 0 and pieces[before[k] - 1] is not None, f'placeholder {k} has no label')
        label = pieces[before[k] - 1].decode()
        m = re.search(r'\[(\w+): $', label)
        require(m is not None, f'placeholder {k} label {label!r} is not a [name: ] field')
        names[slot] = m.group(1)
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    refs = {}
    for disp, want in SLOT_REFS.items():
        got = [hex(start + m.start()) for m in re.finditer(rb'[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]\x24' + bytes([disp]) + rb'\x00\x00\x00', body)]
        require(got == want, f'[rsp+{disp:#x}] references are {got}')
        refs[f'[rsp+{disp:#x}]'] = got
    return dict(window=hex(va), template=hex(tpl), fields=names, slot_refs=refs,
                local_source='[rbx+0xb0]', initial_source='r15', latest_source='r14')


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


def collect_heights(replies):
    """The 0x2269cd8 loop: replies is [(peer, reply)], reply None for an RPC error, else (variant, heights or None)."""
    out = {}
    for peer, reply in replies:
        if reply is None or reply[0] != 2 or reply[1] is None:
            continue
        out[peer] = reply[1]
    return out


def select_heights(values, other_len=0):
    """The 0x226a53f loop: None for the error path, else the kept (initial, latest)."""
    if not (len(values) > 1 or (len(values) == 1 and other_len == 1)):
        return None
    cur = values[0]
    for new in values[1:]:
        keep_cur = cur[0] > new[0] if cur[0] != new[0] else cur[1] > new[1]
        if not keep_cur:
            cur = new
    return cur


def too_far_behind(local, target):
    return min(local + 0x4e20, 2 ** 64 - 1) <= target


def freshness_panics(deadline, now):
    return deadline < now


def analyse(data):
    img = Image(data)
    return dict(target=TARGET, windows={k: hex(v) for k, v in windows(img).items()},
                peer_queries=check_queries(img), height_selection=check_selection(img), status_log=check_status_log(img), height_gate=check_gate(img), tolerance_log=check_tolerance(img), freshness=check_freshness(img),
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
    print('status log fields: ' + ', '.join(f'{k}={v}' for k, v in sorted(result['status_log']['fields'].items())))
    print(f"height gate: too far behind iff local_height.saturating_add({g['tolerance']}) <= latest_height; "
          f"else stale hardfork iff local_height < initial_height")
    print(f"logged tolerance: {t['default']} (default) / {t['hardfork']} (after hardfork branch)")
    print(f"freshness: panic at {f['location_file']}:{f['location_line']}:{f['location_column']} "
          f"iff state_time + {f['added_seconds']} s < now")
    return 0


if __name__ == '__main__':
    sys.exit(main())
