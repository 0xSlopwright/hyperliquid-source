#!/usr/bin/env python3
"""Independent check for RE-009-C. Imports nothing from tools/.

Parses the ELF section table itself, then checks the binary sha256, the exact
bytes at every pinned key VA (and the decoded rel32 / RIP-relative GOT target of
every call), the sha256 of every pinned loop/count block, and re-derives the
loop bounds and word counts claimed in lthash-mechanism.json.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
PACKET_JSON = HERE / 'lthash-mechanism.json'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_SHA256 = '9450c6225fbc78446bfd7813592ec7e9700006c1fa0bf9ad567216ddb703b12a'

# (va, exact bytes, kind, decoded target or None, role)
KEYS = (
    (0x3269cbe, 'e8ad935600', 'call', 0x37d3070, 'leaf1 top->producer 0x37d3070'),
    (0x37d3574, 'e8e7113f00', 'call', 0x3bc4760, 'leaf1 producer->fold 0x3bc4760'),
    (0x37d386c, 'e8ef0e3f00', 'call', 0x3bc4760, 'leaf1 producer->fold 0x3bc4760'),
    (0x3bc47f4, 'e867e987ff', 'call', 0x3443160, 'leaf1 fold->rayon 0x3443160'),
    (0x344320e, 'e8ed0c3b00', 'call', 0x37f3f00, 'leaf1 rayon->leaf 0x37f3f00'),
    (0x37f3f59, 'e8320ea9ff', 'call', 0x3284d90, 'leaf1 leaf->preparer 0x3284d90'),
    (0x37f3f96, 'ff1524c1f701', 'got', 0x57700c0, 'leaf1 blake3 new slot 0x57700c0'),
    (0x37f4045, 'ff157dc0f701', 'got', 0x57700c8, 'leaf1 blake3 update slot 0x57700c8'),
    (0x37f408a, 'ba00080000', 'bytes', None, 'leaf1 mov edx,0x800'),
    (0x37f408f, 'ff151bc0f701', 'got', 0x57700b0, 'leaf1 blake3 finalize_xof slot 0x57700b0'),
    (0x37f40c3, 'b8010000000f1f840000000000', 'bytes', None, 'leaf1 entry-loop index init'),
    (0x37f41ba, '31c00f1f4000', 'bytes', None, 'leaf1 merge-loop index init'),
    (0x3269ed9, 'e8f29c5600', 'call', 0x37d3bd0, 'leaf2 top->producer 0x37d3bd0'),
    (0x37d4080, 'e85b103f00', 'call', 0x3bc50e0, 'leaf2 producer->fold 0x3bc50e0'),
    (0x37d43ae, 'e82d0d3f00', 'call', 0x3bc50e0, 'leaf2 producer->fold 0x3bc50e0'),
    (0x3bc5174, 'e8d7b987ff', 'call', 0x3440b50, 'leaf2 fold->rayon 0x3440b50'),
    (0x3440bfe, 'e87d363b00', 'call', 0x37f4280, 'leaf2 rayon->leaf 0x37f4280'),
    (0x37f42e7, 'e8e407a9ff', 'call', 0x3284ad0, 'leaf2 leaf->preparer 0x3284ad0'),
    (0x37f4324, 'ff1596bdf701', 'got', 0x57700c0, 'leaf2 blake3 new slot 0x57700c0'),
    (0x37f43d6, 'ff15ecbcf701', 'got', 0x57700c8, 'leaf2 blake3 update slot 0x57700c8'),
    (0x37f441b, 'ba00080000', 'bytes', None, 'leaf2 mov edx,0x800'),
    (0x37f4420, 'ff158abcf701', 'got', 0x57700b0, 'leaf2 blake3 finalize_xof slot 0x57700b0'),
    (0x37f4454, 'b8010000000f1f8000000000', 'bytes', None, 'leaf2 entry-loop index init'),
    (0x37f454a, '31c00f1f4000', 'bytes', None, 'leaf2 merge-loop index init'),
    (0x326a0e5, 'e866845600', 'call', 0x37d2550, 'leaf3 top->producer 0x37d2550'),
    (0x37d29c2, 'e879203f00', 'call', 0x3bc4a40, 'leaf3 producer->fold 0x3bc4a40'),
    (0x37d2d00, 'e83b1d3f00', 'call', 0x3bc4a40, 'leaf3 producer->fold 0x3bc4a40'),
    (0x3bc4ad4, 'e8b77887ff', 'call', 0x343c390, 'leaf3 fold->rayon 0x343c390'),
    (0x343c43e, 'e8cd813b00', 'call', 0x37f4610, 'leaf3 rayon->leaf 0x37f4610'),
    (0x37f4689, 'e8e205a9ff', 'call', 0x3284c70, 'leaf3 leaf->preparer 0x3284c70'),
    (0x37f46c6, 'ff15f4b9f701', 'got', 0x57700c0, 'leaf3 blake3 new slot 0x57700c0'),
    (0x37f477b, 'ff1547b9f701', 'got', 0x57700c8, 'leaf3 blake3 update slot 0x57700c8'),
    (0x37f47c0, 'ba00080000', 'bytes', None, 'leaf3 mov edx,0x800'),
    (0x37f47c5, 'ff15e5b8f701', 'got', 0x57700b0, 'leaf3 blake3 finalize_xof slot 0x57700b0'),
    (0x37f47f9, 'b8010000006690', 'bytes', None, 'leaf3 entry-loop index init'),
    (0x37f48ea, '31c00f1f4000', 'bytes', None, 'leaf3 merge-loop index init'),
    (0x326a2e0, 'e8dbf6ffff', 'call', 0x32699c0, 'top writer 0x32699c0'),
)
# (va, length, sha256, role) for every lattice loop body and count block
BLOBS = (
    (0x37f40d0, 0x58, 'bc9f85950b5b128667509e5bd44bf7fd0ea6b82d23c3ed47efd6cf2651ba7f56', 'leaf1 entry-loop'),
    (0x37f4170, 0x4a, 'f101b382045ca6bb4de0683b7ed0c8b6120ba43cb39242bbb71ba5de5808ead3', 'leaf1 count'),
    (0x37f41c0, 0x58, 'bfa6bec51222ef69acde34eacbe117378e28c9c1875cde2692a9383a6ed5a9bf', 'leaf1 merge-loop'),
    (0x37f4460, 0x58, '553407a90166478d63e856f509c4cf89cf036524bfccbe8de7b3bff5a8d754bf', 'leaf2 entry-loop'),
    (0x37f4500, 0x4a, '129eb13f4d859d6c2ff945f2f51b71675b7ad9ef3dfdb173850c9a4194e0d42b', 'leaf2 count'),
    (0x37f4550, 0x58, 'abdf5e7c5cba79a9919c090fe9e21522fe2d682837ee6fdf7a7d17782100b9ed', 'leaf2 merge-loop'),
    (0x37f4800, 0x58, '5478aba72f647f63ce13caa4757da2b663ac0b004a72f0ce5a542890f84dbeb3', 'leaf3 entry-loop'),
    (0x37f48a0, 0x4a, '74122bacf7b1c0d01b2788fcf55e4a9a6ab0772e6a86d8658773cc1e46170e8c', 'leaf3 count'),
    (0x37f48f0, 0x58, '4870ac9a5cb7deacbba85b6b5c32e1972c833cf13a367f767a8bf639d2511a80', 'leaf3 merge-loop'),
)
ENTRY_LOOPS = (0x37f40d0, 0x37f4460, 0x37f4800)
MERGE_LOOPS = (0x37f41c0, 0x37f4550, 0x37f48f0)


def text_section(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('not ELF64 LE')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    es, cnt, ni = struct.unpack_from('<HHH', data, 58)
    hdr = [struct.unpack_from('<IIQQQQ', data, shoff + i * es) for i in range(cnt)]
    stro = hdr[ni][4]
    for name, _t, _f, addr, off, size in hdr:
        if data[stro + name:data.index(b'\0', stro + name)] == b'.text':
            return addr, off, size
    raise ValueError('no .text')


def check(data, packet=None, require_sha=True):
    errors = []
    if require_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        errors.append('binary sha256 mismatch')
    ta, to, ts = text_section(data)

    def rd(va, n):
        if not (ta <= va and va + n <= ta + ts):
            raise ValueError(f'{va:#x} outside .text')
        return data[va - ta + to:va - ta + to + n]
    for va, hx, kind, tgt, role in KEYS:
        got = rd(va, len(hx) // 2)
        if got.hex() != hx:
            errors.append(f'{va:#x} {role}: bytes {got.hex()} != {hx}')
            continue
        if kind == 'call' and va + 5 + struct.unpack('<i', got[1:5])[0] != tgt:
            errors.append(f'{va:#x} {role}: rel32 target')
        if kind == 'got' and va + 6 + struct.unpack('<i', got[2:6])[0] != tgt:
            errors.append(f'{va:#x} {role}: GOT slot')
    for va, n, sha, role in BLOBS:
        if hashlib.sha256(rd(va, n)).hexdigest() != sha:
            errors.append(f'{va:#x} {role}: block sha256')
    derived = []
    for body in ENTRY_LOOPS + MERGE_LOOPS:
        b = rd(body, 0x58)
        # tail is: 48 83 c0 <step> | 48 3d <bound32> | 75 <rel8>
        step, bound = b[-9], struct.unpack_from('<I', b, 0x58 - 6)[0]
        swaps = sum(1 for i in range(len(b) - 3) if b[i:i + 2] == b'\x66\xc1'
                    and b[i + 2] >> 3 == 0x18 and b[i + 3] == 8)
        stores = b.count(b'\x66\x89')
        derived.append((body, step, bound, swaps, stores))
    if packet is not None:
        for i, L in enumerate(packet['leaves']):
            for key, (body, step, bound, swaps, stores) in (
                    ('lattice_entry_add', derived[i]), ('lattice_merge_add', derived[3 + i])):
                rec = L[key]
                start = rec['index_start']
                if start != (1 if key == 'lattice_entry_add' else 0):
                    errors.append(f'{body:#x}: packet index_start disagrees with pinned init bytes')
                if (rec['index_step'], int(rec['index_bound'], 16), rec['rol16_8_swaps'],
                        rec['u16_stores']) != (step, bound, swaps, stores):
                    errors.append(f'{body:#x}: packet loop fields disagree with bytes')
                if rec['u16_words_total'] != len(range(start, bound, step)) * stores:
                    errors.append(f'{body:#x}: packet word count disagrees with bytes')
    return errors


def main():
    raw = PACKET_JSON.read_bytes()
    errors = []
    if hashlib.sha256(raw).hexdigest() != JSON_SHA256:
        errors.append('packet json sha256 mismatch')
    errors += check(BINARY.read_bytes(), json.loads(raw))
    for e in errors:
        print('FAIL', e)
    n = len(KEYS) + len(BLOBS)
    print(f'independent_verify: {n} pinned items checked, '
          f'{len(KEYS)} key VAs, {len(BLOBS)} blocks, errors={len(errors)}')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
