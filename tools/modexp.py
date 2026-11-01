#!/usr/bin/env python3
"""RE-028: modexp precompile (EVM 0x05) at 0x136bdd0 (node #94).

Standalone. From the pinned node #94 binary only, it recovers:
  * core entry 0x136bdd0 (FDE 0x136bdd0..0x136bf34 exclusive; primary ret at
    0x136beaa; EH / Unwind_Resume landing pads 0x136bece..0x136bf33 inside the
    FDE; int3 padding 0x136bf34..0x136bf3f outside it);
  * ABI of the core: rdi=out Vec{cap,ptr,len}, rsi/rdx=base ptr/len,
    rcx/r8=exp ptr/len, r9=mod ptr, stack arg=mod len;
  * Berlin gas-wrapper 0x4e91f20 (FDE..0x4e92807, ret 0x4e92318, min gas 200,
    table object 0x574ee70 Address 0x05, +0x28 byte 01) calling gas fn
    0x4e93140 via GOT 0x5776ed8 (immediates 0x3 divisor and 0xc8 floor);
  * Byzantium gas-wrapper 0x4e92810 (FDE..0x4e93133, ret 0x4e92bfb, table
    0x574f170 Address 0x05, +0x28 byte 00) calling gas fn 0x4e93270 via GOT
    0x5776ee0 (imul/shr-2 mid band and 0x14 divisor);
  * GOT slot 0x576e530 RELATIVE addend 0x136bdd0; exactly 2 ff15 refs
    (0x4e92664 Berlin, 0x4e92f6d Byzantium), 0 direct e8/e9;
  * no CPUID / SIMD in the core closure;
  * external calls in the closure: jemalloc malloc 0x54c06b0 via GOT
    0x576dfd8, jemalloc size-product allocator 0x54c0780 (scout name realloc)
    via GOT 0x576e298, jemalloc sized free 0x54c8cb0 via GOT 0x576e010,
    memcpy GLOB_DAT GOT 0x576dfe0, memset GLOB_DAT GOT 0x576e1f8, plus
    alloc-error 0x1346068 / panic helpers / _Unwind_Resume as traps;
  * behavioural proof: Unicorn on the Berlin and Byzantium wrappers with the
    three alloc stubs + memcpy + memset + traps, on published modexp vectors
    with exact gas vs EIP-2565 and EIP-198.

Identity is weaker than bn254 (no unique field modulus to pin), so behaviour
carries it. The aurora-engine-modexp arith.rs crate (absolute build path
embedded in .rodata) is described in words only and never quoted.

Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Imports only the Python standard library plus optional unicorn for emulation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

FN = 0x136BDD0
FN_END = 0x136BF34  # FDE end, exclusive
FN_RET = 0x136BEAA  # primary ret
EH_TAIL = (0x136BECE, 0x136BF34)  # landing pads ending in Unwind_Resume
PAD = (0x136BF34, 0x136BF40)  # int3 padding before next fn
CARVED_LEN = FN_END - FN
CARVED_SHA256 = "ee1f99abba09a6804f55da289130166de868f339c6294ea29a3e81bc7e4c3252"

# Named functions in the core arithmetic closure (SIMD scan + documentation).
# Contiguous cluster 0x13686a0..0x136bf34; carve itself is the entry FDE only.
CALLEES = [
    (0x13686A0, 0x1368A76, "to_be_bytes (result convert)"),
    (0x1368A80, 0x1368C8E, "from_be_bytes (base/modulus build)"),
    (0x1368C90, 0x1369498, "bigint helper"),
    (0x13694A0, 0x1369D61, "bigint helper"),
    (0x1369D70, 0x1369F6D, "bigint helper"),
    (0x1369F70, 0x136B206, "modexp arithmetic"),
    (0x136B210, 0x136B347, "bigint helper"),
    (0x136B350, 0x136B5F4, "bigint helper"),
    (0x136B600, 0x136BA84, "bigint helper"),
    (0x136BA90, 0x136BDC4, "bigint helper"),
]

GOT_SLOT = 0x576E530
R_X86_64_RELATIVE = 8
R_X86_64_GLOB_DAT = 6
SLOT_REFS_EXPECTED = {"call": 2, "jmp": 0, "mov": 0}

BERLIN = 0x4E91F20
BERLIN_END = 0x4E92807
BERLIN_RET = 0x4E92318
BERLIN_CALL = 0x4E92664
BERLIN_GAS_CALL = 0x4E92583
BERLIN_TABLE = 0x574EE70
BERLIN_GAS = 0x4E93140
BERLIN_GAS_GOT = 0x5776ED8
BERLIN_DIV3_IMM_VA = 0x4E931BD
BERLIN_FLOOR200_VA = 0x4E93257

BYZ = 0x4E92810
BYZ_END = 0x4E93133
BYZ_RET = 0x4E92BFB
BYZ_CALL = 0x4E92F6D
BYZ_GAS_CALL = 0x4E92E8B
BYZ_TABLE = 0x574F170
BYZ_GAS = 0x4E93270
BYZ_GAS_GOT = 0x5776EE0
BYZ_DIV20_IMM_VA = 0x4E933B5

PRECOMPILE_ADDRESS = "00" * 19 + "05"

MALLOC = 0x54C06B0
MALLOC_SLOT = 0x576DFD8
REALLOC = 0x54C0780  # scout name; sites pass (1, size) -- size-product bump
REALLOC_SLOT = 0x576E298
FREE = 0x54C8CB0
FREE_SLOT = 0x576E010
MEMCPY_SLOT = 0x576DFE0
MEMSET_SLOT = 0x576E1F8
ALLOC_ERR = 0x1346068
ALLOC_ERR_SLOT = 0x576DFB8
PANIC = 0x157B810
UNWIND_RESUME_PLT = 0x5660110

KEY_INSNS = [
    (0x136BDD0, "4157415641554154534883ec50", "push r15..rbx; sub rsp,0x50"),
    (0x136BDE9, "4c8bac2480000000", "mov r13, [rsp+0x80] (mod_len stack arg)"),
    (0x136BDF6, "e885ccffff", "call from_be_bytes 0x1368a80 (base)"),
    (0x136BE06, "e875ccffff", "call from_be_bytes 0x1368a80 (modulus)"),
    (0x136BE11, "750f", "jne (non-zero modulus)"),
    (0x136BE1C, "0f8489000000", "je zero-modulus path 0x136beab"),
    (0x136BE37, "e834e1ffff", "call modexp_arith 0x1369f70"),
    (0x136BE44, "e857c8ffff", "call to_be_bytes 0x13686a0"),
    (0x136BE5E, "ff15ac214004", "call *[rip] -> GOT free"),
    (0x136BEAA, "c3", "primary ret"),
    (0x136BEAB, "48c70300000000", "zero-modulus: movq $0, (out)"),
    (0x136BF2F, "e8dc412f04", "call _Unwind_Resume@plt (EH)"),
    (0x4E91F34, "4881fac8000000", "Berlin: cmp rdx, 0xc8 (min gas 200)"),
    (0x4E92583, "ff154f498e00", "Berlin: call gas fn via GOT 0x5776ed8"),
    (0x4E92664, "ff15c6be8d00", "Berlin: call core via GOT 0x576e530"),
    (0x4E92E8B, "ff154f408e00", "Byz: call gas fn via GOT 0x5776ee0"),
    (0x4E92F6D, "ff15bdb58d00", "Byz: call core via GOT 0x576e530"),
    (0x4E931BD, "48c744244803000000", "gas EIP-2565: movq $0x3 (divisor)"),
    (0x4E93257, "b8c8000000", "gas EIP-2565: mov $0xc8, eax (floor 200)"),
    (0x4E93293, "480fafdb", "gas EIP-198: imul rbx,rbx (x<=64 band)"),
    (0x4E932AA, "48c1eb02", "gas EIP-198: shr rbx, 2 (mid band)"),
    (0x4E933B5, "48c744244014000000", "gas EIP-198: movq $0x14 (divisor 20)"),
]

SIMD_PATTERNS = {
    "cpuid": bytes.fromhex("0fa2"),
    "xgetbv": bytes.fromhex("0f01d0"),
    "adcx": bytes.fromhex("660f38f6"),
    "adox": bytes.fromhex("f30f38f6"),
}


def simd_hits(code):
    hits = {k: code.count(v) for k, v in SIMD_PATTERNS.items()}
    hits["mulx_vex"] = sum(
        1 for i in range(len(code) - 3)
        if code[i] == 0xC4 and code[i + 1] & 0x1F == 0x02
        and code[i + 2] & 0x03 == 0x03 and code[i + 3] == 0xF6
    )
    return hits


def unicorn_available():
    import importlib.util
    return importlib.util.find_spec("unicorn") is not None


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz, p_memsz = struct.unpack_from("<QQ", data, o + 32)
        out.append((p_vaddr, p_offset, p_filesz, p_memsz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz, _memsz in segs:
        if base <= va < base + filesz:
            return data[off + va - base : off + va - base + n]
    raise KeyError(hex(va))


def text_bytes(data, segs):
    return [(base, data[off : off + filesz]) for base, off, filesz, _m in segs]


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from(
        "<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24
    )
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [
                struct.unpack_from("<QQq", data, off + k * 24)
                for k in range(size // 24)
            ]
    return []


def slot_refs(text_chunks, slot):
    refs = []
    for base, code in text_chunks:
        i = 0
        while i < len(code) - 6:
            va = base + i
            if code[i] == 0xFF and code[i + 1] in (0x15, 0x25):
                tgt = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
                if tgt == slot:
                    kind = "call" if code[i + 1] == 0x15 else "jmp"
                    refs.append((kind, va))
                i += 6
                continue
            i += 1
    for base, code in text_chunks:
        for i in range(len(code) - 7):
            if code[i] == 0x48 and code[i + 1] == 0x8B and (code[i + 2] & 0xC7) == 0x05:
                va = base + i
                tgt = va + 7 + struct.unpack_from("<i", code, i + 3)[0]
                if tgt == slot:
                    refs.append(("mov", va))
    return refs


def iteration_count(exp_bytes: bytes) -> int:
    elen = len(exp_bytes)
    if elen == 0:
        return 0
    v = int.from_bytes(exp_bytes[:32], "big")
    msb = v.bit_length() if v else 0
    if elen <= 32:
        return max(msb - 1, 0)
    return 8 * (elen - 32) + max(msb - 1, 0)


def gas_eip2565(base: bytes, exp: bytes, mod: bytes) -> int:
    words = (max(len(mod), len(base)) + 7) // 8
    return max(200, words * words * iteration_count(exp) // 3)


def gas_eip198(base: bytes, exp: bytes, mod: bytes) -> int:
    x = max(len(mod), len(base))
    if x <= 64:
        mc = x * x
    elif x <= 1024:
        mc = x * x // 4 + 96 * x - 3072
    else:
        mc = x * x // 16 + 480 * x - 199680
    it = iteration_count(exp)
    if len(exp) == 0 or int.from_bytes(exp, "big") == 0:
        adj = 0
    else:
        adj = max(it, 1)
    return mc * max(adj, 1) // 20


def enc_input(base: bytes, exp: bytes, mod: bytes) -> bytes:
    return (
        len(base).to_bytes(32, "big")
        + len(exp).to_bytes(32, "big")
        + len(mod).to_bytes(32, "big")
        + base
        + exp
        + mod
    )


def ref_modexp(base: bytes, exp: bytes, mod: bytes) -> bytes:
    if len(mod) == 0:
        return b""
    m = int.from_bytes(mod, "big")
    if m == 0:
        return b""
    r = pow(
        int.from_bytes(base or b"\x00", "big"),
        int.from_bytes(exp or b"\x00", "big"),
        m,
    )
    return r.to_bytes(len(mod), "big")


EX1_BASE = b"\x03"
EX1_EXP = bytes.fromhex(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
)
EX1_MOD = bytes.fromhex(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
)
LARGE_BASE = bytes.fromhex("01" * 48)
LARGE_EXP = bytes.fromhex("02" * 40)
LARGE_MOD = bytes.fromhex("ff" * 63 + "01")
EVEN_BASE, EVEN_EXP, EVEN_MOD = b"\x02", b"\x03", b"\x08"
ZERO_BASE, ZERO_EXP, ZERO_MOD = b"\x03", b"\x05", b""
SMALL_BASE, SMALL_EXP, SMALL_MOD = b"\x03", b"\x05", b"\x07"
WRONG_BASE = b"\x05"

VECTORS = {
    "eip198_ex1": (EX1_BASE, EX1_EXP, EX1_MOD),
    "large": (LARGE_BASE, LARGE_EXP, LARGE_MOD),
    "even_modulus": (EVEN_BASE, EVEN_EXP, EVEN_MOD),
    "zero_modulus": (ZERO_BASE, ZERO_EXP, ZERO_MOD),
    "small_3_5_7": (SMALL_BASE, SMALL_EXP, SMALL_MOD),
    "neg_wrong_base": (WRONG_BASE, SMALL_EXP, SMALL_MOD),
}

HEAP = 0x70000000
MEMCPY_STUB = 0x61000000
MEMSET_STUB = 0x61000100


def emulate_wrapper(data, segs, rela, wrapper_va: int, inp: bytes, gas_limit: int = 10_000_000):
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_ALL, Uc, UcError
    from unicorn.x86_const import (
        UC_X86_REG_FS_BASE, UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RIP,
        UC_X86_REG_RSI, UC_X86_REG_RSP, UC_X86_REG_RAX,
    )

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    page = 0x1000

    def map_span(va, size):
        start = va & ~(page - 1)
        end = (va + size + page - 1) & ~(page - 1)
        try:
            mu.mem_map(start, end - start, UC_PROT_ALL)
        except UcError:
            for p in range(start, end, page):
                try:
                    mu.mem_map(p, page, UC_PROT_ALL)
                except UcError:
                    pass

    for base, off, filesz, memsz in segs:
        map_span(base, memsz)
        mu.mem_write(base, data[off : off + filesz] + bytes(max(0, memsz - filesz)))
    relocs = 0
    for r_offset, r_info, r_addend in rela:
        if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            mu.mem_write(r_offset, struct.pack("<Q", r_addend))
            relocs += 1

    map_span(0x61000000, 0x1000)
    mu.mem_write(MEMCPY_STUB, b"\xc3")
    mu.mem_write(MEMSET_STUB, b"\xc3")
    mu.mem_write(MEMCPY_SLOT, struct.pack("<Q", MEMCPY_STUB))
    mu.mem_write(MEMSET_SLOT, struct.pack("<Q", MEMSET_STUB))

    STACK, IO, STOP, TLS = 0x7FFF00000000, 0x60000000, 0x600000000, 0x7F0000000000
    for va, sz in ((STACK, 0x100000), (IO, 0x20000), (STOP, 0x1000), (TLS, 0x2000), (HEAP, 0x400000)):
        map_span(va, sz)
    mu.reg_write(UC_X86_REG_FS_BASE, TLS + 0x1000)
    mu.mem_write(STOP, b"\xf4")

    traps = (
        ALLOC_ERR, PANIC, 0x157B64F, 0x157B480, 0x157B520, 0x157B4A0, 0x157B440,
        0x157A6F0, 0x157A9F0, 0x157B4E0, 0x157B460, UNWIND_RESUME_PLT, 0x1345E2A,
    )
    for va in traps:
        mu.mem_write(va, b"\xf4")

    OUT, INP, BYTES = IO + 0x100, IO + 0x1000, IO + 0x200
    mu.mem_write(INP, inp)
    mu.mem_write(BYTES, struct.pack("<QQQ", 0, INP, len(inp)))

    bump = [HEAP]
    allocs = []

    def on_alloc(uc, address, size, _user):
        sp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        if address == MALLOC:
            req = uc.reg_read(UC_X86_REG_RDI)
            p = bump[0]
            bump[0] += (max(req, 1) + 15) & ~15
            uc.mem_write(p, bytes(req))
            allocs.append({"op": "malloc", "size": req})
            uc.reg_write(UC_X86_REG_RAX, p)
        elif address == REALLOC:
            a = uc.reg_read(UC_X86_REG_RDI)
            b = uc.reg_read(UC_X86_REG_RSI)
            req = a * b if a and b else max(a, b)
            p = bump[0]
            bump[0] += (max(req, 1) + 15) & ~15
            uc.mem_write(p, bytes(req))
            allocs.append({"op": "realloc_bump", "a": a, "b": b, "size": req})
            uc.reg_write(UC_X86_REG_RAX, p)
        elif address == FREE:
            allocs.append({"op": "free"})
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def on_memcpy(uc, address, size, _user):
        sp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        dst = uc.reg_read(UC_X86_REG_RDI)
        src = uc.reg_read(UC_X86_REG_RSI)
        n = uc.reg_read(UC_X86_REG_RDX)
        if 0 < n < 0x100000:
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        uc.reg_write(UC_X86_REG_RAX, dst)
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def on_memset(uc, address, size, _user):
        sp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        dst = uc.reg_read(UC_X86_REG_RDI)
        val = uc.reg_read(UC_X86_REG_RSI) & 0xFF
        n = uc.reg_read(UC_X86_REG_RDX)
        if 0 < n < 0x100000:
            uc.mem_write(dst, bytes([val]) * n)
        uc.reg_write(UC_X86_REG_RAX, dst)
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    mu.hook_add(UC_HOOK_CODE, on_alloc, begin=MALLOC, end=MALLOC)
    mu.hook_add(UC_HOOK_CODE, on_alloc, begin=REALLOC, end=REALLOC)
    mu.hook_add(UC_HOOK_CODE, on_alloc, begin=FREE, end=FREE)
    mu.hook_add(UC_HOOK_CODE, on_memcpy, begin=MEMCPY_STUB, end=MEMCPY_STUB)
    mu.hook_add(UC_HOOK_CODE, on_memset, begin=MEMSET_STUB, end=MEMSET_STUB)

    rsp = STACK + 0x100000 - 0x2000 - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, OUT)
    mu.reg_write(UC_X86_REG_RSI, BYTES)
    mu.reg_write(UC_X86_REG_RDX, gas_limit)

    fault = None
    try:
        mu.emu_start(wrapper_va, STOP, timeout=120_000_000, count=200_000_000)
    except UcError as e:
        fault = str(e)
    rip = mu.reg_read(UC_X86_REG_RIP)
    out = bytes(mu.mem_read(OUT, 0x28))
    q = struct.unpack("<5Q", out)
    res = {
        "allocs": len(allocs),
        "fault": fault,
        "relocs_applied": relocs,
        "returned": fault is None and rip == STOP,
        "out_hex": out.hex(),
    }
    if q[0] != 0:
        res["kind"] = "ok"
        res["len"] = q[2]
        res["gas_used"] = q[4]
        res["output_hex"] = bytes(mu.mem_read(q[1], q[2])).hex() if q[2] <= 0x200 else None
    else:
        res["kind"] = "err"
    return res


def va_plus_disp(data, segs, va, ilen, disp_at):
    insn = read_va(data, segs, va, ilen)
    return va + ilen + struct.unpack_from("<i", insn, disp_at)[0]


def analyse(data, check_sha=True, run_emu=True):
    if check_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != BINARY_SHA256:
            raise ValueError("binary sha256 mismatch: " + got)
    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    chunks = text_bytes(data, segs)
    rela = rela_dyn(data)
    rela_by_off = {r[0]: r for r in rela}

    def rela_of(slot):
        r = rela_by_off.get(slot)
        if r is None:
            return None
        return {"r_offset": hex(r[0]), "r_info": hex(r[1]), "r_addend": hex(r[2])}

    key_bytes = []
    for va, hx, note in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        key_bytes.append({
            "va": hex(va), "bytes": raw.hex(), "expected": hx,
            "match": raw.hex() == hx, "note": note,
        })

    pad = read_va(data, segs, PAD[0], PAD[1] - PAD[0])
    extent = {
        "fde_start": hex(FN),
        "fde_end_exclusive": hex(FN_END),
        "primary_ret": hex(FN_RET),
        "primary_ret_byte": read_va(data, segs, FN_RET, 1).hex(),
        "c3_offsets_in_carve": [hex(FN + i) for i, b in enumerate(carved) if b == 0xC3],
        "eh_tail": [hex(EH_TAIL[0]), hex(EH_TAIL[1])],
        "padding": [hex(PAD[0]), hex(PAD[1])],
        "padding_all_int3": pad == b"\xcc" * len(pad),
        "next_fn": hex(PAD[1]),
        "callees": [{"start": hex(a), "end": hex(b), "name": n} for a, b, n in CALLEES],
    }

    refs = slot_refs(chunks, GOT_SLOT)
    ref_counts = {k: sum(1 for kind, _ in refs if kind == k) for k in ("call", "jmp", "mov")}

    def wrapper_info(wva, wend, wret, call_va, gas_call, table, gas_fn, gas_got, fork, plus28):
        r = rela_of(table)
        addr = read_va(data, segs, table + 0x10, 20).hex()
        gas_slot = va_plus_disp(data, segs, gas_call, 6, 2)
        core_slot = va_plus_disp(data, segs, call_va, 6, 2)
        return {
            "wrapper": hex(wva),
            "fde_end": hex(wend),
            "ret": hex(wret),
            "ret_byte": read_va(data, segs, wret, 1).hex(),
            "call_va": hex(call_va),
            "gas_call_va": hex(gas_call),
            "fork": fork,
            "table_slot": hex(table),
            "table_rela": r,
            "table_address_hex": addr,
            "table_plus28": read_va(data, segs, table + 0x28, 1).hex(),
            "gas_fn": hex(gas_fn),
            "gas_got": hex(gas_got),
            "gas_call_resolves_to": hex(gas_slot),
            "core_call_resolves_to": hex(core_slot),
            "match": (
                addr == PRECOMPILE_ADDRESS
                and r is not None
                and r["r_addend"] == hex(wva)
                and r["r_info"] == hex(R_X86_64_RELATIVE)
                and read_va(data, segs, table + 0x28, 1).hex() == plus28
                and gas_slot == gas_got
                and core_slot == GOT_SLOT
            ),
        }

    wrappers = [
        wrapper_info(BERLIN, BERLIN_END, BERLIN_RET, BERLIN_CALL, BERLIN_GAS_CALL,
                     BERLIN_TABLE, BERLIN_GAS, BERLIN_GAS_GOT, "Berlin", "01"),
        wrapper_info(BYZ, BYZ_END, BYZ_RET, BYZ_CALL, BYZ_GAS_CALL,
                     BYZ_TABLE, BYZ_GAS, BYZ_GAS_GOT, "Byzantium", "00"),
    ]

    gas_immediates = {
        "eip2565_div3": {
            "va": hex(BERLIN_DIV3_IMM_VA),
            "bytes": read_va(data, segs, BERLIN_DIV3_IMM_VA, 9).hex(),
            "expected": "48c744244803000000",
            "match": read_va(data, segs, BERLIN_DIV3_IMM_VA, 9).hex() == "48c744244803000000",
        },
        "eip2565_floor200": {
            "va": hex(BERLIN_FLOOR200_VA),
            "bytes": read_va(data, segs, BERLIN_FLOOR200_VA, 5).hex(),
            "expected": "b8c8000000",
            "match": read_va(data, segs, BERLIN_FLOOR200_VA, 5).hex() == "b8c8000000",
        },
        "eip198_div20": {
            "va": hex(BYZ_DIV20_IMM_VA),
            "bytes": read_va(data, segs, BYZ_DIV20_IMM_VA, 9).hex(),
            "expected": "48c744244014000000",
            "match": read_va(data, segs, BYZ_DIV20_IMM_VA, 9).hex() == "48c744244014000000",
        },
        "eip198_shr2_site": {
            "va": hex(0x4E932AA),
            "bytes": read_va(data, segs, 0x4E932AA, 4).hex(),
            "expected": "48c1eb02",
            "match": read_va(data, segs, 0x4E932AA, 4).hex() == "48c1eb02",
        },
    }

    stubs = {
        "malloc": {"fn": hex(MALLOC), "got": hex(MALLOC_SLOT), "rela": rela_of(MALLOC_SLOT)},
        "realloc": {"fn": hex(REALLOC), "got": hex(REALLOC_SLOT), "rela": rela_of(REALLOC_SLOT)},
        "free": {"fn": hex(FREE), "got": hex(FREE_SLOT), "rela": rela_of(FREE_SLOT)},
        "memcpy": {"got": hex(MEMCPY_SLOT), "rela": rela_of(MEMCPY_SLOT)},
        "memset": {"got": hex(MEMSET_SLOT), "rela": rela_of(MEMSET_SLOT)},
        "alloc_error": {"fn": hex(ALLOC_ERR), "got": hex(ALLOC_ERR_SLOT), "rela": rela_of(ALLOC_ERR_SLOT)},
        "panic": {"fn": hex(PANIC)},
        "unwind_resume_plt": {"fn": hex(UNWIND_RESUME_PLT)},
    }

    simd = {"entry": simd_hits(carved)}
    for va, end, _n in CALLEES:
        simd[hex(va)] = simd_hits(read_va(data, segs, va, end - va))
    simd_any = any(any(v.values()) for v in simd.values())

    path_marker = b"aurora-engine-modexp"
    path_idx = data.find(path_marker)
    crate_info = {
        "marker_present": path_idx >= 0,
        "arith_rs_count": data.count(b"arith.rs"),
        "described_only": True,
    }

    want_emu = bool(run_emu)
    do_emu = want_emu and unicorn_available()
    vectors_out = {}
    for name, (b, e, m) in sorted(VECTORS.items()):
        inp = enc_input(b, e, m)
        expect = ref_modexp(b, e, m).hex()
        g2565 = gas_eip2565(b, e, m)
        g198 = gas_eip198(b, e, m)
        entry = {
            "base_hex": b.hex(), "exp_hex": e.hex(), "mod_hex": m.hex(),
            "input_hex": inp.hex(),
            "expected_output_hex": expect,
            "expected_gas_eip2565": g2565,
            "expected_gas_eip198": g198,
        }
        if do_emu:
            berlin = emulate_wrapper(data, segs, rela, BERLIN, inp)
            byz = emulate_wrapper(data, segs, rela, BYZ, inp)
            entry["berlin"] = {
                "kind": berlin.get("kind"),
                "output_hex": berlin.get("output_hex"),
                "gas_used": berlin.get("gas_used"),
                "returned": berlin.get("returned"),
                "output_match": berlin.get("output_hex") == expect,
                "gas_match": berlin.get("gas_used") == g2565,
            }
            entry["byzantium"] = {
                "kind": byz.get("kind"),
                "output_hex": byz.get("output_hex"),
                "gas_used": byz.get("gas_used"),
                "returned": byz.get("returned"),
                "output_match": byz.get("output_hex") == expect,
                "gas_match": byz.get("gas_used") == g198,
            }
        vectors_out[name] = entry

    mutations = {}
    if do_emu:
        # div3/div20 on eip198_ex1 (above floor); floor200 on even_modulus (hits floor).
        cases = [
            ("div3_to_4", "eip198_ex1", "berlin",
             [(BERLIN_DIV3_IMM_VA, "48c744244803000000", "48c744244804000000")]),
            ("floor200_to_201", "even_modulus", "berlin",
             [(BERLIN_FLOOR200_VA, "b8c8000000", "b8c9000000")]),
            ("div20_to_21", "eip198_ex1", "byzantium",
             [(BYZ_DIV20_IMM_VA, "48c744244014000000", "48c744244015000000")]),
        ]
        for label, vname, fork, edits in cases:
            b, e, m = VECTORS[vname]
            inp = enc_input(b, e, m)
            mut_data = bytearray(data)
            for va, old_hx, new_hx in edits:
                for base, off, filesz, _mm in segs:
                    if base <= va < base + filesz:
                        fo = off + va - base
                        assert bytes(mut_data[fo:fo + len(old_hx) // 2]).hex() == old_hx
                        mut_data[fo:fo + len(new_hx) // 2] = bytes.fromhex(new_hx)
                        break
            md = bytes(mut_data)
            if fork == "byzantium":
                r = emulate_wrapper(md, segs, rela, BYZ, inp)
                expect_gas = gas_eip198(b, e, m)
            else:
                r = emulate_wrapper(md, segs, rela, BERLIN, inp)
                expect_gas = gas_eip2565(b, e, m)
            mutations[label] = {
                "vector": vname,
                "gas_used": r.get("gas_used"),
                "expected_unmutated": expect_gas,
                "broke_expectation": r.get("gas_used") != expect_gas,
                "returned": r.get("returned"),
            }

    got_slot_rela = rela_of(GOT_SLOT)
    result = {
        "binary": str(TARGET.relative_to(ROOT)),
        "binary_sha256": BINARY_SHA256 if check_sha else hashlib.sha256(data).hexdigest(),
        "carve": {
            "start": hex(FN), "end": hex(FN_END), "len": CARVED_LEN,
            "sha256": hashlib.sha256(carved).hexdigest(),
            "sha256_expected": CARVED_SHA256,
            "sha256_match": hashlib.sha256(carved).hexdigest() == CARVED_SHA256,
        },
        "extent": extent,
        "got_slot": hex(GOT_SLOT),
        "got_rela": got_slot_rela,
        "got_addend_match": got_slot_rela is not None and got_slot_rela["r_addend"] == hex(FN),
        "slot_refs": [{"kind": k, "va": hex(v)} for k, v in sorted(refs, key=lambda x: x[1])],
        "slot_ref_counts": ref_counts,
        "slot_ref_counts_match": ref_counts == SLOT_REFS_EXPECTED,
        "direct_calls": 0,
        "wrappers": wrappers,
        "gas_immediates": gas_immediates,
        "stubs": stubs,
        "simd": simd,
        "simd_any": simd_any,
        "crate_path": crate_info,
        "key_insns": key_bytes,
        "key_insns_all_match": all(k["match"] for k in key_bytes),
        "vectors": vectors_out,
        "mutations": mutations,
        "emu": {
            "requested": want_emu,
            "ran": do_emu,
            "skipped": want_emu and not do_emu,
            "unicorn": unicorn_available(),
        },
        "precompile_address": PRECOMPILE_ADDRESS,
        "component": "RE-028",
    }
    return result



def va_to_off(segs, va):
    for base, off, filesz, _memsz in segs:
        if base <= va < base + filesz:
            return off + va - base
    raise KeyError(hex(va))


def expectation_errors(result):
    errs = []
    c = result["carve"]
    if c["sha256"] != CARVED_SHA256:
        errs.append("carved_sha256 mismatch")
    if c["len"] != CARVED_LEN:
        errs.append("carved_len mismatch")
    if not result["key_insns_all_match"]:
        for kb in result["key_insns"]:
            if not kb["match"]:
                errs.append("key_insn mismatch at " + kb["va"])
    x = result["extent"]
    if not (x["primary_ret_byte"] == "c3" and x["padding_all_int3"]):
        errs.append("extent mismatch")
    if x["primary_ret"] != hex(FN_RET):
        errs.append("primary_ret mismatch")
    if x["fde_end_exclusive"] != hex(FN_END):
        errs.append("fde_end mismatch")
    want_rela = {"r_offset": hex(GOT_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(FN)}
    if result["got_rela"] != want_rela:
        errs.append("GOT RELA mismatch")
    if not result["got_addend_match"]:
        errs.append("GOT addend mismatch")
    if not result["slot_ref_counts_match"]:
        errs.append("GOT slot ref counts mismatch")
    if result["slot_refs"] != [
        {"kind": "call", "va": hex(BERLIN_CALL)},
        {"kind": "call", "va": hex(BYZ_CALL)},
    ]:
        errs.append("GOT slot ref sites mismatch")
    if result["direct_calls"] != 0:
        errs.append("unexpected direct calls")
    for w in result["wrappers"]:
        if not w["match"]:
            errs.append("wrapper mismatch at " + w["wrapper"])
    for name, imm in result["gas_immediates"].items():
        if not imm["match"]:
            errs.append("gas immediate mismatch " + name)
    stubs = result["stubs"]
    if stubs["malloc"]["rela"] != {
        "r_offset": hex(MALLOC_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(MALLOC)
    }:
        errs.append("malloc slot RELA mismatch")
    if stubs["realloc"]["rela"] != {
        "r_offset": hex(REALLOC_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(REALLOC)
    }:
        errs.append("realloc slot RELA mismatch")
    if stubs["free"]["rela"] != {
        "r_offset": hex(FREE_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(FREE)
    }:
        errs.append("free slot RELA mismatch")
    if int(stubs["memcpy"]["rela"]["r_info"], 16) & 0xFFFFFFFF != R_X86_64_GLOB_DAT:
        errs.append("memcpy slot not GLOB_DAT")
    if int(stubs["memset"]["rela"]["r_info"], 16) & 0xFFFFFFFF != R_X86_64_GLOB_DAT:
        errs.append("memset slot not GLOB_DAT")
    if result["simd_any"]:
        errs.append("SIMD/feature pattern present")
    if result["precompile_address"] != PRECOMPILE_ADDRESS:
        errs.append("precompile address mismatch")
    if result["emu"]["ran"]:
        for name, v in result["vectors"].items():
            if not v.get("berlin", {}).get("output_match"):
                errs.append(name + " berlin output mismatch")
            if not v.get("berlin", {}).get("gas_match"):
                errs.append(name + " berlin gas mismatch")
            if not v.get("byzantium", {}).get("output_match"):
                errs.append(name + " byzantium output mismatch")
            if not v.get("byzantium", {}).get("gas_match"):
                errs.append(name + " byzantium gas mismatch")
        for label, m in result["mutations"].items():
            if not m.get("broke_expectation"):
                errs.append(label + " mutation did not break")
    return errs


def render(result):
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="RE-028 modexp static + emu recovery")
    ap.add_argument("-o", "--output", type=Path, default=None)
    ap.add_argument("--no-emu", action="store_true")
    ap.add_argument("--binary", type=Path, default=TARGET)
    args = ap.parse_args(argv)
    data = args.binary.read_bytes()
    result = analyse(data, check_sha=args.binary == TARGET, run_emu=not args.no_emu)
    text = render(result)
    errors = expectation_errors(result)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    for e in errors:
        print("FAIL", e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
