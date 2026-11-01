#!/usr/bin/env python3
"""Checker for the foundation cache-refresh zero-test window (node #94, 0x54d6360).

Stdlib only. Run from the repository root:

    python3 tools/foundation_cache_refresh_zero.py \\
        --check research/work-items/foundation-cache-refresh-zero-94/evidence.json

Every claim is re-derived from target bytes: the 45-byte window body, its
three int3 padding bytes, the retained FDE records (window, callee, caller,
next), the shared-callee call encoding (callee is an FDE start whose body is
excluded), the single verified direct e8 caller in .text, and the
cache-refresh zero-test rule over the return low byte on its edges.
A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x54D6360: "f30f1efa",
    0x54D6364: "4883ec08",
    0x54D6368: "488d15b1752900",
    0x54D636F: "31f6",
    0x54D6371: "b901000000",
    0x54D6376: "e8b5fbffff",
    0x54D637B: "4885c0",
    0x54D637E: "488905f33c4c00",
    0x54D6385: "0f94c0",
    0x54D6388: "4883c408",
    0x54D638C: "c3",
}

WINDOW_START = 0x54D6360
CALL_SITE = 0x54D6376
CALL_TARGET = 0x54D5F30
TABLE_BASE = 0x576D920
GLOBAL_SLOT = 0x599A078
# First bytes at the callee FDE start, from the retained disassembly.
CALLEE_PREFIX = "f30f1efa4157"


def u64(text):
    return int(text, 16)


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    strtab_off = e_shoff + e_shstrndx * e_shentsize
    (st_name, st_type, st_flags, st_addr, st_off, st_size) = struct.unpack_from(
        "<IIQQQQ", binary, strtab_off)
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (nm, tp, fl, addr, o, sz) = struct.unpack_from("<IIQQQQ", binary, off)
        end = binary.index(b"\x00", st_off + nm)
        name = binary[st_off + nm:end].decode()
        sections[name] = (addr, o, sz)
    return sections


def read_va(binary, sections, va, count):
    """Read count bytes at virtual address va via its section mapping."""
    for name, (addr, off, size) in sections.items():
        if addr <= va < addr + size and va + count <= addr + size:
            return binary[off + (va - addr):off + (va - addr) + count]
    raise ValueError(f"VA {hex(va)} not covered by any section")


def check_target_digest(ev, binary):
    digest = hashlib.sha256(binary).hexdigest()
    if digest != ev["target_sha256"]:
        raise ValueError(
            f"target digest mismatch: {digest} != {ev['target_sha256']}")


def check_window(ev, binary, sections):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        raise ValueError(f"body length {len(body)} != {fn['bytes']}")
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        raise ValueError("body sha256 mismatch")
    for va, hexbytes in INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"instruction bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    # The lea at 0x54d6368 must resolve to the table base, and the store at
    # 0x54d637e must resolve to the global slot; both are RIP-relative.
    lea = read_va(binary, sections, 0x54D6368, 7)
    (disp,) = struct.unpack_from("<i", lea, 3)
    if 0x54D6368 + 7 + disp != TABLE_BASE:
        raise ValueError(
            f"lea resolves to {hex(0x54D6368 + 7 + disp)} != {hex(TABLE_BASE)}")
    store = read_va(binary, sections, 0x54D637E, 7)
    (disp,) = struct.unpack_from("<i", store, 3)
    if 0x54D637E + 7 + disp != GLOBAL_SLOT:
        raise ValueError(
            f"store resolves to {hex(0x54D637E + 7 + disp)} != {hex(GLOBAL_SLOT)}")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")


def check_frames(ev, packet_dir):
    fn = ev["function"]
    call = ev["call"]
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        text = fh.read()
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    if fn["fde_section_offset"][2:] not in text:
        raise ValueError("window FDE section offset not in frames.txt")
    if f"pc={start:016x}..{end:016x}" not in text:
        raise ValueError("window FDE PC range not in frames.txt")
    if f"cie={fn['fde_cie'][2:]}" not in text:
        raise ValueError("window FDE CIE not in frames.txt")
    if f"pc={u64(fn['next_fde_start']):016x}" not in text:
        raise ValueError("next FDE start not in frames.txt")
    # Callee FDE record: the callee is an FDE start, but its body is excluded.
    if call["target_fde_section_offset"][2:] not in text:
        raise ValueError("callee FDE section offset not in frames.txt")
    if call["target_fde_extent"] != 592:
        raise ValueError("callee FDE extent mismatch")
    # Caller FDE record.
    if "002bfa24" not in text:
        raise ValueError("caller FDE section offset not in frames.txt")
    if "pc=00000000054b9b60..00000000054b9f1d" not in text:
        raise ValueError("caller FDE PC range not in frames.txt")


def check_callee_call(ev, binary, sections):
    call = ev["call"]
    site = u64(call["site"])
    target = u64(call["target"])
    enc = read_va(binary, sections, site, 5)
    if enc[0] != 0xE8:
        raise ValueError(f"call site is not e8: {enc.hex()}")
    (rel,) = struct.unpack_from("<i", enc, 1)
    if site + 5 + rel != target:
        raise ValueError(
            f"call target {hex(site + 5 + rel)} != {hex(target)}")
    if target != CALL_TARGET:
        raise ValueError(f"unexpected call target {hex(target)}")
    if call["target_fde_start"] is not True:
        raise ValueError("callee must be recorded as an FDE start")
    prefix = read_va(binary, sections, target, len(CALLEE_PREFIX) // 2)
    if prefix.hex() != CALLEE_PREFIX:
        raise ValueError(f"callee prefix bytes mismatch: {prefix.hex()}")
    if call["target_bytes"] != CALLEE_PREFIX:
        raise ValueError("recorded callee prefix mismatch")


def check_callers(ev, binary, sections, packet_dir):
    """Byte-pattern scan of .text for direct e8 calls to the window."""
    addr, off, size = sections[".text"]
    text = binary[off:off + size]
    found = []
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            site_va = addr + idx
            if site_va + 5 + rel == WINDOW_START:
                found.append(site_va)
        idx += 1
    if found != [0x54B9CE3]:
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != ["0x54b9ce3"]:
        raise ValueError("evidence caller list mismatch")
    if ev["incoming"]["validated_caller_fdes"] != ["0x54b9b60"]:
        raise ValueError("evidence validated-caller list mismatch")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    if "54b9ce3:" not in caller or "54d6360" not in caller:
        raise ValueError("caller disassembly does not retain the call site")


def evaluate_rule(callee_result):
    """Return (global_after, result_low_byte) exactly as decoded."""
    return callee_result, 1 if callee_result == 0 else 0


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        result = u64(edge["callee_result"])
        glob, low = evaluate_rule(result)
        if glob != u64(edge["global_after"]):
            raise ValueError(
                f"edge {edge['note']}: global {hex(glob)} != recorded "
                f"{edge['global_after']}")
        if low != edge["result_low_byte"]:
            raise ValueError(
                f"edge {edge['note']}: model {low} != recorded "
                f"{edge['result_low_byte']}")


def run_evidence(ev, binary, sections, packet_dir):
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee_call(ev, binary, sections)
    check_callers(ev, binary, sections, packet_dir)
    check_edges(ev)


def run_all(evidence_path):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    run_evidence(ev, binary, sections, packet_dir)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_cache_refresh_zero.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation cache-refresh zero-test evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
