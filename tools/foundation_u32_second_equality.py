#!/usr/bin/env python3
"""Checker for the foundation u32 second-field equality window (node #94, 0x552fbe0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_u32_second_equality.py \\
        --check research/work-items/foundation-u32-second-equality-94/evidence.json

Every claim is re-derived from target bytes: the 51-byte window body, its
thirteen int3 padding bytes, the retained FDE record, the memcmp@plt call
encoding (callee is a PLT stub, not an FDE start), the zero direct e8 callers
in .text, and the u32 second-field equality rule over the return low byte on
its edges. A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x552FBE0: "f30f1efa",
    0x552FBE4: "8b5708",
    0x552FBE7: "3b5608",
    0x552FBEA: "7524",
    0x552FBEC: "4883ec08",
    0x552FBF0: "488b36",
    0x552FBF3: "488b3f",
    0x552FBF6: "48c1e203",
    0x552FBFA: "e851051300",
    0x552FBFF: "85c0",
    0x552FC01: "0f94c0",
    0x552FC04: "4883c408",
    0x552FC08: "c3",
    0x552FC09: "0f1f8000000000",
    0x552FC10: "31c0",
    0x552FC12: "c3",
}

WINDOW_START = 0x552FBE0
CALL_SITE = 0x552FBFA
CALL_TARGET = 0x5660150
# PLT stub bytes at the call target: jmp *GOT, push, jmp PLT0.
PLT_STUB = "ff257a8c11006806000000e980ffffff"


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
    stub = read_va(binary, sections, target, len(PLT_STUB) // 2)
    if stub.hex() != PLT_STUB:
        raise ValueError(f"PLT stub bytes mismatch: {stub.hex()}")
    if call["target_fde_start"] is not False:
        raise ValueError("callee must be recorded as not an FDE start")
    if call["target_bytes"] != PLT_STUB[:12]:
        raise ValueError("recorded PLT stub prefix mismatch")


def check_callers(ev, binary, sections):
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
    if found != []:
        raise ValueError(f"unexpected direct callers: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != []:
        raise ValueError("evidence must record zero direct callers")


def evaluate_low_byte(a_second, b_second, buf_a, buf_b):
    """The window's return low byte, exactly as decoded."""
    if a_second != b_second:
        return 0
    n = (a_second & 0xFFFFFFFF) << 3
    return 1 if buf_a[:n] == buf_b[:n] else 0


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got = evaluate_low_byte(
            edge["a_second"], edge["b_second"],
            edge["buf_a"].encode(), edge["buf_b"].encode())
        if got != edge["result_low_byte"]:
            raise ValueError(
                f"edge {edge['note']}: model {got} != recorded "
                f"{edge['result_low_byte']}")


def run_evidence(ev, binary, sections, packet_dir):
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee_call(ev, binary, sections)
    check_callers(ev, binary, sections)
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
        print("usage: foundation_u32_second_equality.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation u32 second-field equality evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
