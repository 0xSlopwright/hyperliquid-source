#!/usr/bin/env python3
"""Checker for the foundation triple-min inequality window (node #94, 0x52f2b50).

Stdlib only. Run from the repository root:

    python3 tools/foundation_triple_min_inequality.py \\
        --check research/work-items/foundation-triple-min-inequality-94/evidence.json

Every claim is re-derived from target bytes: the 90-byte window body, its
six int3 padding bytes, the retained FDE record, the memcmp@plt call encoding
(callee is a PLT stub, not an FDE start), the zero direct e8 callers in .text,
and the triple-min inequality rule over the return low byte on its edges.
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
    0x52F2B50: "f30f1efa",
    0x52F2B54: "55",
    0x52F2B55: "53",
    0x52F2B56: "4883ec08",
    0x52F2B5A: "488b16",
    0x52F2B5D: "488b4e08",
    0x52F2B61: "488b4708",
    0x52F2B65: "488b6a08",
    0x52F2B69: "488b7108",
    0x52F2B6D: "488b3a",
    0x52F2B70: "4839e8",
    0x52F2B73: "4889f3",
    0x52F2B76: "480f46e8",
    0x52F2B7A: "4839f0",
    0x52F2B7D: "488b31",
    0x52F2B80: "480f46d8",
    0x52F2B84: "4889e8",
    0x52F2B87: "4839eb",
    0x52F2B8A: "480f46c3",
    0x52F2B8E: "4889c2",
    0x52F2B91: "e8bad53600",
    0x52F2B96: "85c0",
    0x52F2B98: "0f95c0",
    0x52F2B9B: "4839eb",
    0x52F2B9E: "0f95c2",
    0x52F2BA1: "4883c408",
    0x52F2BA5: "09d0",
    0x52F2BA7: "5b",
    0x52F2BA8: "5d",
    0x52F2BA9: "c3",
}

WINDOW_START = 0x52F2B50
CALL_SITE = 0x52F2B91
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
    # shstrtab header layout: name(4) type(4) flags(8) addr(8) off(8) size(8)
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


def evaluate_low_byte(a_second, first_second, second_second, buf1, buf2):
    """The window's return low byte, exactly as decoded."""
    rbp = min(a_second, first_second)
    rbx = min(a_second, second_second)
    n = min(rbp, rbx)
    memcmp_nonzero = 1 if buf1[:n] != buf2[:n] else 0
    partial_differs = 1 if rbx != rbp else 0
    return memcmp_nonzero | partial_differs


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        a = edge["a_second"]
        f = edge.get("first_second", a)
        s = edge.get("second_second", a)
        got = evaluate_low_byte(
            a, f, s, edge["buf1"].encode(), edge["buf2"].encode())
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
        print("usage: foundation_triple_min_inequality.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation triple-min inequality evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
