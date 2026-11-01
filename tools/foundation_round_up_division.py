#!/usr/bin/env python3
"""Checker for the foundation round-up-division window (node #94, 0x4f9ee90).

Stdlib only. Run from the repository root:

    python3 tools/foundation_round_up_division.py \\
        --check research/work-items/foundation-round-up-division-94/evidence.json

Every claim is re-derived from target bytes: the 28-byte window body, its
four int3 padding bytes, the retained FDE records (window, next, the
11-byte callee, and the single caller FDE, each locked under its own CIE),
the callee body and its five int3 padding bytes, the direct call encoding
to the callee, the full direct-caller scan (exactly one site), and the
round-up-division rule on its edges, including the two div-fault edges.
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
    0x4F9EE90: "f30f1efa",
    0x4F9EE94: "53",
    0x4F9EE95: "4889f3",
    0x4F9EE98: "e8e3ffffff",
    0x4F9EE9D: "31d2",
    0x4F9EE9F: "89c1",
    0x4F9EEA1: "8d41ff",
    0x4F9EEA4: "4801d8",
    0x4F9EEA7: "5b",
    0x4F9EEA8: "48f7f1",
    0x4F9EEAB: "c3",
}

CALLEE_INSTR = {
    0x4F9EE80: "f30f1efa",
    0x4F9EE84: "8b4740",
    0x4F9EE87: "83c001",
    0x4F9EE8A: "c3",
}

WINDOW_START = 0x4F9EE90
CALLEE_START = 0x4F9EE80


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
    # The call must target the callee: rel32 from the end of the call.
    enc = read_va(binary, sections, 0x4F9EE98, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x4F9EE98 + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The div must divide by rcx, the divisor register.
    if read_va(binary, sections, 0x4F9EEA8, 3) != bytes.fromhex("48f7f1"):
        raise ValueError("div site is not div %rcx")


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
    cal = ev["callee"]
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
    if fn["next_fde_section_offset"][2:] not in text:
        raise ValueError("next FDE section offset not in frames.txt")
    if f"cie={fn['next_fde_cie'][2:]}" not in text:
        raise ValueError("next FDE CIE not in frames.txt")
    cstart = u64(cal["start_va"])
    cend = u64(cal["end_va_exclusive"])
    if cal["fde_section_offset"][2:] not in text:
        raise ValueError("callee FDE section offset not in frames.txt")
    if f"pc={cstart:016x}..{cend:016x}" not in text:
        raise ValueError("callee FDE PC range not in frames.txt")
    if f"cie={cal['fde_cie'][2:]}" not in text:
        raise ValueError("callee FDE CIE not in frames.txt")
    if f"pc={u64(cal['next_fde_start']):016x}" not in text:
        raise ValueError("callee-next FDE start not in frames.txt")
    if cal["next_fde_section_offset"][2:] not in text:
        raise ValueError("callee-next FDE section offset not in frames.txt")
    if f"cie={cal['next_fde_cie'][2:]}" not in text:
        raise ValueError("callee-next FDE CIE not in frames.txt")
    for caller in ev["incoming"]["direct_e8_callers"]:
        if caller["fde_section_offset"][2:] not in text:
            raise ValueError("caller FDE section offset not in frames.txt")
        if f"pc={u64(caller['fde_start']):016x}..{u64(caller['fde_end_exclusive']):016x}" not in text:
            raise ValueError("caller FDE PC range not in frames.txt")
        if f"cie={caller['fde_cie'][2:]}" not in text:
            raise ValueError("caller FDE CIE not in frames.txt")


def check_callee(ev, binary, sections):
    cal = ev["callee"]
    start = u64(cal["start_va"])
    end = u64(cal["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != cal["bytes"]:
        raise ValueError(f"callee length {len(body)} != {cal['bytes']}")
    if hashlib.sha256(body).hexdigest() != cal["sha256"]:
        raise ValueError("callee sha256 mismatch")
    for va, hexbytes in CALLEE_INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"callee bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    if u64(cal["field_offset"]) != 0x40:
        raise ValueError("callee field offset must be 0x40")
    nxt = u64(cal["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != cal["padding_bytes"]:
        raise ValueError(f"callee padding length {len(pad)} != {cal['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"callee padding not all int3: {pad.hex()}")


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
    want = [u64(c["site"]) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def evaluate_edge(edge):
    """Check one edge against the round-up-division model."""
    field = u64(edge["field"])
    x = u64(edge["x"])
    t = (field + 1) & 0xFFFFFFFF
    if t != u64(edge["t"]):
        raise ValueError(
            f"edge {edge['note']}: model t {hex(t)} != {edge['t']}")
    if "fault" in edge:
        if edge["fault"] == "div-by-zero":
            if t != 0:
                raise ValueError(
                    f"edge {edge['note']}: div-by-zero edge needs t == 0")
        else:
            raise ValueError(f"edge {edge['note']}: unknown fault kind")
        return
    if t == 0:
        raise ValueError(f"edge {edge['note']}: t == 0 must be a fault edge")
    # ADD writes only RAX; its carry is not propagated into the zeroed RDX.
    # Thus the 128-bit dividend is zero:wrapped_rax. For t > 0 the
    # quotient always fits u64, even when the preceding addition carries.
    dividend = (x + ((t - 1) & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    q, r = divmod(dividend, t)
    if q != u64(edge["q"]):
        raise ValueError(
            f"edge {edge['note']}: model q {hex(q)} != {edge['q']}")
    if r != u64(edge["r"]):
        raise ValueError(
            f"edge {edge['note']}: model r {hex(r)} != {edge['r']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if u64(rule["field_offset"]) != 0x40:
        raise ValueError("field offset must be 0x40")
    if rule["return_register"] != "rax":
        raise ValueError("return register must be rax")
    if rule["x_register"] != "rsi":
        raise ValueError("x register must be rsi")


def run_evidence(ev, binary, sections, packet_dir):
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee(ev, binary, sections)
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
        print("usage: foundation_round_up_division.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation round-up-division evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
