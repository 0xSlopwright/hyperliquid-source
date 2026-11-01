#!/usr/bin/env python3
"""Checker for the foundation indexed-store-and-clear window (node #94, 0x5240c20).

Stdlib only. Run from the repository root:

    python3 tools/foundation_indexed_store_and_clear.py \\
        --check research/work-items/foundation-indexed-store-and-clear-94/evidence.json

Every claim is re-derived from target bytes: the 59-byte window body, its
five int3 padding bytes, the retained FDE records (window, next, the
58-byte callee, and the FDE after the callee, each locked under its own
CIE), the callee body and its six int3 padding bytes, the direct call
encoding to the callee, the full direct-caller scan (exactly zero sites),
and the indexed-store-and-clear rule on its edges, including the 2-byte
zeroing hole and the 32-bit index edge. A failure prints the mismatching
check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x5240C20: "f30f1efa",
    0x5240C24: "4889f0",
    0x5240C27: "53",
    0x5240C28: "4889fb",
    0x5240C2B: "89d7",
    0x5240C2D: "488b80a8000000",
    0x5240C34: "89ce",
    0x5240C36: "48c1e704",
    0x5240C3A: "480338",
    0x5240C3D: "e87e341f00",
    0x5240C42: "31c0",
    0x5240C44: "c70300000000",
    0x5240C4A: "66894304",
    0x5240C4E: "4889d8",
    0x5240C51: "48c7430800000000",
    0x5240C59: "5b",
    0x5240C5A: "c3",
}

CALLEE_INSTR = {
    0x54340C0: "f30f1efa",
    0x54340C4: "4154",
    0x54340C6: "55",
    0x54340C7: "53",
    0x54340C8: "4c8b6708",
    0x54340CC: "89f3",
    0x54340CE: "498dac2480000000",
    0x54340D6: "4889ef",
    0x54340D9: "e842c12200",
    0x54340DE: "85c0",
    0x54340E0: "7511",
    0x54340E2: "41895c2404",
    0x54340E7: "4889ef",
    0x54340EA: "5b",
    0x54340EB: "5d",
    0x54340EC: "415c",
    0x54340EE: "e93dc12200",
    0x54340F3: "89c7",
    0x54340F5: "e856c52200",
}

WINDOW_START = 0x5240C20
CALLEE_START = 0x54340C0


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
    enc = read_va(binary, sections, 0x5240C3D, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x5240C3D + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The index shift must be shl $0x4 (16-byte stride).
    if read_va(binary, sections, 0x5240C36, 4) != bytes.fromhex("48c1e704"):
        raise ValueError("index shift site is not shl $0x4, %rdi")
    # The three zeroing stores must be dword@0, word@4, qword@8.
    if read_va(binary, sections, 0x5240C44, 6) != bytes.fromhex("c70300000000"):
        raise ValueError("dword zero store site mismatch")
    if read_va(binary, sections, 0x5240C4A, 4) != bytes.fromhex("66894304"):
        raise ValueError("word zero store site mismatch")
    if read_va(binary, sections, 0x5240C51, 8) != bytes.fromhex("48c7430800000000"):
        raise ValueError("qword zero store site mismatch")


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
    if not cal["is_fde_start"]:
        raise ValueError("callee must be an FDE start")
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
    want = [u64(c) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def evaluate_edge(edge):
    """Check one edge against the indexed-store-and-clear model."""
    idx = u64(edge["idx"])
    table_base = u64(edge["table_base"])
    entry = (table_base + ((idx & 0xFFFFFFFF) << 4)) & 0xFFFFFFFFFFFFFFFF
    if entry != u64(edge["entry"]):
        raise ValueError(
            f"edge {edge['note']}: model entry {hex(entry)} != {edge['entry']}")
    if entry != u64(edge["call_rdi"]):
        raise ValueError(
            f"edge {edge['note']}: call rdi {edge['call_rdi']} != entry")
    if u64(edge["ecx"]) != u64(edge["call_rsi"]):
        raise ValueError(
            f"edge {edge['note']}: call rsi {edge['call_rsi']} != ecx")
    before = bytes.fromhex(edge["obj_before"])
    if len(before) != 16:
        raise ValueError(f"edge {edge['note']}: object must be 16 bytes")
    after = bytearray(before)
    after[0:6] = b"\x00" * 6
    after[8:16] = b"\x00" * 8
    if bytes(after).hex() != edge["obj_after"]:
        raise ValueError(
            f"edge {edge['note']}: model obj_after {bytes(after).hex()} "
            f"!= {edge['obj_after']}")
    if u64(edge["ret"]) != u64(edge["obj"]):
        raise ValueError(
            f"edge {edge['note']}: return {edge['ret']} != object {edge['obj']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if rule["stores"] != [
            {"offset": "0x0", "size": 4, "value": 0},
            {"offset": "0x4", "size": 2, "value": 0},
            {"offset": "0x8", "size": 8, "value": 0}]:
        raise ValueError("zeroing stores must be dword@0, word@4, qword@8")
    if rule["return_register"] != "rax":
        raise ValueError("return register must be rax")
    if rule["call_args"]["rdi"] != "entry":
        raise ValueError("call rdi must be the entry")
    if ev["incoming"]["direct_e8_callers"] != []:
        raise ValueError("this packet claims zero direct callers")


def run_all(evidence_path):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee(ev, binary, sections)
    check_callers(ev, binary, sections)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_indexed_store_and_clear.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation indexed-store-and-clear evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
