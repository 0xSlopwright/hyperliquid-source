#!/usr/bin/env python3
"""Checker for the foundation all-empty-gate window (node #94, 0x50a90a0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_all_empty_gate.py \\
        --check research/work-items/foundation-all-empty-gate-94/evidence.json

Every claim is re-derived from target bytes: the 109-byte window body, its
three int3 padding bytes, the retained FDE records (window, next, shared
callee), the direct call encoding (the callee is a 5-byte endbr64;ret
no-op FDE start, and its body beyond those 5 bytes is excluded), the
full direct-caller scan (zero sites), and the all-empty-gate rule over
the five qword pairs and the 32-bit counter decrement on its edges.
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
    0x50A90A0: "f30f1efa",
    0x50A90A4: "488b07",
    0x50A90A7: "488b5008",
    0x50A90AB: "48395010",
    0x50A90AF: "7407",
    0x50A90B1: "c3",
    0x50A90B2: "660f1f440000",
    0x50A90B8: "488b4838",
    0x50A90BC: "48394840",
    0x50A90C0: "75ef",
    0x50A90C2: "488b7068",
    0x50A90C6: "48397070",
    0x50A90CA: "75e5",
    0x50A90CC: "488bb080000000",
    0x50A90D3: "4839b088000000",
    0x50A90DA: "75d5",
    0x50A90DC: "488bb0b0000000",
    0x50A90E3: "4839b0b8000000",
    0x50A90EA: "75c5",
    0x50A90EC: "53",
    0x50A90ED: "488b4708",
    0x50A90F1: "4889fb",
    0x50A90F4: "488db800070000",
    0x50A90FB: "e860bc2800",
    0x50A9100: "488b4308",
    0x50A9104: "83a89c14000001",
    0x50A910B: "5b",
    0x50A910C: "c3",
}

WINDOW_START = 0x50A90A0
CALL_SITE = 0x50A90FB
CALL_TARGET = 0x5334D60


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
    if fn["next_fde_section_offset"][2:] not in text:
        raise ValueError("next FDE section offset not in frames.txt")
    if f"cie={fn['next_fde_cie'][2:]}" not in text:
        raise ValueError("next FDE CIE not in frames.txt")
    # Shared callee FDE record: a 5-byte endbr64;ret no-op, locked by
    # offset, PC range, and CIE; its body beyond those bytes is excluded.
    call = ev["call"]
    if call["target_fde_section_offset"][2:] not in text:
        raise ValueError("callee FDE section offset not in frames.txt")
    if "pc=0000000005334d60..0000000005334d65" not in text:
        raise ValueError("callee FDE PC range not in frames.txt")
    if f"cie={call['target_fde_cie'][2:]}" not in text:
        raise ValueError("callee FDE CIE not in frames.txt")


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
    if site != CALL_SITE:
        raise ValueError("unexpected call site")
    if call["target_fde_start"] is not True:
        raise ValueError("callee must be recorded as an FDE start")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")
    if call["target_fde_bytes"] != 5:
        raise ValueError("callee FDE extent must be 5 bytes")
    # Callee body: exactly endbr64;ret, a no-op stub.
    stub = read_va(binary, sections, target, 5)
    if stub.hex() != call["target_bytes"]:
        raise ValueError(f"callee body bytes mismatch: {stub.hex()}")
    if call["target_bytes"] != "f30f1efac3":
        raise ValueError("callee body must be endbr64;ret")
    if call["call_arg_offset"] != "0x700":
        raise ValueError("callee argument offset must be 0x700")
    if call["counter_offset"] != "0x149c":
        raise ValueError("counter offset must be 0x149c")


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
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != []:
        raise ValueError("evidence caller list must be empty")


def simulate(edge):
    """Return (calls, counter_out) for one edge."""
    pairs = [(u64(a), u64(b)) for a, b in edge["pairs"]]
    if len(pairs) != 5:
        raise ValueError("edge must carry exactly five pairs")
    if all(a == b for a, b in pairs):
        return (1, (u64(edge["counter_in"]) - 1) & 0xFFFFFFFF)
    return (0, u64(edge["counter_in"]))


def evaluate_edge(edge):
    """Check one edge against the all-empty-gate model."""
    calls, counter_out = simulate(edge)
    if calls != edge["calls"]:
        raise ValueError(
            f"edge {edge['note']}: model calls {calls} != {edge['calls']}")
    if counter_out != u64(edge["counter_out"]):
        raise ValueError(
            f"edge {edge['note']}: model counter {hex(counter_out)} != "
            f"{edge['counter_out']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)


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
        print("usage: foundation_all_empty_gate.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation all-empty-gate evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
