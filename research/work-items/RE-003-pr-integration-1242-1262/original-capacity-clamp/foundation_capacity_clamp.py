#!/usr/bin/env python3
"""Checker for the foundation capacity-clamp window (node #94, 0x4f050a0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_capacity_clamp.py \\
        --check research/work-items/foundation-capacity-clamp-94/evidence.json

Every claim is re-derived from target bytes: the 110-byte window body, its
two int3 padding bytes, the retained FDE records (window, next, callee,
caller), the direct call encoding (the callee IS an FDE start, but its body
is excluded), the single direct caller verified as an instruction start from
its FDE, and the capacity-clamp rule over the clamp formula and the callee
flag byte on its edges.
A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
# The window starts with push rbp, not endbr64.
INSTR = {
    0x4F050A0: "55",
    0x4F050A1: "4889e5",
    0x4F050A4: "4156",
    0x4F050A6: "53",
    0x4F050A7: "4883ec20",
    0x4F050AB: "4889fb",
    0x4F050AE: "48ffc6",
    0x4F050B1: "488b07",
    0x4F050B4: "488d0c00",
    0x4F050B8: "4839ce",
    0x4F050BB: "480f46f1",
    0x4F050BF: "4883fe05",
    0x4F050C3: "41be04000000",
    0x4F050C9: "4c0f43f6",
    0x4F050CD: "488b5708",
    0x4F050D1: "488d7dd8",
    0x4F050D5: "4889c6",
    0x4F050D8: "4c89f1",
    0x4F050DB: "e850feffff",
    0x4F050E0: "807dd800",
    0x4F050E4: "740a",
    0x4F050E6: "488b45e0",
    0x4F050EA: "488b55e8",
    0x4F050EE: "eb15",
    0x4F050F0: "488b45e0",
    0x4F050F4: "48894308",
    0x4F050F8: "4c8933",
    0x4F050FB: "48b80100000000000080",
    0x4F05105: "4883c420",
    0x4F05109: "5b",
    0x4F0510A: "415e",
    0x4F0510C: "5d",
    0x4F0510D: "c3",
}

WINDOW_START = 0x4F050A0
CALL_SITE = 0x4F050DB
CALL_TARGET = 0x4F04F30
SENTINEL = 0x8000000000000001
MASK = 0xFFFFFFFFFFFFFFFF


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
    # Callee FDE record: the callee IS an FDE start, but its body is excluded.
    call = ev["call"]
    if call["target_fde_section_offset"][2:] not in text:
        raise ValueError("callee FDE section offset not in frames.txt")
    if "pc=0000000004f04f30..0000000004f04fc0" not in text:
        raise ValueError("callee FDE PC range not in frames.txt")
    # Caller FDE record, retained for the single verified caller.
    caller = ev["incoming"]["validated_caller_fdes"][0]
    if caller["fde_section_offset"][2:] not in text:
        raise ValueError("caller FDE section offset not in frames.txt")
    if "pc=0000000004f04a30..0000000004f04a59" not in text:
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
    if call["target_fde_extent"] != 144:
        raise ValueError("callee FDE extent must be 144")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")


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
    if found != [0x4F04A37]:
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != ["0x4f04a37"]:
        raise ValueError("evidence caller list must be exactly [0x4f04a37]")
    callers = ev["incoming"]["validated_caller_fdes"]
    if len(callers) != 1 or callers[0]["site"] != "0x4f04a37":
        raise ValueError("evidence validated-caller list must hold 0x4f04a37")
    if callers[0]["sentinel_check"] is not True:
        raise ValueError("caller sentinel check must be recorded")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller_text = fh.read()
    if "call   4f050a0" not in caller_text:
        raise ValueError("caller disassembly lacks the call to the window")
    if "0x8000000000000001" not in caller_text:
        raise ValueError("caller disassembly lacks the sentinel constant")


def newcap(oldcap, req):
    """The clamp exactly as the window computes it, over wrapping u64."""
    return max(4, min((req + 1) & MASK, (2 * oldcap) & MASK))


def evaluate_edge(edge):
    """Return (result_u64, pair_or_None, stored_or_None) for one edge."""
    cap = newcap(u64(edge["oldcap"]), u64(edge["req"]))
    if cap != u64(edge["newcap"]):
        raise ValueError(
            f"edge {edge['note']}: model newcap {hex(cap)} != recorded "
            f"{edge['newcap']}")
    if edge["flag"] == 0:
        stored = {"cap": edge["newcap"], "ptr": edge["out_qword1"]}
        return SENTINEL, None, stored
    pair = {"rax": edge["out_qword1"], "rdx": edge["out_qword2"]}
    return u64(edge["out_qword1"]), pair, None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        result, pair, stored = evaluate_edge(edge)
        if result != u64(edge["result"]):
            raise ValueError(
                f"edge {edge['note']}: model {hex(result)} != recorded "
                f"{edge['result']}")
        if pair != edge["pair"]:
            raise ValueError(
                f"edge {edge['note']}: model pair {pair} != recorded "
                f"{edge['pair']}")
        if stored != edge["stored"]:
            raise ValueError(
                f"edge {edge['note']}: model stored {stored} != recorded "
                f"{edge['stored']}")


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
        print("usage: foundation_capacity_clamp.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation capacity-clamp evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
