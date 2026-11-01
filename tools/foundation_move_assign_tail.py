#!/usr/bin/env python3
"""Checker for the foundation move-assign-tail window (node #94, 0x522d940).

Stdlib only. Run from the repository root:

    python3 tools/foundation_move_assign_tail.py \\
        --check research/work-items/foundation-move-assign-tail-94/evidence.json

Every claim is re-derived from target bytes: the 111-byte window body, its
single int3 padding byte, the retained FDE records (window, next, first
caller), the direct call encoding (the callee is the operator delete[]
PLT stub, not an FDE start, and its body is excluded), the full 17-site
direct-caller scan, and the move-assign rule over the 6 inline bytes, the
tail pointer, and the old-tail free on its edges.
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
    0x522D940: "f30f1efa",
    0x522D944: "53",
    0x522D945: "4889fb",
    0x522D948: "4839f7",
    0x522D94B: "745d",
    0x522D94D: "0fb606",
    0x522D950: "8807",
    0x522D952: "0fb64601",
    0x522D956: "c60600",
    0x522D959: "884701",
    0x522D95C: "0fb64602",
    0x522D960: "c6460100",
    0x522D964: "884702",
    0x522D967: "0fb64603",
    0x522D96B: "c6460200",
    0x522D96F: "884703",
    0x522D972: "0fb64604",
    0x522D976: "c6460300",
    0x522D97A: "884704",
    0x522D97D: "0fb64605",
    0x522D981: "c6460400",
    0x522D985: "884705",
    0x522D988: "488b4608",
    0x522D98C: "c6460500",
    0x522D990: "48c7460800000000",
    0x522D998: "488b7f08",
    0x522D99C: "48894308",
    0x522D9A0: "4885ff",
    0x522D9A3: "7405",
    0x522D9A5: "e8d62a4300",
    0x522D9AA: "4889d8",
    0x522D9AD: "5b",
    0x522D9AE: "c3",
}

WINDOW_START = 0x522D940
CALL_SITE = 0x522D9A5
CALL_TARGET = 0x5660480

EXPECTED_CALLERS = [
    0x522DA93, 0x523008B, 0x52302E8, 0x5230357, 0x5232D0A, 0x5233076,
    0x52330C4, 0x52331BA, 0x5233206, 0x5233242, 0x523349F, 0x5233531,
    0x5233CFC, 0x5234296, 0x5234485, 0x52344D1, 0x52344FF,
]


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
    # The next FDE uses a different CIE from the window; each record is
    # locked with its own CIE, never assumed shared.
    if f"cie={fn['next_fde_cie'][2:]}" not in text:
        raise ValueError("next FDE CIE not in frames.txt")
    # First caller FDE record, retained for the first verified caller.
    caller = ev["incoming"]["validated_caller_fdes"][0]
    if caller["fde_section_offset"][2:] not in text:
        raise ValueError("caller FDE section offset not in frames.txt")
    if "pc=000000000522d9e0..000000000522daab" not in text:
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
    if site != CALL_SITE:
        raise ValueError("unexpected call site")
    if call["target_fde_start"] is not False:
        raise ValueError("callee must be recorded as NOT an FDE start")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")
    # PLT stub bytes: jmp *GOT, push imm, jmp PLT0.
    stub = read_va(binary, sections, target, 16)
    if stub.hex() != call["target_plt_stub"]:
        raise ValueError(f"PLT stub bytes mismatch: {stub.hex()}")
    if hashlib.sha256(stub).hexdigest() != call["target_plt_stub_sha256"]:
        raise ValueError("PLT stub sha256 mismatch")


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
    if found != EXPECTED_CALLERS:
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != [hex(f) for f in EXPECTED_CALLERS]:
        raise ValueError("evidence caller list mismatch")
    callers = ev["incoming"]["validated_caller_fdes"]
    if len(callers) != 1 or callers[0]["site"] != "0x522da93":
        raise ValueError("evidence validated-caller list must hold 0x522da93")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller_text = fh.read()
    if "call   522d940" not in caller_text:
        raise ValueError("caller disassembly lacks the call to the window")


def simulate(edge):
    """Return (dest_bytes, dest_tail, src_bytes, src_tail, calls, call_arg)."""
    if edge["self_assign"]:
        return (edge["dest_bytes_in"], u64(edge["dest_tail_in"]),
                edge["src_bytes_in"], u64(edge["src_tail_in"]), 0, None)
    dest_tail_old = u64(edge["dest_tail_in"])
    src_tail_old = u64(edge["src_tail_in"])
    calls = 1 if dest_tail_old != 0 else 0
    call_arg = hex(dest_tail_old) if calls else None
    return (edge["src_bytes_in"], src_tail_old, [0] * 6, 0, calls, call_arg)


def evaluate_edge(edge):
    """Check one edge against the move-assign model."""
    dest_bytes, dest_tail, src_bytes, src_tail, calls, call_arg = simulate(edge)
    if dest_bytes != edge["dest_bytes_out"]:
        raise ValueError(
            f"edge {edge['note']}: dest bytes {dest_bytes} != "
            f"{edge['dest_bytes_out']}")
    if dest_tail != u64(edge["dest_tail_out"]):
        raise ValueError(
            f"edge {edge['note']}: dest tail {hex(dest_tail)} != "
            f"{edge['dest_tail_out']}")
    if src_bytes != edge["src_bytes_out"]:
        raise ValueError(
            f"edge {edge['note']}: src bytes {src_bytes} != "
            f"{edge['src_bytes_out']}")
    if src_tail != u64(edge["src_tail_out"]):
        raise ValueError(
            f"edge {edge['note']}: src tail {hex(src_tail)} != "
            f"{edge['src_tail_out']}")
    if calls != edge["calls"]:
        raise ValueError(
            f"edge {edge['note']}: model calls {calls} != {edge['calls']}")
    if call_arg != edge["call_arg"]:
        raise ValueError(
            f"edge {edge['note']}: model call arg {call_arg} != "
            f"{edge['call_arg']}")
    # The untouched gap bytes [6..8) must survive on both structs.
    if edge["dest_gap_in"] != edge["dest_gap_out"]:
        raise ValueError(f"edge {edge['note']}: dest gap bytes changed")
    if edge["src_gap_in"] != edge["src_gap_out"]:
        raise ValueError(f"edge {edge['note']}: src gap bytes changed")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)


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
        print("usage: foundation_move_assign_tail.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation move-assign-tail evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
