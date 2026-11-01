#!/usr/bin/env python3
"""Checker for the foundation destructor-loop window (node #94, 0x4fbb610).

Stdlib only. Run from the repository root:

    python3 tools/foundation_destructor_loop.py \\
        --check research/work-items/foundation-destructor-loop-94/evidence.json

Every claim is re-derived from target bytes: the 136-byte window body, its
eight int3 padding bytes, the retained FDE records (window, next, and the
five caller FDEs, each locked under its own CIE), the direct call encoding
and the tail jump encoding (both to the operator delete PLT stub, which is
not an FDE start, so no body size is claimed for it), the full direct-
caller scan (five sites), and the destructor-loop rule over the 0x68-
stride elements and the outer buffer on its edges.
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
    0x4FBB610: "f30f1efa",
    0x4FBB614: "4154",
    0x4FBB616: "4989fc",
    0x4FBB619: "55",
    0x4FBB61A: "53",
    0x4FBB61B: "488b6f08",
    0x4FBB61F: "488b1f",
    0x4FBB622: "4839dd",
    0x4FBB625: "7442",
    0x4FBB627: "660f1f840000000000",
    0x4FBB630: "48833b00",
    0x4FBB634: "7407",
    0x4FBB636: "48c70300000000",
    0x4FBB63D: "488b7b50",
    0x4FBB641: "483b7b58",
    0x4FBB645: "7404",
    0x4FBB647: "48897b58",
    0x4FBB64B: "4885ff",
    0x4FBB64E: "7438",
    0x4FBB650: "488b7360",
    0x4FBB654: "4883c368",
    0x4FBB658: "4829fe",
    0x4FBB65B: "e8e04d6a00",
    0x4FBB660: "4839dd",
    0x4FBB663: "75cb",
    0x4FBB665: "498b1c24",
    0x4FBB669: "4885db",
    0x4FBB66C: "7425",
    0x4FBB66E: "498b742410",
    0x4FBB673: "4889df",
    0x4FBB676: "4829de",
    0x4FBB679: "5b",
    0x4FBB67A: "5d",
    0x4FBB67B: "415c",
    0x4FBB67D: "e9be4d6a00",
    0x4FBB682: "660f1f440000",
    0x4FBB688: "4883c368",
    0x4FBB68C: "4839dd",
    0x4FBB68F: "759f",
    0x4FBB691: "ebd2",
    0x4FBB693: "5b",
    0x4FBB694: "5d",
    0x4FBB695: "415c",
    0x4FBB697: "c3",
}

WINDOW_START = 0x4FBB610
CALL_SITE = 0x4FBB65B
TAIL_SITE = 0x4FBB67D
CALL_TARGET = 0x5660440


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
    for caller in ev["incoming"]["direct_e8_callers"]:
        if caller["fde_section_offset"][2:] not in text:
            raise ValueError(
                f"caller FDE offset {caller['fde_section_offset']} "
                "not in frames.txt")
        if f"pc={u64(caller['fde_start']):016x}..{u64(caller['fde_end']):016x}" not in text:
            raise ValueError(
                f"caller FDE range {caller['fde_start']}..{caller['fde_end']} "
                "not in frames.txt")
        if f"cie={caller['fde_cie'][2:]}" not in text:
            raise ValueError(
                f"caller FDE CIE {caller['fde_cie']} not in frames.txt")


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
    tail = u64(call["tail_site"])
    tail_target = u64(call["tail_target"])
    tenc = read_va(binary, sections, tail, 5)
    if tenc[0] != 0xE9:
        raise ValueError(f"tail site is not e9: {tenc.hex()}")
    (trel,) = struct.unpack_from("<i", tenc, 1)
    if tail + 5 + trel != tail_target:
        raise ValueError(
            f"tail target {hex(tail + 5 + trel)} != {hex(tail_target)}")
    if tail != TAIL_SITE:
        raise ValueError("unexpected tail site")
    if tail_target != CALL_TARGET:
        raise ValueError("tail must jump to the same PLT stub")
    if call["target_fde_start"] is not False:
        raise ValueError("callee must be recorded as NOT an FDE start")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")
    # PLT stub: jmp *GOT, push imm32, jmp PLT0 (16 bytes).
    stub = read_va(binary, sections, target, 16)
    if stub.hex() != call["target_bytes"]:
        raise ValueError(f"callee stub bytes mismatch: {stub.hex()}")
    if stub[0] != 0xFF or stub[1] != 0x25:
        raise ValueError("callee stub must start with jmp *GOT")
    if stub[6] != 0x68:
        raise ValueError("callee stub must push an index")
    if stub[11] != 0xE9:
        raise ValueError("callee stub must end with jmp PLT0")
    if call["stride"] != 104:
        raise ValueError("element stride must be 0x68 (104)")


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
    want = [u64(c["site"]) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        ctext = fh.read()
    for c in ev["incoming"]["direct_e8_callers"]:
        if c["site"][2:] not in ctext:
            raise ValueError(
                f"caller site {c['site']} not in caller.objdump.txt")


def simulate(edge):
    """Return (calls, writes, tail) for one edge."""
    calls = []
    writes = []
    for i, el in enumerate(edge["elements"]):
        first = u64(el["first"])
        second = u64(el["second"])
        sync = u64(el["second_sync"])
        end = u64(el["second_end"])
        if first != 0:
            writes.append({"field": "first", "index": i})
        if sync != second:
            writes.append({"field": "second_sync", "index": i})
        if second != 0:
            calls.append({"ptr": hex(second),
                          "size": hex((end - second) & 0xFFFFFFFFFFFFFFFF)})
    outer = edge["outer"]
    optr = u64(outer["ptr"])
    oend = u64(outer["end"])
    tail = None
    if optr != 0:
        tail = {"ptr": hex(optr),
                "size": hex((oend - optr) & 0xFFFFFFFFFFFFFFFF)}
    return (calls, writes, tail)


def evaluate_edge(edge):
    """Check one edge against the destructor-loop model."""
    calls, writes, tail = simulate(edge)
    if calls != edge["calls"]:
        raise ValueError(
            f"edge {edge['note']}: model calls {calls} != {edge['calls']}")
    if writes != edge["writes"]:
        raise ValueError(
            f"edge {edge['note']}: model writes {writes} != {edge['writes']}")
    if tail != edge["tail"]:
        raise ValueError(
            f"edge {edge['note']}: model tail {tail} != {edge['tail']}")


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
        print("usage: foundation_destructor_loop.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation destructor-loop evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
