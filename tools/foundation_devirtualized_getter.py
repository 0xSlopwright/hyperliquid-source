#!/usr/bin/env python3
"""Checker for the foundation devirtualized-getter window (node #94, 0x514b620).

Stdlib only. Run from the repository root:

    python3 tools/foundation_devirtualized_getter.py \\
        --check research/work-items/foundation-devirtualized-getter-94/evidence.json

Every claim is re-derived from target bytes: the 101-byte window body, its
eleven int3 padding bytes, the retained FDE records (window, next, the
known getter, and the FDE after the getter, each locked under its own CIE),
the 9-byte getter body, the global slot's .rela.dyn RELATIVE relocation to
that getter, the register-indirect virtual call encoding, the full direct-
caller scan (zero sites), and the devirtualized-getter rule on its edges.
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
    0x514B620: "f30f1efa",
    0x514B624: "488bba00120000",
    0x514B62B: "4881c2e0110000",
    0x514B632: "4839d7",
    0x514B635: "7421",
    0x514B637: "488b07",
    0x514B63A: "488b00",
    0x514B63D: "483b05dcc96200",
    0x514B644: "7522",
    0x514B646: "488b4708",
    0x514B64A: "488906",
    0x514B64D: "b801000000",
    0x514B652: "c3",
    0x514B653: "0f1f440000",
    0x514B658: "31c0",
    0x514B65A: "488906",
    0x514B65D: "b801000000",
    0x514B662: "c3",
    0x514B663: "0f1f440000",
    0x514B668: "4883ec18",
    0x514B66C: "4889742408",
    0x514B671: "ffd0",
    0x514B673: "488b742408",
    0x514B678: "488906",
    0x514B67B: "b801000000",
    0x514B680: "4883c418",
    0x514B684: "c3",
}

GETTER_INSTR = {
    0x4FA7E80: "f30f1efa",
    0x4FA7E84: "488b4708",
    0x4FA7E88: "c3",
}

WINDOW_START = 0x514B620
GETTER_START = 0x4FA7E80
GLOBAL_SLOT = 0x5778020


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
    # Branch targets: je lands on the zero path, jne on the virtual path.
    if 0x514B637 + 0x21 != 0x514B658:
        raise ValueError("je target is not the zero path")
    if 0x514B646 + 0x22 != 0x514B668:
        raise ValueError("jne target is not the virtual path")
    # The global-slot comparison must read slot 0x5778020 via rip-relative.
    enc = read_va(binary, sections, 0x514B63D, 7)
    (disp,) = struct.unpack_from("<i", enc, 3)
    if 0x514B644 + disp != GLOBAL_SLOT:
        raise ValueError(
            f"global slot {hex(0x514B644 + disp)} != {hex(GLOBAL_SLOT)}")
    # The only call must be register-indirect: call *%rax.
    if read_va(binary, sections, 0x514B671, 2) != bytes.fromhex("ffd0"):
        raise ValueError("virtual call site is not call *%rax")


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
    gt = ev["getter"]
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
    gstart = u64(gt["start_va"])
    gend = u64(gt["end_va_exclusive"])
    if gt["fde_section_offset"][2:] not in text:
        raise ValueError("getter FDE section offset not in frames.txt")
    if f"pc={gstart:016x}..{gend:016x}" not in text:
        raise ValueError("getter FDE PC range not in frames.txt")
    if f"cie={gt['fde_cie'][2:]}" not in text:
        raise ValueError("getter FDE CIE not in frames.txt")
    if f"pc={u64(gt['next_fde_start']):016x}" not in text:
        raise ValueError("getter-next FDE start not in frames.txt")
    if gt["next_fde_section_offset"][2:] not in text:
        raise ValueError("getter-next FDE section offset not in frames.txt")
    if f"cie={gt['next_fde_cie'][2:]}" not in text:
        raise ValueError("getter-next FDE CIE not in frames.txt")


def check_getter(ev, binary, sections):
    gt = ev["getter"]
    start = u64(gt["start_va"])
    end = u64(gt["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != gt["bytes"]:
        raise ValueError(f"getter length {len(body)} != {gt['bytes']}")
    if hashlib.sha256(body).hexdigest() != gt["sha256"]:
        raise ValueError("getter sha256 mismatch")
    for va, hexbytes in GETTER_INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"getter bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    nxt = u64(gt["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != gt["padding_bytes"]:
        raise ValueError(f"getter padding length {len(pad)} != {gt['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"getter padding not all int3: {pad.hex()}")
    # The global slot must resolve to the getter via a RELATIVE relocation.
    glob = ev["global"]
    if u64(glob["slot_va"]) != GLOBAL_SLOT:
        raise ValueError("unexpected global slot")
    if u64(glob["reloc_addend"]) != GETTER_START:
        raise ValueError("global reloc addend is not the getter")
    if glob["reloc_type"] != "R_X86_64_RELATIVE":
        raise ValueError("global reloc is not RELATIVE")
    addr, off, size = sections[".rela.dyn"]
    found = False
    for i in range(size // 24):
        (o, info, add) = struct.unpack_from("<QQq", binary, off + i * 24)
        if o == GLOBAL_SLOT:
            if (info & 0xFFFFFFFF) != 8:
                raise ValueError(f"global reloc type {info & 0xffffffff} != 8")
            if (add & 0xFFFFFFFFFFFFFFFF) != GETTER_START:
                raise ValueError("global reloc addend mismatch in .rela.dyn")
            found = True
    if not found:
        raise ValueError("global slot has no .rela.dyn entry")


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
    """Check one edge against the devirtualized-getter model."""
    elem = u64(edge["elem"])
    sentinel = u64(edge["sentinel"])
    vf = u64(edge["first_vfunc"])
    if "base" in edge:
        if sentinel != (u64(edge["base"]) + 0x11E0):
            raise ValueError(
                f"edge {edge['note']}: sentinel is not base + 0x11e0")
    if elem == sentinel:
        out, called = 0, False
    elif vf == GETTER_START:
        out, called = u64(edge["field8"]), False
    else:
        out, called = u64(edge["call_result"]), True
    if out != u64(edge["out"]):
        raise ValueError(
            f"edge {edge['note']}: model out {hex(out)} != {edge['out']}")
    if called != edge["called"]:
        raise ValueError(
            f"edge {edge['note']}: model called {called} != {edge['called']}")
    if edge["ret"] != 1:
        raise ValueError(f"edge {edge['note']}: return must be 1")
    if "call_args" in edge:
        want = [hex(elem), "out", hex(sentinel), "entry-rcx"]
        if edge["call_args"] != want:
            raise ValueError(
                f"edge {edge['note']}: call args {edge['call_args']} != {want}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if u64(rule["elem_offset"]) != 0x1200:
        raise ValueError("elem offset must be 0x1200")
    if u64(rule["sentinel_delta"]) != 0x11E0:
        raise ValueError("sentinel delta must be 0x11e0")
    if u64(rule["field_offset"]) != 0x8:
        raise ValueError("field offset must be 0x8")
    if rule["return_value"] != 1:
        raise ValueError("return value must be 1")


def run_evidence(ev, binary, sections, packet_dir):
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_getter(ev, binary, sections)
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
        print("usage: foundation_devirtualized_getter.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation devirtualized-getter evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
