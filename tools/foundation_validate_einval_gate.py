#!/usr/bin/env python3
"""Checker for the foundation validate-or-EINVAL gate window (node #94, 0x54e1b10).

Stdlib only. Run from the repository root:

    python3 tools/foundation_validate_einval_gate.py \\
        --check research/work-items/foundation-validate-einval-gate-94/evidence.json

Every claim is re-derived from target bytes: the 110-byte window body, its
two int3 padding bytes, the retained FDE records (window, next, callee),
the direct call encoding (the callee IS an FDE start, but its body is
excluded), the empty direct-caller scan over .text, and the
validate-or-fail rule over five gate conditions on its edges.
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
    0x54E1B10: "f30f1efa",
    0x54E1B14: "4885c9",
    0x54E1B17: "745f",
    0x54E1B19: "4d85c0",
    0x54E1B1C: "745a",
    0x54E1B1E: "4883ec08",
    0x54E1B22: "48837c241008",
    0x54E1B28: "0f95c0",
    0x54E1B2B: "4d85c9",
    0x54E1B2E: "0f94c2",
    0x54E1B31: "08d0",
    0x54E1B33: "7506",
    0x54E1B35: "49833830",
    0x54E1B39: "740d",
    0x54E1B3B: "b816000000",
    0x54E1B40: "4883c408",
    0x54E1B44: "c3",
    0x54E1B45: "0f1f00",
    0x54E1B48: "4c8d4128",
    0x54E1B4C: "498b31",
    0x54E1B4F: "51",
    0x54E1B50: "4c8d5110",
    0x54E1B54: "4150",
    0x54E1B56: "488d5108",
    0x54E1B5A: "4c8d4920",
    0x54E1B5E: "4c8d4118",
    0x54E1B62: "4c89d1",
    0x54E1B65: "e8465a0400",
    0x54E1B6A: "58",
    0x54E1B6B: "5a",
    0x54E1B6C: "31c0",
    0x54E1B6E: "4883c408",
    0x54E1B72: "c3",
    0x54E1B73: "0f1f440000",
    0x54E1B78: "b816000000",
    0x54E1B7D: "c3",
}

WINDOW_START = 0x54E1B10
CALL_SITE = 0x54E1B65
CALL_TARGET = 0x55275B0
FAIL_RESULT = 0x16
PASS_RESULT = 0x0


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
    if "pc=00000000055275b0..0000000005527992" not in text:
        raise ValueError("callee FDE PC range not in frames.txt")


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
    if call["target_fde_extent"] != 994:
        raise ValueError("callee FDE extent must be 994")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")


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
    if ev["incoming"]["validated_caller_fdes"] != []:
        raise ValueError("evidence validated-caller list must be empty")


def evaluate_gate(edge):
    """Return (result_u64, callee_args_or_None) exactly as the window computes."""
    rcx_zero = edge["rcx_zero"]
    r8_zero = edge["r8_zero"]
    r9_zero = edge["r9_zero"]
    stack_arg = u64(edge["stack_arg"])
    pointee = None if edge["pointee"] is None else u64(edge["pointee"])
    if rcx_zero or r8_zero or r9_zero or stack_arg != 8 or pointee != 0x30:
        return FAIL_RESULT, None
    base = u64(edge["rcx_value"])
    args = {
        "rdi": "passthrough",
        "rsi": hex(pointee),
        "rdx": hex(base + 8),
        "rcx": hex(base + 0x10),
        "r8": hex(base + 0x18),
        "r9": hex(base + 0x20),
        "stack7": hex(base + 0x28),
        "stack8": hex(base),
    }
    return PASS_RESULT, args


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        result, args = evaluate_gate(edge)
        if result != u64(edge["result"]):
            raise ValueError(
                f"edge {edge['note']}: model {hex(result)} != recorded "
                f"{edge['result']}")
        if args is None:
            if edge["callee_args"] is not None:
                raise ValueError(
                    f"edge {edge['note']}: failure edge must have no "
                    f"callee args")
        else:
            if edge["callee_args"] != args:
                raise ValueError(
                    f"edge {edge['note']}: callee args {args} != recorded "
                    f"{edge['callee_args']}")


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
        print("usage: foundation_validate_einval_gate.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation validate-or-EINVAL gate evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
