#!/usr/bin/env python3
"""Checker for the foundation length-prefix encode window (node #94, 0x5571600).

Stdlib only. Run from the repository root:

    python3 tools/foundation_length_prefix_encode.py \\
        --check research/work-items/foundation-length-prefix-encode-94/evidence.json

Every claim is re-derived from target bytes: the 148-byte window body, its
twelve int3 padding bytes, the retained FDE records (window, next, caller),
the memcpy@plt call encoding (the callee is a PLT stub, not an FDE start),
the single verified direct e8 caller in .text, and the length-prefix encode
rule over capacity, length, and the header on its edges.
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
    0x5571600: "f30f1efa",
    0x5571604: "4989d0",
    0x5571607: "53",
    0x5571608: "4889ca",
    0x557160B: "4883f91f",
    0x557160F: "772f",
    0x5571611: "488d5901",
    0x5571615: "4839de",
    0x5571618: "726e",
    0x557161A: "8d04cd00000000",
    0x5571621: "8807",
    0x5571623: "b801000000",
    0x5571628: "4801c7",
    0x557162B: "4c89c6",
    0x557162E: "e8cdea0e00",
    0x5571633: "4889d8",
    0x5571636: "5b",
    0x5571637: "c3",
    0x5571638: "0f1f840000000000",
    0x5571640: "31c0",
    0x5571642: "4881f9ff0f0000",
    0x5571649: "0f97c0",
    0x557164C: "83c002",
    0x557164F: "4863d8",
    0x5571652: "4801cb",
    0x5571655: "4839de",
    0x5571658: "722e",
    0x557165A: "83f803",
    0x557165D: "7511",
    0x557165F: "89c8",
    0x5571661: "c1e004",
    0x5571664: "83c00c",
    0x5571667: "8907",
    0x5571669: "b803000000",
    0x557166E: "ebb8",
    0x5571670: "89c8",
    0x5571672: "c1e004",
    0x5571675: "83c004",
    0x5571678: "668907",
    0x557167B: "b802000000",
    0x5571680: "eba6",
    0x5571682: "660f1f440000",
    0x5571688: "48c7c3baffffff",
    0x557168F: "4889d8",
    0x5571692: "5b",
    0x5571693: "c3",
}

WINDOW_START = 0x5571600
CALL_SITE = 0x557162E
CALL_TARGET = 0x5660100
# Full 16-byte memcpy@plt stub, from the retained disassembly.
PLT_STUB = "ff25a28c11006801000000e9d0ffffff"
FAIL_RESULT = 0xFFFFFFFFFFFFFFBA


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
    # Caller FDE record.
    if "002d1784" not in text:
        raise ValueError("caller FDE section offset not in frames.txt")
    if "pc=00000000055739f0..0000000005573f89" not in text:
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
    if call["target_fde_start"] is not False:
        raise ValueError("callee must be recorded as not an FDE start")
    if call["target_fde_extent"] is not None:
        raise ValueError("PLT callee must have no FDE extent")
    if call["target_fde_section_offset"] is not None:
        raise ValueError("PLT callee must have no FDE section offset")
    stub = read_va(binary, sections, target, len(PLT_STUB) // 2)
    if stub.hex() != PLT_STUB:
        raise ValueError(f"PLT stub bytes mismatch: {stub.hex()}")
    if call["target_bytes"] != PLT_STUB:
        raise ValueError("recorded PLT stub bytes mismatch")


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
    if found != [0x5573B9C]:
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != ["0x5573b9c"]:
        raise ValueError("evidence caller list mismatch")
    if ev["incoming"]["validated_caller_fdes"] != ["0x55739f0"]:
        raise ValueError("evidence validated-caller list mismatch")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    if "5573b9c:" not in caller or "5571600" not in caller:
        raise ValueError("caller disassembly does not retain the call site")


def header_and_total(length):
    """Return (header_bytes, total) exactly as the window computes them."""
    if length <= 0x1F:
        return bytes([(length * 8) & 0xFF]), length + 1
    if length <= 0xFFF:
        return ((length * 16 + 4) & 0xFFFF).to_bytes(2, "little"), length + 2
    return (((length & 0xFFFFFFFF) * 16 + 12) & 0xFFFFFFFF).to_bytes(
        4, "little"), length + 3


def evaluate_rule(capacity, length):
    """Return (result_u64, header_or_None, total_or_None)."""
    header, total = header_and_total(length)
    if capacity < total:
        return FAIL_RESULT, None, None
    return total, header, total


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        capacity = u64(edge["capacity"])
        length = u64(edge["length"])
        data = bytes.fromhex(edge["data_hex"])
        result, header, total = evaluate_rule(capacity, length)
        if result != u64(edge["result"]):
            raise ValueError(
                f"edge {edge['note']}: model {hex(result)} != recorded "
                f"{edge['result']}")
        if header is None:
            if edge["header_hex"] is not None:
                raise ValueError(
                    f"edge {edge['note']}: failure edge must have no header")
            if edge["total"] is not None:
                raise ValueError(
                    f"edge {edge['note']}: failure edge must have no total")
            if edge["output_hex"] is not None:
                raise ValueError(
                    f"edge {edge['note']}: failure edge must write nothing")
        else:
            if edge["header_hex"] != header.hex():
                raise ValueError(
                    f"edge {edge['note']}: header {header.hex()} != recorded "
                    f"{edge['header_hex']}")
            if edge["total"] != total:
                raise ValueError(
                    f"edge {edge['note']}: total {total} != recorded "
                    f"{edge['total']}")
            if edge["copy_content_checked"]:
                if len(data) != length:
                    raise ValueError(
                        f"edge {edge['note']}: checked data length "
                        f"{len(data)} != {length}")
                if edge["output_hex"] != (header + data).hex():
                    raise ValueError(
                        f"edge {edge['note']}: output mismatch")


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
        print("usage: foundation_length_prefix_encode.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation length-prefix encode evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
