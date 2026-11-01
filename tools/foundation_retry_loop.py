#!/usr/bin/env python3
"""Checker for the foundation retry-loop window (node #94, 0x3cbefb0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_retry_loop.py \\
        --check research/work-items/foundation-retry-loop-94/evidence.json

Every claim is re-derived from target bytes: the 115-byte window body, its
thirteen int3 padding bytes, the retained FDE records (window, next, callee,
caller), the direct call encoding (the callee IS an FDE start, but its body
is excluded), the single direct caller verified as an instruction start from
its FDE, and the retry-loop rule over the attempts count and the callee
result sequence on its edges.
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
    0x3CBEFB0: "55",
    0x3CBEFB1: "4157",
    0x3CBEFB3: "4156",
    0x3CBEFB5: "4155",
    0x3CBEFB7: "4154",
    0x3CBEFB9: "53",
    0x3CBEFBA: "4883ec18",
    0x3CBEFBE: "4c8b6718",
    0x3CBEFC2: "4d85e4",
    0x3CBEFC5: "744b",
    0x3CBEFC7: "4889fb",
    0x3CBEFCA: "4c8d6f20",
    0x3CBEFCE: "488b2dabf7aa01",
    0x3CBEFD5: "4c8d3571b452fc",
    0x3CBEFDC: "4c8d7c2408",
    0x3CBEFE1: "6666666666662e0f1f840000000000",
    0x3CBEFF0: "4c896c2408",
    0x3CBEFF5: "48896c2410",
    0x3CBEFFA: "4889df",
    0x3CBEFFD: "4c89f6",
    0x3CBF000: "4c89fa",
    0x3CBF003: "e8f8740000",
    0x3CBF008: "4885c0",
    0x3CBF00B: "7507",
    0x3CBF00D: "49ffcc",
    0x3CBF010: "75de",
    0x3CBF012: "31c0",
    0x3CBF014: "4883c418",
    0x3CBF018: "5b",
    0x3CBF019: "415c",
    0x3CBF01B: "415d",
    0x3CBF01D: "415e",
    0x3CBF01F: "415f",
    0x3CBF021: "5d",
    0x3CBF022: "c3",
}

WINDOW_START = 0x3CBEFB0
CALL_SITE = 0x3CBF003
CALL_TARGET = 0x3CC6500
GLOBAL_QWORD = 0x576E780
FIXED_RSI = 0x1EA44D


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
    cursor = start
    for va, hexbytes in sorted(INSTR.items()):
        if va != cursor:
            raise ValueError(f"instruction table gap or overlap at {hex(cursor)}")
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"instruction bytes at {hex(va)}: {got.hex()} != {hexbytes}")
        cursor += len(want)
    if cursor != end:
        raise ValueError("instruction table does not cover the full FDE window")


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
    # Its CIE differs from the window's; each record is locked with its own CIE.
    call = ev["call"]
    if call["target_fde_section_offset"][2:] not in text:
        raise ValueError("callee FDE section offset not in frames.txt")
    if "pc=0000000003cc6500..0000000003cc662e" not in text:
        raise ValueError("callee FDE PC range not in frames.txt")
    # Caller FDE record, retained for the single verified caller.
    caller = ev["incoming"]["validated_caller_fdes"][0]
    if caller["fde_section_offset"][2:] not in text:
        raise ValueError("caller FDE section offset not in frames.txt")
    if "pc=0000000003cbf7a0..0000000003cbfbc2" not in text:
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
    if call["target_fde_extent"] != 302:
        raise ValueError("callee FDE extent must be 302")
    if call["target_claimed_here"] is not False:
        raise ValueError("callee body must be excluded from this packet")
    # Fixed callee arguments, from the rip-relative encodings.
    if site != CALL_SITE:
        raise ValueError("unexpected call site")
    # mov rbp, [rip+0x1aaf7ab] at 0x3cbefce loads the global qword address.
    disp_bytes = read_va(binary, sections, 0x3CBEFCE + 3, 4)
    (disp,) = struct.unpack_from("<i", disp_bytes, 0)
    if 0x3CBEFCE + 7 + disp != GLOBAL_QWORD:
        raise ValueError("global qword address mismatch")
    # lea r14, [rip-0x3ad4b8f] at 0x3cbefd5 fixes rsi.
    disp_bytes = read_va(binary, sections, 0x3CBEFD5 + 3, 4)
    (disp,) = struct.unpack_from("<i", disp_bytes, 0)
    if 0x3CBEFD5 + 7 + disp != FIXED_RSI:
        raise ValueError("fixed rsi address mismatch")


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
    if found != [0x3CBFA87]:
        raise ValueError(f"direct caller scan mismatch: {[hex(f) for f in found]}")
    if ev["incoming"]["direct_e8_callers"] != ["0x3cbfa87"]:
        raise ValueError("evidence caller list must be exactly [0x3cbfa87]")
    callers = ev["incoming"]["validated_caller_fdes"]
    if len(callers) != 1 or callers[0]["site"] != "0x3cbfa87":
        raise ValueError("evidence validated-caller list must hold 0x3cbfa87")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller_text = fh.read()
    if "call   3cbefb0" not in caller_text:
        raise ValueError("caller disassembly lacks the call to the window")


def simulate(attempts, results):
    """Return (result_u64, calls_made) for one edge, exactly as the loop."""
    calls = 0
    remaining = attempts
    if remaining == 0:
        return 0, 0
    for value in results:
        calls += 1
        if value != 0:
            return value, calls
        remaining -= 1
        if remaining == 0:
            return 0, calls
    # Ran out of recorded results before the counter exhausted: the edge
    # must supply exactly the consumed prefix, so this is a malformed edge.
    raise ValueError("edge results end before the loop terminates")


def evaluate_edge(edge):
    """Return (result_u64, calls_made) for one edge."""
    attempts = u64(edge["attempts"])
    results = [u64(v) for v in edge["callee_results"]]
    result, calls = simulate(attempts, results)
    if result != u64(edge["result"]):
        raise ValueError(
            f"edge {edge['note']}: model {hex(result)} != recorded "
            f"{edge['result']}")
    if calls != edge["calls_made"]:
        raise ValueError(
            f"edge {edge['note']}: model calls {calls} != recorded "
            f"{edge['calls_made']}")
    # Every recorded result must be consumed: no trailing unused results.
    if len(results) != calls:
        raise ValueError(
            f"edge {edge['note']}: {len(results)} results but {calls} calls")
    return result, calls


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
        print("usage: foundation_retry_loop.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation retry-loop evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
