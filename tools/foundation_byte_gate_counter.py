#!/usr/bin/env python3
"""Checker for the foundation byte-gate counter window (node #94, 0x4fd6030).

Stdlib only. Run from the repository root:

    python3 tools/foundation_byte_gate_counter.py \
        --check research/work-items/foundation-byte-gate-counter-94/evidence.json

Every claim is re-derived from target bytes: the 76-byte window body, its
four int3 padding bytes, the two retained FDE records (window, caller), the
shared-callee call encoding (callee is not an FDE start), the four verified
direct e8 callers in .text, and the byte-gate flag rule with its unconditional
counter increment on its edges. A failure prints the mismatching check and
exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x4FD6030: "f30f1efa",
    0x4FD6034: "55",
    0x4FD6035: "4889cd",
    0x4FD6038: "53",
    0x4FD6039: "4889fb",
    0x4FD603C: "bf01000000",
    0x4FD6041: "488d4b08",
    0x4FD6045: "4883ec08",
    0x4FD6049: "4885f6",
    0x4FD604C: "741a",
    0x4FD604E: "4889ee",
    0x4FD6051: "e8faa46800",
    0x4FD6056: "4883432801",
    0x4FD605B: "4883c408",
    0x4FD605F: "4889e8",
    0x4FD6062: "5b",
    0x4FD6063: "5d",
    0x4FD6064: "c3",
    0x4FD6065: "0f1f00",
    0x4FD6068: "4839ca",
    0x4FD606B: "74e1",
    0x4FD606D: "31ff",
    0x4FD606F: "0fb64220",
    0x4FD6073: "384520",
    0x4FD6076: "400f92c7",
    0x4FD607A: "ebd2",
}

WINDOW_START = 0x4FD6030


def u64(text):
    return int(text, 16)


def evaluate_flag(second, input_plus8, third, byte_fourth, byte_third):
    """The window's flag selection, exactly as decoded.

    second != 0 selects 1 without consulting pointers or bytes; a zero
    second with input+8 == third also selects 1; otherwise the flag is 1
    iff byte[fourth+0x20] < byte[third+0x20] under UNSIGNED comparison
    (setb after cmp byte ptr [rbp+0x20], al).
    """
    if second != 0:
        return 1
    if input_plus8 == third:
        return 1
    return 1 if byte_fourth < byte_third else 0


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, _type, _flags, addr, offset, size) = struct.unpack_from(
            "<IIQQQQ", binary, off)
        headers.append((name, addr, offset, size))
    str_off = headers[e_shstrndx][2]
    out = {}
    for (name_off, addr, offset, size) in headers:
        end = binary.index(b"\x00", str_off + name_off)
        name = binary[str_off + name_off:end].decode()
        out[name] = (addr, offset, size)
    return out


def read_va(binary, sections, va, count):
    addr, offset, size = sections[".text"]
    if not (addr <= va and va + count <= addr + size):
        raise ValueError("VA %#x outside .text" % va)
    start = offset + (va - addr)
    return binary[start:start + count]


def check_target_digest(ev, binary):
    if hashlib.sha256(binary).hexdigest() != ev["target_sha256"]:
        return "target SHA-256 mismatch"
    return None


def check_window(ev, binary, sections):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        return "window length mismatch: %d != %d" % (len(body), fn["bytes"])
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        return "window body SHA-256 mismatch"
    for va, hexbytes in INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "instruction bytes mismatch at %#x" % va
    return None


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        return "padding length mismatch: %d != %d" % (len(pad), fn["padding_bytes"])
    if pad != b"\xcc" * len(pad):
        return "padding bytes are not int3"
    return None


def check_frames(ev, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames = fh.read()
    fn = ev["function"]
    if "pc=0000000004fd6030..0000000004fd607c" not in frames:
        return "window FDE record missing from frames.txt"
    # The dump prints section offsets without the 0x prefix.
    if fn["fde_section_offset"][2:] not in frames:
        return "window FDE section offset missing from frames.txt"
    if "pc=0000000004fe4e50..0000000004fe72b2" not in frames:
        return "caller FDE record missing from frames.txt"
    if "0062557c" not in frames:
        return "caller FDE section offset missing from frames.txt"
    if "5660550" in frames:
        return "frames.txt wrongly contains a callee FDE record"
    return None


def check_callee_call(ev, binary, sections):
    call = ev["call"]
    site = u64(call["site"])
    want = bytes.fromhex(call["target_bytes"])
    got = read_va(binary, sections, site, len(want))
    if got != want:
        return "callee call bytes mismatch at %#x" % site
    (rel,) = struct.unpack_from("<i", got, 1)
    if site + 5 + rel != u64(call["target"]):
        return "callee call target mismatch"
    if call["target_fde_start"]:
        return "evidence wrongly claims the callee is an FDE start"
    if call["target_fde_extent"] is not None:
        return "evidence wrongly claims a callee FDE extent"
    return None


def check_callers(ev, binary, sections, packet_dir):
    # Full .text scan: exactly four direct e8 calls may target the window.
    addr, offset, size = sections[".text"]
    text = binary[offset:offset + size]
    found = []
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            if addr + idx + 5 + rel == WINDOW_START:
                found.append(addr + idx)
        idx += 1
    if found != [0x4FE680E, 0x4FE68C7, 0x4FE69D0, 0x4FE6B54]:
        return "direct e8 caller scan mismatch: %s" % (
            [hex(f) for f in found],)
    incoming = ev["incoming"]
    if incoming["direct_e8_callers"] != [
            "0x4fe680e", "0x4fe68c7", "0x4fe69d0", "0x4fe6b54"]:
        return "evidence caller list mismatch"
    if incoming["validated_caller_fdes"] != ["0x4fe4e50"]:
        return "evidence validated-caller list mismatch"
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    for site in ("4fe680e:", "4fe68c7:", "4fe69d0:", "4fe6b54:"):
        if site not in caller:
            return "caller disassembly does not retain call site %s" % site
    if "4fd6030" not in caller:
        return "caller disassembly does not retain the window target"
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    if "4fd6051:" not in window or "4fd607c:" not in window:
        return "window disassembly does not retain the call and padding"
    return None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got_flag = evaluate_flag(
            u64(edge["second"]), u64(edge["input_plus8"]),
            u64(edge["third"]), u64(edge["byte_fourth"]),
            u64(edge["byte_third"]))
        if got_flag != edge["result_flag"]:
            return "rule edge flag mismatch: %s -> %d, expected %d" % (
                edge, got_flag, edge["result_flag"])
        got_counter = (u64(edge["counter_before"]) + 1) % (1 << 64)
        if got_counter != u64(edge["counter_after"]):
            return "rule edge counter mismatch: %s -> %#x, expected %#x" % (
                edge, got_counter, u64(edge["counter_after"]))
        # The return claim is locked by bytes, not by arithmetic: the
        # INSTR map pins `mov rbp, rcx` at entry and `mov rax, rbp` on
        # the return path, so the returned value is the fourth input.
        # Edges carry it explicitly so a mutated return value fails here.
        if u64(edge["return_value"]) != u64(edge["fourth"]):
            return "rule edge return mismatch: %s" % (edge,)
    return None


CHECKS = (
    ("target digest", lambda ev, b, s, p: check_target_digest(ev, b)),
    ("window body", lambda ev, b, s, p: check_window(ev, b, s)),
    ("padding", lambda ev, b, s, p: check_padding(ev, b, s)),
    ("frames", lambda ev, b, s, p: check_frames(ev, p)),
    ("callee call", lambda ev, b, s, p: check_callee_call(ev, b, s)),
    ("callers", lambda ev, b, s, p: check_callers(ev, b, s, p)),
    ("rule edges", lambda ev, b, s, p: check_edges(ev)),
)


def run_evidence(ev, binary, sections, packet_dir):
    """Run every check against an already-loaded evidence dict.

    Returns a list of failure strings (empty on success). Corruption
    controls in the unit tests call this directly with mutated dicts.
    """
    failures = []
    for name, fn in CHECKS:
        try:
            err = fn(ev, binary, sections, packet_dir)
        except Exception as exc:  # corrupted input must fail, not crash
            err = "%s (%s)" % (name, exc)
        if err:
            failures.append("%s: %s" % (name, err))
    return failures


def run_all(evidence_path):
    """Return a list of failure strings (empty on success)."""
    with open(evidence_path) as fh:
        ev = json.load(fh)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    return run_evidence(ev, binary, sections, packet_dir)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: %s --check <evidence.json>" % argv[0], file=sys.stderr)
        return 2
    failures = run_all(argv[2])
    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("Foundation byte-gate counter evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
