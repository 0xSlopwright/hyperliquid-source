#!/usr/bin/env python3
"""Checker for the foundation helper low-byte equality window (node #94, 0x5004e70).

Stdlib only. Run from the repository root:

    python3 tools/foundation_helper_low_byte_equality.py \
        --check research/work-items/foundation-helper-low-byte-equality-94/evidence.json

Every claim is re-derived from target bytes: the 49-byte window body, its
fifteen int3 padding bytes, the three retained FDE records (window, shared
callee, first caller), the shared-callee call encoding, the single verified
direct e8 caller in .text, and the low-byte equality rule on its edges. A
failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x5004E70: "f30f1efa",
    0x5004E74: "53",
    0x5004E75: "4889fb",
    0x5004E78: "488b3f",
    0x5004E7B: "41b801000000",
    0x5004E81: "8b5308",
    0x5004E84: "488db388030000",
    0x5004E8B: "8b8ff00a0000",
    0x5004E91: "e82a3cffff",
    0x5004E96: "388314100000",
    0x5004E9C: "5b",
    0x5004E9D: "0f94c0",
    0x5004EA0: "c3",
}

WINDOW_START = 0x5004E70


def u64(text):
    return int(text, 16)


def evaluate_rule(callee_result, stored_byte):
    """The window's low-byte equality rule, over al.

    Only the callee result's low byte participates: the comparison is
    cmp byte ptr [input + 0x1014], al followed by sete al, so the verdict
    is 1 iff (callee_result & 0xff) == stored_byte, else 0.
    """
    return 1 if (callee_result & 0xFF) == stored_byte else 0


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
    if "pc=0000000005004e70..0000000005004ea1" not in frames:
        return "window FDE record missing from frames.txt"
    # The dump prints section offsets without the 0x prefix.
    if fn["fde_section_offset"][2:] not in frames:
        return "window FDE section offset missing from frames.txt"
    if "pc=0000000004ff8ac0..0000000004ff8b28" not in frames:
        return "callee FDE record missing from frames.txt"
    if "0028f740" not in frames:
        return "callee FDE section offset missing from frames.txt"
    if "pc=00000000050070f0..00000000050073c7" not in frames:
        return "caller FDE record missing from frames.txt"
    if "00626be4" not in frames:
        return "caller FDE section offset missing from frames.txt"
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
    if not call["target_fde_start"]:
        return "evidence wrongly claims the callee is not an FDE start"
    if call["target_fde_extent"] != 104:
        return "callee FDE extent mismatch"
    return None


def check_callers(ev, binary, sections, packet_dir):
    # Full .text scan: exactly one direct e8 call may target the window.
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
    if found != [0x50071C9]:
        return "direct e8 caller scan mismatch: %s" % (
            [hex(f) for f in found],)
    incoming = ev["incoming"]
    if incoming["direct_e8_callers"] != ["0x50071c9"]:
        return "evidence caller list mismatch"
    if incoming["validated_caller_fdes"] != ["0x50070f0"]:
        return "evidence validated-caller list mismatch"
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    if "50071c9:" not in caller or "5004e70" not in caller:
        return "caller disassembly does not retain the call site"
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    if "5004e91:" not in window or "5004ea1:" not in window:
        return "window disassembly does not retain the call and padding"
    return None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got = evaluate_rule(u64(edge["callee_result"]), u64(edge["stored_byte"]))
        if got != edge["result"]:
            return "rule edge mismatch: %s -> %d, expected %d" % (
                edge, got, edge["result"])
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
    print("Foundation helper low-byte equality evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
