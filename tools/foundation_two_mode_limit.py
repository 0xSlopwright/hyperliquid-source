#!/usr/bin/env python3
"""Checker for the foundation two-mode limit-check window (node #94, 0x5172c10).

Stdlib only. Run from the repository root:

    python3 tools/foundation_two_mode_limit.py \
        --check research/work-items/foundation-two-mode-limit-94/evidence.json

Every claim is re-derived from target bytes: the 85-byte window body, its
11 int3 padding bytes, the three retained FDE records (window, first
caller, shared callee), the first caller call site, the shared-callee call
encoding, and the two-mode return rule on its edges.
A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
# The 3-byte nop at 0x5172c45 is alignment padding inside the window.
INSTR = {
    0x5172C10: "f30f1efa",
    0x5172C14: "55",
    0x5172C15: "53",
    0x5172C16: "4889fb",
    0x5172C19: "4883ec08",
    0x5172C1D: "48837f3800",
    0x5172C22: "7f24",
    0x5172C24: "48634730",
    0x5172C28: "31d2",
    0x5172C2A: "85c0",
    0x5172C2C: "7e0e",
    0x5172C2E: "488b5728",
    0x5172C32: "48035710",
    0x5172C36: "4839d0",
    0x5172C39: "0f92c2",
    0x5172C3C: "4883c408",
    0x5172C40: "89d0",
    0x5172C42: "5b",
    0x5172C43: "5d",
    0x5172C44: "c3",
    0x5172C45: "0f1f00",
    0x5172C48: "4889f5",
    0x5172C4B: "e8b0feffff",
    0x5172C50: "488d740500",
    0x5172C55: "483b7338",
    0x5172C59: "0f93c2",
    0x5172C5C: "4883c408",
    0x5172C60: "89d0",
    0x5172C62: "5b",
    0x5172C63: "5d",
    0x5172C64: "c3",
}

CALLER_SITE = 0x5173A41
CALLER_SITE_BYTES = "e8caf1ffff"


def u64(text):
    return int(text, 16)


def sign_i64(value):
    value &= MASK64
    return value - (1 << 64) if value >= (1 << 63) else value


def sign_i32(value):
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def evaluate_rule(field38, count_i32, base, offset, input_value, callee_result):
    """The window's two-mode return rule, mirroring instruction semantics.

    field38 > 0 (signed) -> dynamic: 1 iff (input + callee_result) mod 2**64
    >= field38 (unsigned).
    Otherwise -> static: count <= 0 (signed) -> 0; else 1 iff
    count < (base + offset) mod 2**64 (unsigned).
    """
    if sign_i64(field38) > 0:
        return 1 if (input_value + callee_result) & MASK64 >= field38 else 0
    count = sign_i32(count_i32)
    if count <= 0:
        return 0
    limit = (base + offset) & MASK64
    return 1 if count < limit else 0


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
    if "pc=0000000005172c10..0000000005172c65" not in frames:
        return "window FDE record missing from frames.txt"
    # The dump prints section offsets without the 0x prefix.
    if fn["fde_section_offset"][2:] not in frames:
        return "window FDE section offset missing from frames.txt"
    if "pc=00000000051739d0..0000000005173a5e" not in frames:
        return "caller FDE record missing from frames.txt"
    if "0029c608" not in frames:
        return "caller FDE section offset missing from frames.txt"
    call = ev["call"]
    if "pc=0000000005172b00..0000000005172c01" not in frames:
        return "callee FDE record missing from frames.txt"
    if call["target_fde_section_offset"][2:] not in frames:
        return "callee FDE section offset missing from frames.txt"
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
        return "evidence wrongly denies the callee is an FDE start"
    return None


def check_caller(ev, binary, sections, packet_dir):
    got = read_va(binary, sections, CALLER_SITE, len(bytes.fromhex(CALLER_SITE_BYTES)))
    if got.hex() != CALLER_SITE_BYTES:
        return "first caller call-site bytes mismatch"
    if hex(CALLER_SITE) not in ev["incoming"]["direct_e8_callers"]:
        return "first caller site missing from evidence caller list"
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    if "5173a41:" not in caller or "call" not in caller or "5172c10" not in caller:
        return "caller disassembly does not retain the call site"
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    if "5172c4b:" not in window or "5172c65:" not in window:
        return "window disassembly does not retain the call and padding"
    return None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got = evaluate_rule(
            u64(edge["field38"]), edge["count_i32"],
            u64(edge["base"]), u64(edge["offset"]),
            u64(edge["input"]), edge["callee_result"])
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
    ("caller", lambda ev, b, s, p: check_caller(ev, b, s, p)),
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
    print("Foundation two-mode limit-check evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
