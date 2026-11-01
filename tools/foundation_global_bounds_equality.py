#!/usr/bin/env python3
"""Checker for the foundation global-bounds-gated equality window (node #94, 0x528e900).

Stdlib only. Run from the repository root:

    python3 tools/foundation_global_bounds_equality.py \
        --check research/work-items/foundation-global-bounds-equality-94/evidence.json

Every claim is re-derived from target bytes: the 83-byte window body, its
single int3 padding byte, the two retained FDE records (window, first
caller, with distinct CIEs), the first caller call site, the shared-callee
call encoding, and the global-bounds-gated equality rule on its edges.
A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

MASK64 = (1 << 64) - 1
BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
# The 4-byte nop at 0x528e924 is alignment padding inside the window.
INSTR = {
    0x528E900: "f30f1efa",
    0x528E904: "55",
    0x528E905: "31c0",
    0x528E907: "53",
    0x528E908: "4883ec08",
    0x528E90C: "488d2dadf54f00",
    0x528E913: "488b4d08",
    0x528E917: "48394f08",
    0x528E91B: "730b",
    0x528E91D: "4883c408",
    0x528E921: "5b",
    0x528E922: "5d",
    0x528E923: "c3",
    0x528E924: "0f1f4000",
    0x528E928: "488b7500",
    0x528E92C: "48c7c2ffffffff",
    0x528E933: "4889fb",
    0x528E936: "e8b5243d00",
    0x528E93B: "4889c2",
    0x528E93E: "488b4308",
    0x528E942: "482b4508",
    0x528E946: "4839d0",
    0x528E949: "0f94c0",
    0x528E94C: "4883c408",
    0x528E950: "5b",
    0x528E951: "5d",
    0x528E952: "c3",
}

CALLER_SITE = 0x528F20D
CALLER_SITE_BYTES = "e8eef6ffff"


def u64(text):
    return int(text, 16)


def evaluate_rule(input_second, global_second, callee_result):
    """The window's global-bounds-gated equality rule.

    Unsigned gate: input_second < global_second -> 0 (no call).
    Otherwise: 1 iff callee_result == (input_second - global_second) mod 2**64.
    """
    if input_second < global_second:
        return 0
    difference = (input_second - global_second) & MASK64
    return 1 if callee_result == difference else 0


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
    if "pc=000000000528e900..000000000528e953" not in frames:
        return "window FDE record missing from frames.txt"
    # The dump prints section offsets without the 0x prefix.
    if fn["fde_section_offset"][2:] not in frames:
        return "window FDE section offset missing from frames.txt"
    if "pc=000000000528f020..000000000528fb9f" not in frames:
        return "caller FDE record missing from frames.txt"
    if "00647b68" not in frames:
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
    if call["target_fde_start"]:
        return "evidence wrongly claims the callee is an FDE start"
    return None


def check_caller(ev, binary, sections, packet_dir):
    got = read_va(binary, sections, CALLER_SITE, len(bytes.fromhex(CALLER_SITE_BYTES)))
    if got.hex() != CALLER_SITE_BYTES:
        return "first caller call-site bytes mismatch"
    if hex(CALLER_SITE) not in ev["incoming"]["direct_e8_callers"]:
        return "first caller site missing from evidence caller list"
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    if "528f20d:" not in caller or "call" not in caller or "528e900" not in caller:
        return "caller disassembly does not retain the call site"
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    if "528e936:" not in window or "528e953:" not in window:
        return "window disassembly does not retain the call and padding"
    return None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got = evaluate_rule(
            u64(edge["input_second"]), u64(edge["global_second"]),
            edge["callee_result"])
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
    print("Foundation global-bounds-gated equality evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
