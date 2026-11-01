#!/usr/bin/env python3
"""Checker for the foundation all-records flag-scan window (node #94, 0x3bde0b0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_all_records_flag_scan.py \
        --check research/work-items/foundation-all-records-flag-scan-94/evidence.json

Every claim is re-derived from target bytes: the 91-byte window body, its
five int3 padding bytes, the two retained FDE records (window and shared
callee), the shared-callee call encoding, the absence of direct e8 callers
in .text, and the all-records flag-scan rule on its edges. A failure prints
the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

MASK64 = (1 << 64) - 1
BINARY = os.path.join("artifacts", "node", "94", "hl-node")
THRESHOLD = 10001

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x3BDE0B0: "4883ec68",
    0x3BDE0B4: "488b4710",
    0x3BDE0B8: "483d11270000",
    0x3BDE0BE: "7218",
    0x3BDE0C0: "66c74424084301",
    0x3BDE0C7: "488d7c2408",
    0x3BDE0CC: "e8cfcc0300",
    0x3BDE0D1: "b001",
    0x3BDE0D3: "4883c468",
    0x3BDE0D7: "c3",
    0x3BDE0D8: "488b4f08",
    0x3BDE0DC: "48c1e004",
    0x3BDE0E0: "488d1480",
    0x3BDE0E4: "6666662e0f1f840000000000",
    0x3BDE0F0: "4885d2",
    0x3BDE0F3: "0f94c0",
    0x3BDE0F6: "740e",
    0x3BDE0F8: "4883c2b0",
    0x3BDE0FC: "80794e00",
    0x3BDE100: "488d4950",
    0x3BDE104: "75ea",
    0x3BDE106: "4883c468",
    0x3BDE10A: "c3",
}

WINDOW_START = 0x3BDE0B0


def u64(text):
    return int(text, 16)


def evaluate_rule(count, flags, flags_summary):
    """The window's all-records flag-scan rule, over al.

    count >= 10001 takes the fast path and returns 1 regardless of any
    flags. Otherwise the verdict is 1 iff every enumerated flag byte is
    nonzero (an empty list returns 1 vacuously); for counts too large to
    enumerate, flags_summary states "all-nonzero" (1) or "contains-zero"
    (0). flags_summary must be "not-consulted (fast path)" on the fast
    path.
    """
    if count >= THRESHOLD:
        if flags_summary != "not-consulted (fast path)":
            raise ValueError("fast-path edge must not consult flags")
        return 1
    if flags is not None:
        return 1 if all(f != 0 for f in flags) else 0
    if flags_summary == "all-nonzero":
        return 1
    if flags_summary == "contains-zero":
        return 0
    raise ValueError("scan-path edge needs flags or a flags_summary")


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
    if "pc=0000000003bde0b0..0000000003bde10b" not in frames:
        return "window FDE record missing from frames.txt"
    # The dump prints section offsets without the 0x prefix.
    if fn["fde_section_offset"][2:] not in frames:
        return "window FDE section offset missing from frames.txt"
    if "pc=0000000003c1ada0..0000000003c1b1ce" not in frames:
        return "callee FDE record missing from frames.txt"
    if "00509b84" not in frames:
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
        return "evidence wrongly claims the callee is not an FDE start"
    if call["target_fde_extent"] != 1070:
        return "callee FDE extent mismatch"
    return None


def check_callers(ev, binary, sections, packet_dir):
    # Full .text scan: no direct e8 call may target the window start.
    addr, offset, size = sections[".text"]
    text = binary[offset:offset + size]
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            if addr + idx + 5 + rel == WINDOW_START:
                return "unexpected direct e8 caller at %#x" % (addr + idx)
        idx += 1
    incoming = ev["incoming"]
    if incoming["direct_e8_callers"] != []:
        return "evidence caller list is not empty"
    if incoming["validated_caller_fdes"] != []:
        return "evidence validated-caller list is not empty"
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    if "3bde0cc:" not in window or "3bde10b:" not in window:
        return "window disassembly does not retain the call and padding"
    return None


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        got = evaluate_rule(
            u64(edge["count"]), edge["flags"], edge["flags_summary"])
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
    print("Foundation all-records flag-scan evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
