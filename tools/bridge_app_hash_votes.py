#!/usr/bin/env python3
"""Evaluate the node #94 voteAppHash path from ELF bytes: wrapper, Keccak of the signable pair, voter key, tracker, quorum row, prune and the block step take.

The action wrapper and its copies, the arm core, the tracker, the quorum test, the height prune and the take run as real bytes in a Python evaluator. A separately written rule list
predicts each result and the whole tracker state after each case, and conditions, immediates and offsets of the reached rows are flipped to show the run can tell.
Tables, names and call sites are read from section bytes. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
import math
import multiprocessing
import pathlib
import random
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
HANDLERS = ROOT / "research" / "work-items" / "RE-010-exchange-handlers" / "exchange-dispatch.json"

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_BCMP = 0x576E378
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_REALLOC = 0x576E030
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E020, 0x576E118, 0x576E1B0, 0x576E098)
SLOT_RECOVER = 0x576FE58
SLOT_ALIGNED = 0x576E298
SLOT_ABSORB = 0x576E1D8
SLOT_SQUEEZE = 0x576E1E0
SLOT_ONCE = 0x576E8B8
SLOT_SORT = 0x57758E0
SLOT_CORE = 0x5773138
SLOT_TAKE = 0x5774D70
ONCE_WORD = 0x577AB98
ONCE_INIT = 0x143EF30

WRAPPERS = (0x1E5F5D0, 0x46770E0, 0x4677280)
CORE = 0x336A4E0
TRACKER = 0x3946A80
TAKE = 0x336A360
DIGEST = 0x37E5A30
STAKE_MAP = 0x3364ED0
ELIGIBLE = 0x3367530
L1_TRACKER = 0x39438E0
L1_QUORUM = 0x3941070
L1_NEW_HEIGHT = 0x33C1D00
L1_NEW_HASH = 0x33C1FE0
HARD_INSERT = 0x33A6D90
HARD_CLONE = 0x33E8A80
HARD_KEYS = 0x3BB2BC0
RATIO = 0x3BDE1F0
VOTER_KEY = 0x33690C0
HOT_USER = 0x3369500
QUORUM = 0x3941240
STAKE_TEST = 0x3366B60
INSERT = 0x339B0D0
NEW_HEIGHT = 0x33BF1C0
NEW_HASH = 0x33BEC30
CLONE_VOTES = 0x33E79F0
ROW_COLLECT = 0x3316090
PRUNE = 0x3942B90
PRUNE_LIST = 0x3BCD010
DEAD_SCAN = 0x3BCA430
SIGNABLE = 0x32478A0
DISPATCH_TABLE = 0x3EDE28
ARM_ROW = 48
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (0x13F, 0x7A, 0x11F, 0x97, 0x2A)
MUTANT_STEP_LIMIT = 60000
MUTANT_CASES = 6
WORKERS = 4
HANDLERS = ROOT / "research" / "work-items" / "RE-010-exchange-handlers" / "exchange-dispatch.json"
PRUNE_DEPTH = 50000

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
USED = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000

HEAP_FREE = HEAP_BASE + 0x40000
OUT_AT = HEAP_BASE + 0x1000
ACTION_AT = HEAP_BASE + 0x2000
SENDER_AT = HEAP_BASE + 0x2200
STATE_AT = HEAP_BASE + 0x10000
TRACKER_AT = STATE_AT + 0x3540
CONTEXT_AT = STATE_AT + 0x3840
OPTION_AT = HEAP_BASE + 0x2300
L1_AT = STATE_AT + 0x35B0
SET_AT = HEAP_BASE + 0x2400
SET_POINTER_AT = HEAP_BASE + 0x2420
RANDOM_L1_CASES = 80
STATE_SHIFT = (0, 0xA80, 0)
RANDOM_CASES = 120
SIGNED_HEIGHTS = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, 0x0CCCCCCCCCCCCCCB)
COPY_LABELS = ("three_of_four_crosses", "exact_two_thirds_is_short", "height_over_limit", "recovery_fails", "signer_differs_tail", "sender_not_validator", "epoch_absent")
MUTANT_CASE_COST = 60000
SENTINELS = ("prune_one_below", "prune_exact_floor", "prune_floor_is_vote_height", "prune_old_quorum_uses_own_height", "second_hash_reaches_after_done", "before_test_true_blocks_row", "epoch_change_lowers_quorum", "weighted_exact", "weighted_just_over", "take_two_rows", "crossing_skips_voter_without_hot_user", "take_seeded_empty_then_full", "take_seeded_full_empty_full",
             "signer_differs_tail", "hot_user_missing_at_new_epoch", "direct_crossing", "direct_foreign_key", "direct_none", "height_limit_ok", "signed_0x100000000", "random_003", "random_041", "l1_ratio_last_to_pass", "l1_stake_last_to_pass", "l1_both_forms_listed_crosses", "l1_both_forms_one_call_hot_crosses",
             "l1_votes_after_done", "l1_listed_not_in_set", "l1_key_not_eligible", "l1_exact_two_thirds", "l1_same_listed_twice", "l1_ratio_empty_set", "l1_before_true_blocks", "l1_random_007", "l1_random_033")
NAME_TEXTS = ("app_hash_vote_tracker", "struct AppHashVoteTracker with 3 elements", "quorum_app_hashes", "highest_quorum_height", "struct QuorumAppHash with 2 elements", "tuple struct AppHash", "struct VoteAppHashAction with 3 elements", "hot_user_to_signature", "appHash")
KEY_ROWS = (
    (0x1e5f5e7, "488b4620", "wrapper reads the height at action +0x20"),
    (0x1e5f5ef, "48bfcbcccccccccccc0c", "wrapper height limit"),
    (0x1e5f636, "e8f5639801", "wrapper calls the Keccak digest"),
    (0x1e5f6e1, "488db540350000", "state +0x3540 is the tracker"),
    (0x1e5f6e8, "4981c040380000", "state +0x3840 is the voter context"),
    (0x46771f1, "488db5c03f0000", "copy 0x46770e0 takes the tracker at state +0x3fc0"),
    (0x46771f8, "4981c0c0420000", "copy 0x46770e0 takes the voter context at state +0x42c0"),
    (0x336a4f7, "48b8cccccccccccccc0c", "core height limit"),
    (0x336a7b9, "66c7033f01", "core height status 0x13f"),
    (0x336a76c, "4981ef50c30000", "prune floor subtracts 50000"),
    (0x336a77a, "b901000000", "prune flag 1"),
    (0x336a5ea, "6a01", "second stack word of the tracker is 1"),
    (0x3947388, "4883f865", "the scan needs 101 heights"),
    (0x39473f7, "48c78424d800000064000000", "the scan takes 100 heights"),
    (0x3941359, "0f0b", "a second map entry stops the quorum test"),
    (0x3947093, "c6433901", "done flag at height value +0x39"),
    (0x39411f3, "4020eb", "L1 quorum is stake AND ratio"),
    (0x39446b2, "4883f865", "L1 scan needs 101 heights"),
    (0x3944721, "48c784244801000064000000", "L1 scan takes 100 heights"),
    (0x3944173, "c6413901", "L1 done flag at height value +0x39"),
    (0x394b163, "5055e87687", "L1 core tracker call"),
    (0x3943a6c, "0f84340c0000", "L1 tracker leaves when both forms are spent"),
    (0x3944088, "80783900", "L1 tracker reads the done flag"),
    (0x37e5afd, "48c78424f000000088000000", "sponge rate 0x88"),
    (0x37e5b09, "66c78424f800000001", "sponge suffix word 1"),
    (0x336a3c0, "49837ef800", "take tests the row map length at +0x38"),
)

class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def rodata_bytes(self):
        data = self.named[".rodata"]
        return data["address"], bytes(self.blob[data["offset"]:data["offset"] + data["size"]])

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte not in (0x2E, 0x64):
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x98 and wide:
        return finish("cdqe")
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushi", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0x3F
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
        if two == 0xBD and not rep:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.tails = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.watch = {}

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pushi":
            self.push(self.get(row.a, 8))
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                if target in self.watch:
                    self.watch[target](self)
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if target not in self.real:
                raise Halt("indirect jump out of the text at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "shld":
            count = row.target
            if count:
                self.put(row.a, width, self.get(row.a, width) << count | self.get(row.b, width) >> (8 * width - count))
        elif op == "bswap":
            self.regs[row.a[1]] = int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big")
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
        elif op == "bsr":
            value = self.get(row.b, row.width)
            self.zf = value == 0
            if value:
                self.put(row.a, row.width, value.bit_length() - 1)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# ---- harness: real bytes through .text; allocator, signature recovery, Keccak and the stake map are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


def body_rows(image, begin, end):
    """Linear rows of a body up to the first opcode the decoder has no form for."""
    base = image.offset(begin)
    data = image.blob[base:base + (end - begin) + 16]

    def read(va, count):
        return data[va - begin:va - begin + count]

    rows = []
    va = begin
    while va < end:
        try:
            row = decode(read, va)
        except EvidenceError:
            break
        rows.append(row)
        va = row.next
    return rows


class Layout:
    """B-tree node layout: key offset, key size, value offset, value size, count offset, leaf size."""

    def __init__(self, name, key_at, key_size, value_at, value_size, parent_at, index_at, count_at, leaf):
        self.name = name
        self.key_at = key_at
        self.key_size = key_size
        self.value_at = value_at
        self.value_size = value_size
        self.parent_at = parent_at
        self.index_at = index_at
        self.count_at = count_at
        self.leaf = leaf


HEIGHTS = Layout("heights", 0x2C8, 8, 0, 0x40, 0x2C0, 0x320, 0x322, 0x328)
HASHES = Layout("hashes of one height", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTES = Layout("voter key to signature", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
HOT = Layout("hot_user_to_signature", 0x320, 0x14, 8, 0x48, 0, 0x3FC, 0x3FE, 0x400)
EPOCHS = Layout("epochs", 8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
VALIDATORS = Layout("validators", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
STAKES = Layout("stake map", 0, 0x20, 0x168, 8, 0x160, 0x1C0, 0x1C2, 0x1C8)
SET = Layout("listed address set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)
LAYOUTS = (HEIGHTS, HASHES, VOTES, HOT, EPOCHS, VALIDATORS, STAKES, SET)


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_RECOVER: self.on_recover,
                 SLOT_REALLOC: self.on_realloc, SLOT_ALIGNED: self.on_aligned, SLOT_ABSORB: self.on_absorb, SLOT_SQUEEZE: self.on_squeeze, SLOT_ONCE: self.on_once, SLOT_SORT: self.on_sort}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.memory.statics[ONCE_WORD] = 0
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {STAKE_MAP: self.on_stakes}
        machine.tails = machine.calls
        self.real.stubs = frozenset(machine.slots) | frozenset(machine.calls)
        machine.watch = {}
        self.tally = collections.Counter()
        self.signed = {}
        self.reset()

    def reset(self):
        self.machine.memory.reset(USED)
        self.machine.memory.statics[ONCE_WORD] = 0
        self.brk = HEAP_FREE
        self.live = {}
        self.events = []
        self.absorbed = b""
        self.recover = None
        self.epoch_values = {}

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + USED:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x40000:
            raise Halt("allocation size %#x" % size)
        m.regs[RAX] = self.allocate(size)

    def on_aligned(self, m):
        m.regs[RAX] = self.allocate(m.regs[RSI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_realloc(self, m):
        regs = m.regs
        old, new = regs[RDI], regs[RSI]
        if old not in self.live:
            raise Halt("realloc %#x" % old)
        size = self.live.pop(old)
        at = self.allocate(new)
        m.memory.copy(at, old, min(size, new))
        regs[RAX] = at

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x8000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, m):
        regs = m.regs
        left = m.memory.bytes_at(regs[RDI], regs[RDX])
        right = m.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_panic(self, m, slot):
        raise Panicked("%#x" % slot)

    def on_once(self, m):
        self.events.append(("once",))
        m.memory.statics[ONCE_WORD] = 0

    def on_sort(self, m):
        raise Halt("long sort")

    def on_absorb(self, m):
        self.absorbed = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])

    def on_squeeze(self, m):
        if m.regs[RDX] != 32:
            raise Halt("squeeze size")
        m.memory.put_bytes(m.regs[RSI], hashlib.sha256(self.absorbed).digest())

    def on_recover(self, m):
        out = m.regs[RDI]
        self.events.append(("recover", m.memory.bytes_at(m.regs[RSI], 0x41).hex(), m.memory.bytes_at(m.regs[RDX], 32).hex(), self.absorbed.hex()))
        if self.recover is None:
            m.memory.write(out, 1, 1)
            m.memory.write(out + 8, 8, 0x7A7A7A7A)
            return
        m.memory.write(out, 1, 0)
        m.memory.put_bytes(out + 1, self.recover)

    def on_stakes(self, m):
        out, value = m.regs[RDI], m.regs[RSI]
        epoch = self.epoch_values.get(value)
        if epoch is None:
            raise Halt("stake map of an unknown epoch")
        items = sorted(self.epochs[epoch][1].items())
        root = self.leaf(STAKES, [(key, struct.pack("<Q", stake)) for key, stake in items]) if items else 0
        m.memory.write(out, 8, root)
        m.memory.write(out + 8, 8, 0)
        m.memory.write(out + 0x10, 8, len(items))

    # fixtures and tree reads

    def leaf(self, layout, items):
        if len(items) > 11:
            raise Halt("fixture leaf too long")
        memory = self.machine.memory
        node = self.allocate(layout.leaf)
        memory.put_bytes(node, bytes(layout.leaf))
        for index, (key, value) in enumerate(items):
            memory.put_bytes(node + layout.key_at + layout.key_size * index, key)
            memory.put_bytes(node + layout.value_at + layout.value_size * index, value)
        memory.write(node + layout.count_at, 2, len(items))
        return node

    def walk(self, layout, root, height):
        """(key, value) rows of a tree in order."""
        memory = self.machine.memory
        if not root:
            return []
        rows = []

        def visit(node, level):
            count = memory.read(node + layout.count_at, 2)
            for index in range(count):
                if level:
                    visit(memory.read(node + layout.leaf + 8 * index, 8), level - 1)
                rows.append((memory.bytes_at(node + layout.key_at + layout.key_size * index, layout.key_size), memory.bytes_at(node + layout.value_at + layout.value_size * index, layout.value_size)))
            if level:
                visit(memory.read(node + layout.leaf + 8 * count, 8), level - 1)
        visit(root, height)
        return rows

    def tree(self, layout, at):
        memory = self.machine.memory
        return self.walk(layout, memory.read(at, 8), memory.read(at + 8, 8))

    def install(self, epochs, current):
        """Epoch tree of the voter context; each epoch is ({voter key: hot user}, {voter key: stake})."""
        memory = self.machine.memory
        self.epochs = epochs
        rows = []
        for epoch in sorted(epochs):
            validators = sorted(epochs[epoch][0].items())
            profile = [(key, filled("profile", 0x18) + hot + filled("profile tail", 0x14)) for key, hot in validators]
            root = self.leaf(VALIDATORS, profile) if profile else 0
            value = struct.pack("<QQQ", root, 0, len(profile)) + filled("epoch tail", 0x10)
            rows.append((epoch.to_bytes(8, "little"), value))
        node = self.leaf(EPOCHS, rows)
        for index, epoch in enumerate(sorted(epochs)):
            self.epoch_values[node + EPOCHS.value_at + EPOCHS.value_size * index] = epoch
        memory.write(CONTEXT_AT + 0x30, 8, node)
        memory.write(CONTEXT_AT + 0x38, 8, 0)
        memory.write(CONTEXT_AT + 0x40, 8, len(rows))
        memory.write(CONTEXT_AT + 0x48, 8, current)

    def clear_tracker(self, at):
        memory = self.machine.memory
        memory.put_bytes(at, filled("tracker head", 0x18))
        for offset, word in ((0x18, 0), (0x20, 0), (0x28, 0), (0x30, 0), (0x38, 8), (0x40, 0), (0x48, 0)):
            memory.write(at + offset, 8, word)


# ---- rule list, written from the reading notes and not from the evaluator ----

def filled(tag, size):
    """Distinct bytes, so that a shifted copy never matches by accident."""
    data = b""
    counter = 0
    while len(data) < size:
        data += hashlib.sha256(("%s %d" % (tag, counter)).encode()).digest()
        counter += 1
    return data[:size]


def uint_form(value):
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + bytes([value])
    if value <= 0xFFFF:
        return b"\xcd" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def signed_bytes(height, app_hash):
    return b"\x92" + uint_form(height) + b"\xd9\x42" + b"0x" + app_hash.hex().encode()


def equal_mask(left, right):
    """The mask the address compare leaves in eax: bytes 0..3 need both 16 byte and tail equality."""
    mask = 0
    for index in range(16):
        if left[index] == right[index] and (index >= 4 or left[16 + index] == right[16 + index]):
            mask |= 1 << index
    return mask


class Model:
    """Rule list of the voteAppHash arm: statuses, one tracker, the row list and the prune."""

    def __init__(self, epochs, current):
        self.epochs = epochs
        self.current = current
        self.heights = {}
        self.rows = []
        self.top = 0

    def voter_of(self, sender):
        """Voter key of a sender at the current epoch, or a status."""
        if self.current not in self.epochs:
            return None, 0x97
        hits = [key for key, hot in self.epochs[self.current][0].items() if hot == sender]
        if not hits:
            return None, 0x2A
        return min(hits), None

    def quorum(self, votes):
        if self.current not in self.epochs:
            return False
        stakes = self.epochs[self.current][1]
        total = sum(stakes.values())
        voted = sum(stakes.get(key, 0) for key in votes)
        if not stakes or not votes:
            return False
        return 2 * total < 3 * voted

    def hot_rows(self, votes):
        rows = {}
        known = self.epochs.get(self.current, ({}, {}))[0]
        for key in sorted(votes):
            hot = known.get(key)
            if hot is not None:
                rows[hot] = votes[key]
        return rows

    def record(self, key, height, app_hash, signature):
        """One tracker pass: the winning row if this vote crossed, else None."""
        entry = self.heights.setdefault(height, {"done": None, "buckets": {}})
        bucket = entry["buckets"].setdefault(app_hash, {})
        if entry["done"] is not None:
            bucket[key] = signature
            return None
        before = self.quorum(bucket)
        bucket[key] = signature
        if before or not self.quorum(bucket):
            return None
        entry["done"] = app_hash
        return dict(bucket)

    def vote(self, sender, recovered, height, app_hash, signature):
        """(outcome, status or result byte, word) of one wrapper call."""
        if height > 0x0CCCCCCCCCCCCCCB:
            return ("error", 0x13F, height)
        if recovered is None:
            return ("error", 0x7A, 0x7A7A7A7A)
        if recovered != sender:
            return ("error", 0x11F, equal_mask(recovered, sender))
        key, status = self.voter_of(sender)
        if status is not None:
            return ("error", status, None)
        votes = self.record(key, height, app_hash, signature)
        if votes is None:
            return ("ok", 0, None)
        self.top = max(self.top, height)
        self.rows.append((height, app_hash, self.hot_rows(votes)))
        floor = max(height - PRUNE_DEPTH, 0)
        for old in [item for item in self.heights if item < floor]:
            del self.heights[old]
        return ("ok", 1, None)

    def direct(self, key, height, app_hash, signature):
        """One direct tracker call: the voters of a crossing, else None."""
        if key is None or self.current not in self.epochs or key not in self.epochs[self.current][0]:
            return None
        return self.record(key, height, app_hash, signature)

    def take(self):
        rows = [row for row in self.rows if row[2]]
        self.rows = []
        return rows


class HardModel(Model):
    """Rule list of the voteL1Hash tracker: two voter forms in one bucket, stake AND ratio."""

    def __init__(self, epochs, current, ratio, listed):
        Model.__init__(self, epochs, current)
        self.ratio = ratio
        self.listed = listed

    def ratio_test(self, hard):
        if self.ratio == 0.0:
            return True
        hits = sum(1 for item in hard if item in self.listed)
        return float(hits) > self.ratio * float(len(self.listed))

    def both(self, bucket):
        return self.quorum(bucket["hot"]) and self.ratio_test(bucket["hard"])

    def one_form(self, height, app_hash, signature, form, key):
        entry = self.heights.setdefault(height, {"done": None, "buckets": {}})
        bucket = entry["buckets"].setdefault(app_hash, {"hot": {}, "hard": {}})
        if entry["done"] is not None:
            bucket[form][key] = signature
            return None
        before = self.both(bucket)
        bucket[form][key] = signature
        if before or not self.both(bucket):
            return None
        entry["done"] = app_hash
        return dict(bucket["hot"]), dict(bucket["hard"])

    def track(self, key, address, height, app_hash, signature):
        """One tracker call: the voter maps of the last crossing, else None."""
        result = None
        known = self.epochs[self.current][0] if self.current in self.epochs else {}
        if key is not None and key in known:
            result = self.one_form(height, app_hash, signature, "hot", key)
        if address is not None and address in self.listed:
            crossed = self.one_form(height, app_hash, signature, "hard", address)
            result = crossed or result
        return result


class Case:
    def __init__(self, label, kind, epochs, ops, current=1, once=0, entry=0, ratio=0.0, listed=()):
        self.label = label
        self.ratio = ratio
        self.listed = listed
        self.entry = entry
        self.kind = kind
        self.epochs = epochs
        self.ops = ops
        self.current = current
        self.once = once


def voter(index):
    return filled("voter key %d" % index, 32)


def hot_user(index):
    return filled("hot user %d" % index, 20)


def signature(index):
    return filled("signature %d" % index, 0x48)


def app_hash(index):
    return filled("app hash %d" % index, 32)


def epoch_of(count, stake=None):
    stakes = {voter(index): (stake[index] if stake else 100) for index in range(count)}
    return ({voter(index): hot_user(index) for index in range(count)}, stakes)


def vote(index, height, which=0, sig=None, recovered="same", sender=None):
    return ("vote", index if sender is None else sender, index, height, which, index if sig is None else sig, recovered)


def named_cases():
    cases = []
    base = {1: epoch_of(4)}
    add = cases.append

    def case(label, ops, epochs=None, current=1, kind="vote", once=0):
        add(Case(label, kind, epochs if epochs is not None else base, ops, current, once))

    case("single_vote_short", [vote(0, 100)])
    case("two_of_four_short", [vote(0, 100), vote(1, 100)])
    case("three_of_four_crosses", [vote(0, 100), vote(1, 100), vote(2, 100)])
    case("four_of_four_after_cross", [vote(0, 100), vote(1, 100), vote(2, 100), vote(3, 100)])
    case("exact_two_thirds_is_short", [vote(0, 7), vote(1, 7)], {1: epoch_of(3)})
    case("all_of_three_crosses", [vote(0, 7), vote(1, 7), vote(2, 7)], {1: epoch_of(3)})
    case("weighted_one_big", [vote(0, 7)], {1: epoch_of(3, (70, 15, 15))})
    case("weighted_exact", [vote(0, 7), vote(2, 7)], {1: epoch_of(3, (50, 50, 50))})
    case("weighted_just_over", [vote(0, 7), vote(1, 7)], {1: epoch_of(3, (67, 34, 50))})
    case("zero_stake_voters", [vote(0, 9), vote(1, 9)], {1: epoch_of(2, (0, 0))})
    case("split_hashes_do_not_add", [vote(0, 9, 0), vote(1, 9, 0), vote(2, 9, 1), vote(3, 9, 1)])
    case("same_voter_two_hashes", [vote(0, 9, 0), vote(0, 9, 1), vote(1, 9, 1), vote(2, 9, 1)])
    case("same_voter_again_new_signature", [vote(0, 9, 0, 0), vote(0, 9, 0, 7)])
    case("two_voters_one_hash_keep_both", [vote(0, 9), vote(1, 9)])
    case("votes_after_done_other_hash", [vote(0, 9), vote(1, 9), vote(2, 9), vote(3, 9, 1), vote(0, 9, 1), vote(1, 9, 1)])
    case("second_hash_reaches_after_done", [vote(0, 9, 0), vote(1, 9, 0), vote(2, 9, 0), vote(0, 9, 1), vote(1, 9, 1), vote(2, 9, 1), vote(3, 9, 1)])
    case("old_height_after_new", [vote(0, 200), vote(1, 200), vote(2, 200), vote(0, 100), vote(1, 100), vote(2, 100)])
    case("height_limit_ok", [vote(0, 0x0CCCCCCCCCCCCCCB), vote(1, 0x0CCCCCCCCCCCCCCB), vote(2, 0x0CCCCCCCCCCCCCCB)])
    case("height_over_limit", [vote(0, 0x0CCCCCCCCCCCCCCC)])
    case("height_top", [vote(0, MASK[8])])
    case("height_zero", [vote(0, 0), vote(1, 0), vote(2, 0)])
    case("recovery_fails", [vote(0, 5, recovered=None)])
    case("signer_differs_tail", [vote(0, 5, recovered=hot_user(0)[:19] + b"\x00")])
    case("signer_differs_head", [vote(0, 5, recovered=b"\x00" + hot_user(0)[1:])])
    case("signer_differs_all", [vote(0, 5, recovered=bytes(20))])
    case("sender_not_validator", [vote(7, 5)], {1: epoch_of(4), 2: epoch_of(1)})
    case("epoch_absent", [vote(0, 5)], {2: epoch_of(4)}, 1)
    case("epoch_no_validators", [vote(0, 5)], {1: ({}, {})})
    case("prune_exact_floor", [vote(0, 10), vote(0, 50010), vote(1, 50010), vote(2, 50010)])
    case("prune_one_below", [vote(0, 9), vote(0, 50010), vote(1, 50010), vote(2, 50010)])
    case("prune_floor_is_vote_height", [vote(0, 10), vote(0, 60000), vote(1, 60000), vote(2, 60000), vote(0, 11), vote(1, 11), vote(2, 11)])
    case("prune_low_height_keeps_all", [vote(0, 1), vote(0, 49999), vote(1, 49999), vote(2, 49999)])
    case("prune_old_quorum_uses_own_height", [vote(0, 300), vote(0, 90000), vote(1, 90000), vote(2, 90000), vote(0, 50200), vote(1, 50200), vote(2, 50200)])
    case("short_vote_prunes_nothing", [vote(0, 1), vote(0, 90000)])
    case("take_empty", [("take",)])
    case("take_after_cross", [vote(0, 9), vote(1, 9), vote(2, 9), ("take",)])
    case("take_two_rows", [vote(0, 9), vote(1, 9), vote(2, 9), vote(0, 10), vote(1, 10), vote(2, 10), ("take",), ("take",)])
    case("take_then_more", [vote(0, 9), vote(1, 9), vote(2, 9), ("take",), vote(0, 10), vote(1, 10), vote(2, 10), ("take",)])
    for pattern in ("e", "f", "ee", "ef", "fe", "ff", "efe", "fef", "eeff", "ffee", "efef"):
        name = {"ef": "take_seeded_empty_then_full", "fef": "take_seeded_full_empty_full"}.get(pattern, "take_seeded_" + pattern)
        case(name, [("seed", pattern), ("take",)])
    two = {1: epoch_of(3), 2: ({voter(0): hot_user(0)}, epoch_of(3)[1]), 3: ({voter(5): hot_user(5)}, {voter(0): 1, voter(5): 1, voter(1): 1}), 4: ({}, {voter(0): 1})}
    case("hot_user_missing_at_new_epoch", [vote(0, 9), vote(1, 9), ("epoch", 2), vote(0, 11), ("take",)], two)
    case("before_test_true_blocks_row", [vote(0, 9), ("epoch", 5), vote(1, 9), ("epoch", 1), vote(2, 9)], {1: epoch_of(4), 5: epoch_of(4, (100, 0, 0, 0))})
    case("epoch_change_lowers_quorum", [vote(0, 9), ("epoch", 5), vote(1, 9)], {1: epoch_of(4), 5: epoch_of(4, (100, 100, 0, 0))})
    case("crossing_skips_voter_without_hot_user", [vote(5, 9), ("epoch", 6), vote(0, 9), ("take",)], {1: ({voter(5): hot_user(5), voter(0): hot_user(0)}, {voter(5): 1, voter(0): 1}), 6: ({voter(0): hot_user(0)}, {voter(5): 1, voter(0): 9})})
    case("two_keys_same_hot_user", [vote(0, 9), vote(1, 9), ("take",)], {1: ({voter(0): hot_user(0), voter(1): hot_user(1)}, {voter(0): 1, voter(1): 1}), 2: ({voter(0): hot_user(9), voter(1): hot_user(9)}, {voter(0): 1, voter(1): 1})})
    case("once_first_use", [vote(0, 9), vote(1, 9), vote(2, 9)], once=3)
    case("once_done", [vote(0, 9), vote(1, 9), vote(2, 9)], once=0)
    large = {1: epoch_of(11)}
    case("eleven_voters", [vote(index, 9) for index in range(11)], large)
    heavy = {1: epoch_of(4)}
    case("hundred_heights", [vote(0, 1000 + item * 3) for item in range(104)], heavy)
    case("hundred_heights_then_quorum", [vote(0, 1000 + item * 3) for item in range(101)] + [vote(1, 1000), vote(2, 1000)], heavy)
    case("prune_many_heights", [vote(0, 1000 + item) for item in range(30)] + [vote(0, 51015), vote(1, 51015), vote(2, 51015)], heavy)
    case("many_hashes_one_height", [vote(0, 9, item) for item in range(14)], heavy)
    case("many_hashes_then_cross", [vote(0, 9, item) for item in range(14)] + [vote(1, 9, 3), vote(2, 9, 3)], heavy)
    for height in SIGNED_HEIGHTS:
        case("signed_%#x" % height, [vote(0, height)])
    case("direct_none", [("tracker", None, 9, 0, 0)], kind="tracker")
    case("direct_foreign_key", [("tracker", filled("outsider", 32), 9, 0, 0)], kind="tracker")
    case("direct_epoch_absent", [("epoch", 8), ("tracker", voter(0), 9, 0, 0)], kind="tracker")
    case("direct_one_key", [("tracker", voter(1), 9, 0, 3)], kind="tracker")
    case("direct_crossing", [("tracker", voter(1), 9, 0, 3), ("tracker", voter(2), 9, 0, 4), ("tracker", voter(0), 9, 0, 5), ("tracker", voter(3), 9, 0, 6)], kind="tracker")
    case("direct_one_member", [("tracker", voter(0), 2, 1, 1)], {1: epoch_of(1)}, kind="tracker")
    by_label = {item.label: item for item in cases}
    for entry in (1, 2):
        for label in COPY_LABELS:
            item = by_label[label]
            add(Case("copy%d_%s" % (entry, label), "vote", item.epochs, item.ops, item.current, item.once, entry))
    return cases


def random_cases(count):
    rng = random.Random(4804)
    out = []
    for serial in range(count):
        members = rng.randint(1, 7)
        stakes = tuple(rng.choice((1, 3, 10, 100, 1000)) for _ in range(members))
        epochs = {1: epoch_of(members, stakes)}
        if rng.random() < 0.4:
            epochs[2] = epoch_of(members, tuple(rng.choice((0, 2, 50)) for _ in range(members)))
        ops = []
        heights = [rng.randint(0, 3) * 26000 + rng.randint(0, 2) for _ in range(3)]
        for _ in range(rng.randint(2, 18)):
            roll = rng.random()
            if roll < 0.06:
                ops.append(("take",))
            elif roll < 0.1 and len(epochs) > 1:
                ops.append(("epoch", rng.choice(sorted(epochs))))
            else:
                ops.append(vote(rng.randrange(members), rng.choice(heights), rng.randrange(3), rng.randrange(9)))
        out.append(Case("random_%03d" % serial, "vote", epochs, ops))
    return out


def listed_address(index):
    return filled("listed %d" % index, 20)


def l1(key, address, height, which=0, sig=0):
    return ("l1", None if key is None else voter(key), None if address is None else listed_address(address), height, which, sig)


def l1_cases():
    cases = []
    base = {1: epoch_of(4)}
    four = sorted(listed_address(index) for index in range(4))

    def case(label, ops, ratio=0.0, listed=four, epochs=None):
        cases.append(Case("l1_" + label, "l1", epochs if epochs is not None else base, ops, ratio=ratio, listed=tuple(listed)))

    case("hot_only_q_zero", [l1(0, None, 9), l1(1, None, 9), l1(2, None, 9), l1(3, None, 9)])
    case("exact_two_thirds", [l1(0, None, 9), l1(1, None, 9)], epochs={1: epoch_of(3)})
    case("listed_alone_never_crosses", [l1(None, 0, 9), l1(None, 1, 9), l1(None, 2, 9), l1(None, 3, 9)], 0.5)
    case("ratio_blocks_stake", [l1(0, None, 9), l1(1, None, 9), l1(2, None, 9), l1(None, 0, 9), l1(None, 1, 9)], 0.5)
    case("ratio_last_to_pass", [l1(0, None, 9), l1(1, None, 9), l1(2, None, 9), l1(None, 0, 9), l1(None, 1, 9), l1(None, 2, 9)], 0.5)
    case("stake_last_to_pass", [l1(None, 0, 9), l1(None, 1, 9), l1(None, 2, 9), l1(0, None, 9), l1(1, None, 9), l1(2, None, 9)], 0.5)
    case("both_forms_one_call_short", [l1(0, 0, 9)], 0.5)
    case("both_forms_one_call_hot_crosses", [l1(0, None, 9), l1(1, None, 9), l1(2, 0, 9, 0, 5)])
    case("both_forms_listed_crosses", [l1(0, 0, 9), l1(1, 1, 9), l1(2, 2, 9, 0, 5)], 0.5)
    case("votes_after_done", [l1(0, None, 9), l1(1, None, 9), l1(2, None, 9), l1(3, 3, 9, 1), l1(None, 0, 9)])
    case("listed_not_in_set", [l1(None, 8, 9)], 0.5)
    case("listed_absent_makes_no_height", [l1(None, 8, 9), l1(None, 9, 10)])
    case("key_not_eligible", [("l1", filled("outsider", 32), None, 9, 0, 0)])
    case("epoch_absent", [("epoch", 7), l1(0, None, 9)])
    case("no_form_at_all", [l1(None, None, 9)])
    case("same_listed_twice", [l1(None, 0, 9, 0, 1), l1(None, 0, 9, 0, 2)], 0.5)
    case("same_hot_twice", [l1(0, None, 9, 0, 1), l1(0, None, 9, 0, 2)], 0.5)
    case("two_hashes_do_not_add", [l1(0, 0, 9, 0), l1(1, 1, 9, 1), l1(2, 2, 9, 0)], 0.5)
    case("ratio_one_never", [l1(0, 0, 9), l1(1, 1, 9), l1(2, 2, 9), l1(3, 3, 9)], 1.0)
    case("ratio_negative", [l1(0, None, 9), l1(1, None, 9), l1(2, None, 9)], -1.0)
    case("ratio_nan", [l1(0, 0, 9), l1(1, 1, 9), l1(2, 2, 9), l1(3, 3, 9)], float("nan"))
    case("ratio_empty_set", [l1(0, 0, 9), l1(1, 1, 9), l1(2, 2, 9)], 0.5, ())
    case("hundred_heights", [l1(0, None, 1000 + item * 3) for item in range(103)])
    case("many_hashes", [l1(None, 0, 9, item) for item in range(14)], 0.5)
    case("before_true_blocks", [l1(0, None, 9), ("epoch", 5), l1(1, None, 9), ("epoch", 1), l1(2, None, 9)], epochs={1: epoch_of(4), 5: epoch_of(4, (100, 0, 0, 0))})
    return cases


def random_l1_cases(count):
    rng = random.Random(8748)
    out = []
    for serial in range(count):
        members = rng.randint(1, 5)
        epochs = {1: epoch_of(members, tuple(rng.choice((1, 3, 10, 100)) for _ in range(members)))}
        listed = sorted(listed_address(index) for index in range(rng.randint(0, 5)))
        ratio = rng.choice((0.0, 0.25, 0.5, 0.75))
        ops = [l1(rng.choice((None, rng.randrange(members))), rng.choice((None, rng.randrange(6))), rng.choice((9, 9, 12)), rng.randrange(2), rng.randrange(5)) for _ in range(rng.randint(2, 16))]
        out.append(Case("l1_random_%03d" % serial, "l1", epochs, ops, ratio=ratio, listed=tuple(listed)))
    return out


def all_cases():
    return named_cases() + random_cases(RANDOM_CASES) + l1_cases() + random_l1_cases(RANDOM_L1_CASES)


def l1_install(harness, case):
    memory = harness.machine.memory
    root = harness.leaf(SET, [(item, b"") for item in sorted(case.listed)]) if case.listed else 0
    memory.write(SET_AT, 8, root)
    memory.write(SET_AT + 8, 8, 0)
    memory.write(SET_AT + 0x10, 8, len(case.listed))
    memory.write(SET_POINTER_AT, 8, SET_AT)
    memory.put_bytes(L1_AT, filled("tracker head", 0x18))
    memory.put_bytes(L1_AT + 0x18, struct.pack("<dQ", case.ratio, 0x11))
    for offset in (0x28, 0x30, 0x38):
        memory.write(L1_AT + offset, 8, 0)


def run_l1(harness, model, op):
    machine = harness.machine
    memory = machine.memory
    _, key, address, height, which, sig_index = op
    record = (b"\x01" + key if key is not None else bytes(33)) + (b"\x01" + address if address is not None else bytes(21))
    memory.put_bytes(OPTION_AT, record)
    memory.put_bytes(ACTION_AT, app_hash(which))
    memory.put_bytes(ACTION_AT + 0x28, signature(sig_index))
    memory.write(STACK_TOP - 0x100, 8, CONTEXT_AT)
    memory.write(STACK_TOP - 0xF8, 8, SET_POINTER_AT)
    memory.write(OUT_AT, 8, MASK[8])
    machine.run(L1_TRACKER, {RDI: OUT_AT, RSI: L1_AT, RDX: height, RCX: ACTION_AT, R8: OPTION_AT, R9: ACTION_AT + 0x28})
    want = model.track(key, address, height, app_hash(which), signature(sig_index))
    harness.tally["l1 crossed" if want else "l1 no result"] += 1
    if want is None:
        return None if memory.read(OUT_AT, 8) == 0 else "l1 result word"
    if memory.read(OUT_AT, 8) != 1 or memory.bytes_at(OUT_AT + 8, 32) != app_hash(which):
        return "l1 result head"
    if dict(harness.tree(VOTES, OUT_AT + 0x28)) != want[0]:
        return "l1 result hot voters"
    if dict(harness.tree(HOT, OUT_AT + 0x40)) != want[1]:
        return "l1 result listed voters"
    return None


def l1_trouble(harness, model):
    memory = harness.machine.memory
    if memory.bytes_at(L1_AT, 0x18) != filled("tracker head", 0x18):
        return "l1 head moved"
    rows = harness.tree(HEIGHTS, L1_AT + 0x28)
    if memory.read(L1_AT + 0x38, 8) != len(rows):
        return "l1 height count"
    if [int.from_bytes(key, "little") for key, _ in rows] != sorted(model.heights):
        return "l1 heights"
    for key, value in rows:
        height = int.from_bytes(key, "little")
        entry = model.heights[height]
        root, level = struct.unpack_from("<QQ", value, 0)
        buckets = harness.walk(HASHES, root, level)
        if [item[0] for item in buckets] != sorted(entry["buckets"]):
            return "l1 hashes at %d" % height
        if value[0x39] != (1 if entry["done"] is not None else 0):
            return "l1 done flag at %d" % height
        if entry["done"] is not None and value[0x19:0x39] != entry["done"]:
            return "l1 done hash at %d" % height
        for name, bucket in buckets:
            hot_root, hot_level, _, hard_root, hard_level, _ = struct.unpack("<6Q", bucket)
            if dict(harness.walk(VOTES, hot_root, hot_level)) != entry["buckets"][name]["hot"]:
                return "l1 hot votes at %d" % height
            if dict(harness.walk(HOT, hard_root, hard_level)) != entry["buckets"][name]["hard"]:
                return "l1 listed votes at %d" % height
    return None


def compare_l1(harness, case):
    memory = harness.machine.memory
    harness.reset()
    harness.install(case.epochs, case.current)
    l1_install(harness, case)
    model = HardModel(case.epochs, case.current, case.ratio, case.listed)
    for op in case.ops:
        if op[0] == "epoch":
            memory.write(CONTEXT_AT + 0x48, 8, op[1])
            model.current = op[1]
        else:
            trouble = run_l1(harness, model, op)
            if trouble:
                return trouble
    return l1_trouble(harness, model)


def read_rows(harness, ptr, count):
    memory = harness.machine.memory
    rows = []
    for index in range(count):
        at = ptr + 0x40 * index
        hot = {key: value for key, value in harness.tree(HOT, at + 0x28)}
        rows.append((memory.read(at, 8), memory.bytes_at(at + 8, 32), hot))
    return rows


def state_trouble(harness, model):
    """Compare the tracker bytes with the model after a case."""
    memory = harness.machine.memory
    at = TRACKER_AT
    if memory.read(at + 0x48, 8) != model.top:
        return "top %#x" % memory.read(at + 0x48, 8)
    if memory.bytes_at(at, 0x18) != filled("tracker head", 0x18):
        return "head moved"
    rows = harness.tree(HEIGHTS, at + 0x18)
    if memory.read(at + 0x28, 8) != len(rows):
        return "height count"
    want = sorted(model.heights)
    if [int.from_bytes(key, "little") for key, _ in rows] != want:
        return "heights"
    for key, value in rows:
        height = int.from_bytes(key, "little")
        entry = model.heights[height]
        buckets = harness.tree(HASHES, TRACKER_NODE(harness, height))
        if [item[0] for item in buckets] != sorted(entry["buckets"]):
            return "hashes at %d" % height
        if value[0x39] != (1 if entry["done"] is not None else 0):
            return "done flag at %d" % height
        if entry["done"] is not None and value[0x19:0x39] != entry["done"]:
            return "done hash at %d" % height
        for name, bucket in buckets:
            voters = {item[0]: item[1] for item in harness_votes(harness, bucket)}
            if voters != entry["buckets"][name]:
                return "votes at %d" % height
            if bucket[0x18:0x30] != bytes(0x18) and int.from_bytes(bucket[0x28:0x30], "little"):
                return "second map at %d" % height
    count = memory.read(at + 0x40, 8)
    if read_rows(harness, memory.read(at + 0x38, 8), count) != model.rows:
        return "row list"
    return None


def harness_votes(harness, bucket):
    root, height = struct.unpack_from("<QQ", bucket, 0)
    return harness.walk(VOTES, root, height)


def TRACKER_NODE(harness, height):
    """Address of the value of one height, for tree reads of its first map."""
    memory = harness.machine.memory
    node = memory.read(TRACKER_AT + 0x18, 8)
    level = memory.read(TRACKER_AT + 0x20, 8)
    while True:
        count = memory.read(node + HEIGHTS.count_at, 2)
        keys = [memory.read(node + HEIGHTS.key_at + 8 * index, 8) for index in range(count)]
        if height in keys:
            return node + HEIGHTS.value_size * keys.index(height)
        node = memory.read(node + HEIGHTS.leaf + 8 * sum(1 for item in keys if item < height), 8)
        level -= 1
        if level < 0:
            raise Halt("height absent from the tree")


def compare(harness, spec, case):
    """Run one case and return a difference text, or None."""
    if case.kind == "l1":
        return compare_l1(harness, case)
    machine = harness.machine
    memory = machine.memory
    harness.reset()
    harness.entry = WRAPPERS[case.entry]
    memory.statics[ONCE_WORD] = case.once
    harness.install(case.epochs, case.current)
    harness.clear_tracker(TRACKER_AT)
    model = Model(case.epochs, case.current)
    for op in case.ops:
        if op[0] == "epoch":
            memory.write(CONTEXT_AT + 0x48, 8, op[1])
            model.current = op[1]
        elif op[0] == "seed":
            seed_rows(harness, model, op[1])
        elif op[0] == "take":
            trouble = run_take(harness, model)
            if trouble:
                return trouble
        elif op[0] == "tracker":
            trouble = run_tracker(harness, model, op)
            if trouble:
                return trouble
        else:
            trouble = run_vote(harness, model, op, case)
            if trouble:
                return trouble
    return state_trouble(harness, model)


def seed_rows(harness, model, pattern):
    """A row list with empty and full maps, which the arm cannot make, for the filter of the take."""
    memory = harness.machine.memory
    at = harness.allocate(0x40 * len(pattern))
    rows = []
    for index, kind in enumerate(pattern):
        items = {hot_user(index): signature(index)} if kind == "f" else {}
        root = harness.leaf(HOT, sorted(items.items())) if items else 0
        row = (200 + index, app_hash(index), items)
        rows.append(row)
        memory.put_bytes(at + 0x40 * index, struct.pack("<Q", row[0]) + row[1] + struct.pack("<QQQ", root, 0, len(items)))
    memory.write(TRACKER_AT + 0x30, 8, len(pattern))
    memory.write(TRACKER_AT + 0x38, 8, at)
    memory.write(TRACKER_AT + 0x40, 8, len(pattern))
    model.rows = rows


def run_take(harness, model):
    machine = harness.machine
    memory = machine.memory
    machine.run(TAKE, {RDI: OUT_AT, RSI: TRACKER_AT})
    want = model.take()
    if read_rows(harness, memory.read(OUT_AT + 8, 8), memory.read(OUT_AT + 0x10, 8)) != want:
        return "taken rows"
    if memory.read(TRACKER_AT + 0x30, 8) or memory.read(TRACKER_AT + 0x38, 8) != 8 or memory.read(TRACKER_AT + 0x40, 8):
        return "list not reset"
    return None


def run_tracker(harness, model, op):
    machine = harness.machine
    memory = machine.memory
    _, key, height, which, sig_index = op
    memory.put_bytes(OPTION_AT, b"\x01" + key if key is not None else bytes(33))
    memory.put_bytes(ACTION_AT, app_hash(which))
    memory.put_bytes(ACTION_AT + 0x28, signature(sig_index))
    memory.write(STACK_TOP - 0x100, 8, CONTEXT_AT)
    memory.write(STACK_TOP - 0xF8, 8, 1)
    memory.write(OUT_AT, 8, MASK[8])
    machine.run(TRACKER, {RDI: OUT_AT, RSI: TRACKER_AT, RDX: height, RCX: ACTION_AT, R8: OPTION_AT, R9: ACTION_AT + 0x28})
    want = model.direct(key, height, app_hash(which), signature(sig_index))
    if want is None:
        return None if memory.read(OUT_AT, 8) == 0 else "direct result word"
    if memory.read(OUT_AT, 8) != 1 or memory.bytes_at(OUT_AT + 8, 32) != app_hash(which):
        return "direct result head"
    if dict(harness.tree(VOTES, OUT_AT + 0x28)) != want:
        return "direct result voters"
    if memory.read(OUT_AT + 0x48, 8) and memory.read(OUT_AT + 0x50, 8):
        return "direct second map"
    return None


def run_vote(harness, model, op, case):
    machine = harness.machine
    memory = machine.memory
    _, sender_index, voter_index, height, which, sig_index, recovered = op
    sender = hot_user(sender_index)
    if isinstance(recovered, str):
        recovered = sender
    digest_input = signed_bytes(height, app_hash(which))
    memory.put_bytes(ACTION_AT, app_hash(which))
    memory.write(ACTION_AT + 0x20, 8, height)
    memory.put_bytes(ACTION_AT + 0x28, signature(sig_index))
    memory.put_bytes(SENDER_AT, sender)
    harness.recover = recovered
    harness.events = []
    machine.run(harness.entry, {RDI: OUT_AT, RSI: ACTION_AT, RDX: SENDER_AT, RCX: STATE_AT - STATE_SHIFT[case.entry]})
    wanted = model.vote(sender, recovered, height, app_hash(which), signature(sig_index))
    tag = memory.read(OUT_AT, 1)
    harness.tally["%s %#x" % wanted[:2]] += 1
    harness.signed[height] = harness.absorbed.hex()
    if wanted[0] == "ok":
        if tag != 9 or memory.read(OUT_AT + 1, 1) != wanted[1]:
            return "ok result %d %d want %d" % (tag, memory.read(OUT_AT + 1, 1), wanted[1])
    else:
        if tag != 0xE or memory.read(OUT_AT + 8, 2) != wanted[1]:
            return "status %d %#x want %#x" % (tag, memory.read(OUT_AT + 8, 2), wanted[1])
        if wanted[2] is not None and memory.read(OUT_AT + 0x10, 8) & (0xFFFF if wanted[1] == 0x11F else MASK[8]) != wanted[2]:
            return "status word"
    if height <= 0x0CCCCCCCCCCCCCCB:
        rows = [row for row in harness.events if row[0] == "recover"]
        digest = hashlib.sha256(digest_input).hexdigest()
        if rows != [("recover", signature(sig_index)[:0x41].hex(), digest, digest_input.hex())]:
            return "recovery input"
    return None


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def status_row(image, tag):
    """Display arm of a status tag: a direct text, a format piece, or a shape this reader leaves unnamed."""
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE) + 4 * tag)[0]
    data = code(image, arm, 64)
    at = data.find(b"\x48\x8d\x35")
    if at >= 0 and data[at + 7] == 0xBA:
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        return tag, arm, "text", code(image, text, size).decode("ascii")
    at = data.find(b"\x48\x8d\x15")
    if at >= 0:
        piece = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = code(image, piece, 1)[0]
        return tag, arm, "piece", code(image, piece + 1, size).decode("ascii", "replace") + "{}"
    return tag, arm, "other", ""


def slot_sites(image, slot):
    """FF 15 sites through one slot, by byte scan of .text."""
    base, text = image.text_bytes()
    out = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            out.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return out


def direct_sites(image, target):
    base, text = image.text_bytes()
    out = []
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text) and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            out.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return out


def dispatch_arm(image):
    """Arm of action row 48 in the relative jump table, and the first direct call in it."""
    arm = DISPATCH_TABLE + struct.unpack_from("<i", image.blob, image.offset(DISPATCH_TABLE) + 4 * ARM_ROW)[0]
    data = code(image, arm, 0x80)
    for at in range(len(data) - 5):
        if data[at] == 0xE8:
            target = arm + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
            if target == WRAPPERS[0]:
                return arm, arm + at, target
    raise EvidenceError("arm 48 does not call the wrapper")


def text_rows(image):
    """Serde names of the tracker, by byte search of .rodata."""
    data = image.rodata_bytes()
    lines = ["text\tfirst_address\tcount"]
    for text in NAME_TEXTS:
        raw = text.encode("ascii")
        at = data[1].find(raw)
        if at < 0:
            raise EvidenceError("text moved: " + text)
        lines.append("%s\t%#x\t%d" % (text, data[0] + at, data[1].count(raw)))
    return lines


def key_row_lines(image):
    lines = ["address\tbytes\tmeaning"]
    for va, hexed, meaning in KEY_ROWS:
        found = code(image, va, len(hexed) // 2).hex()
        if found != hexed:
            raise EvidenceError("row moved at %#x" % va)
        lines.append("%#x\t%s\t%s" % (va, hexed, meaning))
    return lines


def handler_name():
    data = json.loads(HANDLERS.read_text())
    for row in data["cases"]:
        if row["index"] == ARM_ROW:
            return (row.get("reconstruction") or {}).get("wire_type") or "-"
    return "-"


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}


MUTANT_STATE = {}
FAULTS = (Halt, Panicked, EvidenceError, KeyError, ValueError, IndexError, OverflowError, TypeError, RecursionError, struct.error)


def worker_start():
    image = load_image()
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    MUTANT_STATE.update(harness=harness, cases=all_cases())


def run_one(task):
    function, va, at, kind, indices = task
    harness = MUTANT_STATE["harness"]
    cases = MUTANT_STATE["cases"]
    machine = harness.machine
    machine.patches = mutate_patch(harness.image, va, at, kind)
    machine.cache.pop(va, None)
    failed = None
    for index in indices:
        try:
            trouble = compare(harness, None, cases[index])
        except FAULTS as error:
            trouble = type(error).__name__
        if trouble:
            failed = cases[index].label + ": " + trouble
            break
    machine.patches = {}
    machine.cache.pop(va, None)
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:60].replace("\t", " ") if failed else ""}


def run_mutants(image, targets, reached, costs, labels):
    by_va = {}
    sentinels = frozenset(index for index, label in enumerate(labels) if label in SENTINELS)
    for index in sorted(range(len(reached)), key=lambda item: (costs[item], item)):
        for va in reached[index]:
            by_va.setdefault(va, []).append(index)
    tasks = []
    results = []
    for start, _ in targets:
        begin, end = image.exact_fde(start)
        for va, at, kind in mutation_targets(image, body_rows(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            chosen = indices[:3]
            rest = [index for index in indices[3:] if costs[index] < MUTANT_CASE_COST] or indices[3:4]
            if rest:
                step = max(len(rest) / (MUTANT_CASES - 3), 1)
                chosen += [rest[int(step * item)] for item in range(MUTANT_CASES - 3) if int(step * item) < len(rest)]
            tasks.append((start, va, at, kind, sorted(set(chosen) | (sentinels & set(indices)))))
    with multiprocessing.Pool(WORKERS, worker_start) as pool:
        results += pool.map(run_one, tasks, 8)
    return sorted(results, key=lambda row: (row["function"], row["va"], row["kind"]))


# ---- evidence ----

CORE_FUNCTIONS = ((WRAPPERS[0], "wrapper", True), (WRAPPERS[1], "wrapper copy", False), (WRAPPERS[2], "wrapper copy", False), (DIGEST, "Keccak of the signable pair", True), (CORE, "arm core", True), (TRACKER, "tracker", True), (ELIGIBLE, "voter key in epoch test", True),
                  (QUORUM, "bucket quorum", True), (NEW_HEIGHT, "height entry insert", True), (NEW_HASH, "hash entry insert", True), (DEAD_SCAN, "first 100 heights scan", True), (PRUNE, "height split", True), (PRUNE_LIST, "removed height list", True), (TAKE, "block step take and filter", True),
                  (L1_TRACKER, "voteL1Hash tracker", True), (L1_QUORUM, "stake AND ratio quorum", True), (HARD_INSERT, "listed vote insert", True), (L1_NEW_HEIGHT, "L1 height entry insert", True), (L1_NEW_HASH, "L1 hash entry insert", True),
                  (HARD_CLONE, "listed map clone", False), (HARD_KEYS, "listed key list", False), (RATIO, "ratio test, shared", False), (VOTER_KEY, "signer to voter key, shared", False), (HOT_USER, "voter key to hot user, shared", False), (STAKE_TEST, "two thirds stake test, shared", False), (INSERT, "vote insert, shared", False), (CLONE_VOTES, "signature map clone, shared", False), (ROW_COLLECT, "hot row collect, shared", False), (SIGNABLE, "pair writer, shared", False))


def analyse(image, full=True):
    harness = Harness(image)
    cases = all_cases()
    machine = harness.machine
    mismatches = []
    reached = []
    costs = []
    seen = set()
    lines = []
    for case in cases:
        machine.seen = set()
        before = machine.steps
        harness.tally = collections.Counter()
        try:
            trouble = compare(harness, None, case)
        except (Halt, Panicked) as error:
            trouble = "%s %s" % (type(error).__name__, error)
        if trouble:
            mismatches.append("%s: %s" % (case.label, trouble))
        reached.append(frozenset(machine.seen))
        costs.append(machine.steps - before)
        seen |= machine.seen
        lines.append("\t".join((case.kind, case.label, str(len(case.ops)), " ".join("%s=%d" % item for item in sorted(harness.tally.items())) or "-", "fail" if trouble else "match")))
        for key, value in harness.tally.items():
            OUTCOMES[key] += value
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    for start, role, _ in CORE_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = body_rows(image, begin, end)
        hit = sum(1 for row in rows if row.va in seen)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "instructions": len(rows), "stepped": hit})
        function_lines.append("%#x\t%#x\t%d\t%d\t%d\t%s" % (begin, end, end - begin, len(rows), hit, role))
    targets = [(start, role) for start, role, claimed in CORE_FUNCTIONS if claimed]
    results_rows = run_mutants(image, targets, reached, costs, [case.label for case in cases]) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    arm, site, _ = dispatch_arm(image)
    site_lines = ["relation\tsite\thost"]
    for address in direct_sites(image, WRAPPERS[0]) + direct_sites(image, WRAPPERS[1]) + direct_sites(image, WRAPPERS[2]):
        site_lines.append("wrapper call\t%#x\t%#x" % (address, image.fde(address)[0]))
    for slot, name in ((SLOT_CORE, "core through slot"), (SLOT_TAKE, "take through slot")):
        for address in slot_sites(image, slot):
            site_lines.append("%s\t%#x\t%#x" % (name, address, image.fde(address)[0]))
    for address in direct_sites(image, TRACKER):
        site_lines.append("tracker call\t%#x\t%#x" % (address, image.fde(address)[0]))
    status_lines = ["tag\tarm\tform\ttext"]
    for tag, status_arm, form, text in (status_row(image, tag) for tag in STATUS_TAGS):
        status_lines.append("%#x\t%#x\t%s\t%s" % (tag, status_arm, form, text))
    layout_lines = ["tree\tkey_at\tkey_size\tvalue_at\tvalue_size\tparent_at\tindex_at\tcount_at\tleaf_size"]
    for item in LAYOUTS:
        layout_lines.append("%s\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x" % (item.name, item.key_at, item.key_size, item.value_at, item.value_size, item.parent_at, item.index_at, item.count_at, item.leaf))
    vector_lines = ["height\tsigned_bytes\tkeccak_input_length"]
    for height in SIGNED_HEIGHTS:
        vector_lines.append("%#x\t%s\t%d" % (height, harness.signed[height], len(harness.signed[height]) // 2))
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": {"total": len(cases), "operations": sum(len(case.ops) for case in cases), "app_hash": sum(1 for case in cases if case.kind != "l1"), "l1_tracker": sum(1 for case in cases if case.kind == "l1")},
        "outcomes": dict(sorted(OUTCOMES.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0][:200] if mismatches else "",
        "instructions_stepped": steps,
        "functions": functions,
        "mutations": tally,
        "dispatch": {"table": "%#x" % DISPATCH_TABLE, "row": ARM_ROW, "name": handler_name(), "arm": "%#x" % arm, "call": "%#x" % site, "wrapper": "%#x" % WRAPPERS[0]},
        "constants": {"prune_depth": PRUNE_DEPTH, "wrapper_height_limit": "0xccccccccccccccb", "core_height_limit": "0xccccccccccccccc", "scan_trigger": 101, "scan_take": 100, "tracker_state_offset": "0x3540", "copy_tracker_state_offset": "0x3fc0", "context_state_offset": "0x3840", "l1_tracker_state_offset": "0x35b0"},
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_sites": site_lines, "_status": status_lines, "_layouts": layout_lines, "_vectors": vector_lines, "_keys": key_row_lines(image), "_names": text_rows(image),
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, a tree edge step or a list growth arm with no fixture"
SURVIVOR_REASON = "not hand checked row by row: copy size, stack base, capacity, alignment, free guard, tree edge test, or a value only a stub or the discarded scan reads"
OUTCOMES = collections.Counter()


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toperations\toutcomes\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "call-sites.tsv": evidence.pop("_sites"), "status-text.tsv": evidence.pop("_status"),
              "node-layouts.tsv": evidence.pop("_layouts"), "signed-bytes.tsv": evidence.pop("_vectors"), "key-rows.tsv": evidence.pop("_keys"), "names.tsv": evidence.pop("_names")}
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    for name, lines in tables.items():
        files[name] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else (UNREACHED_REASON if row["result"] == "unreached" else SURVIVOR_REASON))) for row in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
