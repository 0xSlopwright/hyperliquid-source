#!/usr/bin/env python3
"""RE-038: too-many-outcomes (0x31 arm) at 0x372a470 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * Carve 0x372a470..0x372a905 (1173 bytes exclusive end at first int3;
    11-byte int3 pad then next function push-rbp at 0x372a910);
  * GOT slot 0x5774a68 with R_X86_64_RELATIVE addend 0x372a470;
    3 inbound ff15; 0 direct e8/e9;
  * Rule (0x31 arm ONLY): outcome count must be <= 0x31 (49) via
    cmpq imm 0x31 / jbe; fall-through stores Err 0x17b + string
    0x599484 / 30 "too many outcomes for question";
  * Neighbouring Err 0x17b arms (fallback/associated/compatible) are
    observed but NOT claimed. Claims the count-cap RULE only.

Adjacent: open #997 (RE-004 OutcomeDeploy) is a sibling covering daily
deploy caps and settle gates — different string/rule ("too many outcomes
deployed today"), does not claim this 0x31 arm. Output is sorted
deterministic JSON. Stdlib only; no emulation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = (
    "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
)

FN = 0x372A470
FN_END = 0x372A905
CARVED_LEN = FN_END - FN
CARVED_SHA256 = (
    "444bf531ab17fbff260d60d2ed09cd1df892505a1b7ae2d5eabb249f78a8e00d"
)
NEXT_FN = 0x372A910

GOT_SLOT = 0x5774A68
R_X86_64_RELATIVE = 8
DIRECT_E8_SITES = ()
FF15_SITES = (0x2719C06, 0x4D12096, 0x4D127A6)

ERR_TAG = 0x17B
CMP_VA = 0x372A54F
JBE_VA = 0x372A555
JBE_TARGET = 0x372A574
ERR_VA = 0x372A557
LEA_STR_VA = 0x372A55C
STR_LEN_STORE_VA = 0x372A567
STR_LEN_IMM = 0x1E
CMP_IMM = 0x31

ERROR_STRING = (
    "too_many_outcomes",
    0x599484,
    b"too many outcomes for question",
)

# Neighbouring Err 0x17b sites in the same carve (NOT claimed).
NEIGHBOUR_ERR_SITES = (
    (0x372A580, 0x59945B, "cannot register fallback as named outcome"),
    (0x372A6AD, 0x599441, "outcome already associated"),
    (0x372A8E1, 0x59941D, "outcome not compatible with question"),
)

KEY_INSNS = [
    (0x372A470, "554157415641554154", "push rbp; push r15; push r14; push r13; push r12"),
    (0x372A54F, "4a837c09e031", "cmp qword [rcx+r9*1-0x20], 0x31"),
    (0x372A555, "761d", "jbe 0x372a574 (count <= 0x31 continue)"),
    (0x372A557, "66c7037b01", "movw [rbx], 0x17b Err STORE (0x31 arm)"),
    (0x372A55C, "488d0521efe6fc", "lea rax, [rip+ string 0x599484]"),
    (0x372A563, "48894308", "mov [rbx+0x8], rax (string ptr)"),
    (0x372A567, "48c743101e000000", "mov qword [rbx+0x10], 0x1e (len 30)"),
    (0x2719C06, "ff155cae0503", "ff15 inbound via GOT"),
    (0x4D12096, "ff15cc29a600", "ff15 inbound via GOT"),
    (0x4D127A6, "ff15bc22a600", "ff15 inbound via GOT"),
]


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        out.append((p_vaddr, p_offset, p_filesz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            return data[off + va - base : off + va - base + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from(
        "<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24
    )
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [
                struct.unpack_from("<QQq", data, off + k * 24)
                for k in range(size // 24)
            ]
    return []


def count_direct_calls(data, segs, target):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 5:
            if code[i] in (0xE8, 0xE9):
                va = base + i
                tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt == target:
                    sites.append((code[i], va))
                i += 5
                continue
            i += 1
    return sites


def count_ff15_to_got(data, segs, got):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 6:
            if code[i] == 0xFF and code[i + 1] == 0x15:
                va = base + i
                rel = struct.unpack_from("<i", code, i + 2)[0]
                if va + 6 + rel == got:
                    sites.append(va)
                i += 6
                continue
            i += 1
    return sorted(sites)


def string_occurrences(data, needle):
    out = []
    start = 0
    segs = segments(data)
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        va = None
        for base, off, filesz in segs:
            if off <= i < off + filesz:
                va = base + (i - off)
                break
        out.append({"file_offset": hex(i), "va": hex(va) if va is not None else None})
        start = i + 1
    return out


def lea_rip_targets(data, segs, target):
    hits = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 7:
            b0 = code[i]
            if b0 in (0x48, 0x4C) and code[i + 1] == 0x8D and (code[i + 2] & 0xC7) == 0x05:
                va = base + i
                rel = struct.unpack_from("<i", code, i + 3)[0]
                if va + 7 + rel == target:
                    hits.append(va)
                i += 7
                continue
            i += 1
    return sorted(hits)


def count_gate_accepts(count):
    """Static semantics of unsigned cmp imm 0x31 / jbe: accept when count <= 0x31."""
    return (count & 0xFFFFFFFFFFFFFFFF) <= CMP_IMM


def analyse(data, check_sha=True):
    if check_sha:
        digest = hashlib.sha256(data).hexdigest()
        if digest != BINARY_SHA256:
            raise SystemExit("binary sha256 mismatch: " + digest)

    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    carve_sha = hashlib.sha256(carved).hexdigest()

    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    next_fn_va = FN_END + int3_pad
    next_fn_bytes = read_va(data, segs, next_fn_va, 2)

    rela = rela_dyn(data)
    relative_to_entry = [
        {"r_offset": hex(off), "r_info": hex(info), "r_addend": hex(addend)}
        for off, info, addend in rela
        if addend == FN and (info & 0xFFFFFFFF) == R_X86_64_RELATIVE
    ]
    got_rela = None
    for off, info, addend in rela:
        if off == GOT_SLOT and (info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
            got_rela = {
                "r_offset": hex(off),
                "r_info": hex(info),
                "r_addend": hex(addend),
            }
            break

    direct_sites = count_direct_calls(data, segs, FN)
    direct_e8 = sorted(va for kind, va in direct_sites if kind == 0xE8)
    direct_e9 = sorted(va for kind, va in direct_sites if kind == 0xE9)
    ff15 = count_ff15_to_got(data, segs, GOT_SLOT)

    name, sva, expected = ERROR_STRING
    raw = read_va(data, segs, sva, len(expected))
    occ = string_occurrences(data, expected)
    lea_bytes = read_va(data, segs, LEA_STR_VA, 7)
    lea_rel = struct.unpack_from("<i", lea_bytes, 3)[0]
    lea_tgt = LEA_STR_VA + 7 + lea_rel
    all_leas_primary = lea_rip_targets(data, segs, sva)

    error_string = {
        "name": name,
        "va": hex(sva),
        "len": len(expected),
        "len_expected": STR_LEN_IMM,
        "bytes_hex": raw.hex(),
        "expected_hex": expected.hex(),
        "text": expected.decode("ascii"),
        "match": raw == expected and len(raw) == len(expected),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "occurrence_count": len(occ),
        "occurrences": occ,
        "lea_in_carve": {
            "va": hex(LEA_STR_VA),
            "bytes": lea_bytes.hex(),
            "target": hex(lea_tgt),
            "targets_string": lea_tgt == sva,
        },
        "lea_rip_refs_primary": [hex(v) for v in all_leas_primary],
        "duplicate_copies_not_claimed": [],
        "not_claimed_leas_of_duplicates": [],
    }

    key_insns = []
    for va, hx, note in KEY_INSNS:
        got = read_va(data, segs, va, len(hx) // 2)
        key_insns.append(
            {
                "va": hex(va),
                "bytes": got.hex(),
                "expected": hx,
                "match": got.hex() == hx,
                "note": note,
            }
        )

    cmp_bytes = read_va(data, segs, CMP_VA, 6)
    jbe_bytes = read_va(data, segs, JBE_VA, 2)
    jbe_rel = struct.unpack_from("<b", jbe_bytes, 1)[0]
    jbe_tgt = JBE_VA + 2 + jbe_rel
    err_bytes = read_va(data, segs, ERR_VA, 5)
    strlen_bytes = read_va(data, segs, STR_LEN_STORE_VA, 8)

    rule_match = (
        cmp_bytes.hex() == "4a837c09e031"
        and jbe_bytes.hex() == "761d"
        and jbe_tgt == JBE_TARGET
        and err_bytes.hex() == "66c7037b01"
        and lea_tgt == sva
        and strlen_bytes.hex() == "48c743101e000000"
        and ERR_VA == JBE_VA + 2
    )

    rules = [
        {
            "name": "too_many_outcomes_count_le_0x31",
            "claimed": True,
            "description": (
                "reject when outcome count > 0x31 (49): "
                "cmpq imm 0x31 / jbe continue; fall-through Err 0x17b + string"
            ),
            "cmp_va": hex(CMP_VA),
            "cmp_bytes": cmp_bytes.hex(),
            "cmp_expected": "4a837c09e031",
            "cmp_immediate": CMP_IMM,
            "jbe_va": hex(JBE_VA),
            "jbe_bytes": jbe_bytes.hex(),
            "jbe_expected": "761d",
            "jbe_target": hex(jbe_tgt),
            "jbe_target_expected": hex(JBE_TARGET),
            "proof": {
                "count_le_0x31_continues": (
                    "unsigned cmp; jbe taken when count <= 0x31 -> 0x372a574"
                ),
                "count_gt_0x31_takes_err": (
                    "jbe not taken when count > 0x31; fall-through to "
                    "0x372a557 Err 0x17b + lea string + len 0x1e"
                ),
            },
            "match": rule_match,
            "negative": "tamper cmp imm 0x31 or jbe opcode/rel -> refuse pin fails",
            "err_string": "too_many_outcomes",
            "truth_table": {
                "accepts_0": count_gate_accepts(0),
                "accepts_49": count_gate_accepts(0x31),
                "rejects_50": not count_gate_accepts(0x32),
            },
        },
    ]

    negatives = {
        "cmp_bytes_match": cmp_bytes.hex() == "4a837c09e031",
        "cmp_imm_is_0x31": cmp_bytes[-1] == CMP_IMM,
        "jbe_bytes_match": jbe_bytes.hex() == "761d",
        "jbe_targets_continue": jbe_tgt == JBE_TARGET,
        "err_is_fallthrough_of_jbe": ERR_VA == JBE_VA + 2,
        "err_17b_movw_store": err_bytes.hex() == "66c7037b01",
        "string_exact": error_string["match"] and error_string["len"] == 30,
        "string_len_imm_0x1e": strlen_bytes.hex() == "48c743101e000000",
        "lea_targets_string": error_string["lea_in_carve"]["targets_string"],
        "occurrence_count_is_1": error_string["occurrence_count"] == 1,
        "got_rela_present": got_rela is not None
        and got_rela["r_addend"] == hex(FN),
        "ff15_inbound_is_3": len(ff15) == 3,
        "no_direct_e8_e9": len(direct_e8) + len(direct_e9) == 0,
        "range_accepts_0_through_49": all(
            count_gate_accepts(n) for n in range(0, 0x32)
        ),
        "range_rejects_ge_50": all(
            not count_gate_accepts(n) for n in (0x32, 0x33, 100, 255)
        ),
    }

    neighbour_arms = [
        {
            "err_va": hex(eva),
            "err_bytes": read_va(data, segs, eva, 5).hex(),
            "string_va": hex(sva_n),
            "string_text": text,
            "claimed": False,
            "note": "neighbouring Err 0x17b arm in same carve; not claimed",
        }
        for eva, sva_n, text in NEIGHBOUR_ERR_SITES
    ]

    adjacent_prior_work = {
        "sibling": {
            "pr": 997,
            "component": "RE-004",
            "note": (
                "Open #997 (RE-004 OutcomeDeploy) covers daily deploy caps "
                "and settle gates with string too many outcomes deployed "
                "today; it does not claim entry 0x372a470, string 0x599484, "
                "or this 0x31 count-cap arm."
            ),
        },
        "inventory_only": [],
    }

    result = {
        "abi": {
            "err_tag": hex(ERR_TAG),
            "err_tag_va": hex(ERR_VA),
            "err_tag_bytes": err_bytes.hex(),
            "err_tag_kind": "movw_store",
            "err_note": (
                "Err 0x17b is a movw STORE at the fall-through of the "
                "0x31 jbe (claimed arm only). Neighbouring 0x17b stores "
                "in this carve belong to other arms and are not claimed."
            ),
        },
        "adjacent_prior_work": adjacent_prior_work,
        "binary": "artifacts/node/94/hl-node",
        "binary_sha256": BINARY_SHA256,
        "carve": {
            "start": hex(FN),
            "end": hex(FN_END),
            "len": CARVED_LEN,
            "sha256": carve_sha,
            "sha256_expected": CARVED_SHA256,
            "sha256_match": carve_sha == CARVED_SHA256,
        },
        "claim": "too_many_outcomes_0x31_arm_only",
        "component": "RE-038",
        "direct_call_sites": [hex(v) for v in direct_e8],
        "direct_calls": len(direct_e8) + len(direct_e9),
        "direct_e9_calls": len(direct_e9),
        "error_strings": [error_string],
        "extent": {
            "carve_note": (
                "Exclusive end 0x372a905 is the first int3 after the "
                "function body; 11-byte int3 pad then next function begins "
                "at push-rbp 0x372a910. Claims the 0x31 count-cap arm only."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_rbp": next_fn_bytes[:1] == bytes([0x55]),
            "next_fn_va": hex(next_fn_va),
        },
        "ff15_inbound_via_got": len(ff15),
        "ff15_sites": [hex(v) for v in ff15],
        "got_addend_match": bool(
            got_rela and got_rela["r_addend"] == hex(FN)
        ),
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "got_relative_to_entry": relative_to_entry,
        "key_insns": key_insns,
        "key_insns_all_match": all(k["match"] for k in key_insns),
        "negatives": negatives,
        "neighbour_arms_not_claimed": neighbour_arms,
        "rules": rules,
        "slot_ref_counts": {
            "call": len(ff15),
            "jmp": 0,
            "mov": 0,
        },
        "slot_refs": [{"va": hex(v), "kind": "ff15"} for v in ff15],
        "string_len_immediate": {
            "va": hex(STR_LEN_STORE_VA),
            "bytes": strlen_bytes.hex(),
            "value": STR_LEN_IMM,
            "match": strlen_bytes.hex() == "48c743101e000000",
        },
        "unclaimed_observations": [
            {
                "name": "neighbour_err_0x17b_arms",
                "note": (
                    "Three other movw 0x17b sites in this carve refuse "
                    "fallback/associated/compatible with different strings; "
                    "pinned as neighbour_arms_not_claimed only."
                ),
            },
        ],
    }
    return result


def expectation_errors(result):
    errs = []
    if not result["carve"]["sha256_match"]:
        errs.append("carve sha256 mismatch")
    if result["carve"]["len"] != CARVED_LEN:
        errs.append("carve len mismatch")
    if not result["key_insns_all_match"]:
        for k in result["key_insns"]:
            if not k["match"]:
                errs.append("key_insn mismatch at " + k["va"])
    for s in result["error_strings"]:
        if not s["match"]:
            errs.append("string " + s["name"] + " mismatch")
        if s["occurrence_count"] != 1:
            errs.append("string occurrence_count != 1")
        if not s["lea_in_carve"]["targets_string"]:
            errs.append("string lea target mismatch")
        if s["len"] != s["len_expected"]:
            errs.append("string len_expected mismatch")
    for r in result["rules"]:
        if r["claimed"] and not r["match"]:
            errs.append("rule " + r["name"] + " mismatch")
    for key, val in sorted(result["negatives"].items()):
        if not val:
            errs.append("negative failed: " + key)
    if result["direct_calls"] != 0:
        errs.append("direct_calls != 0")
    if result["got_slot"] != hex(GOT_SLOT):
        errs.append("got_slot mismatch")
    if not result["got_addend_match"]:
        errs.append("got addend mismatch")
    if result["ff15_inbound_via_got"] != 3:
        errs.append("ff15_inbound_via_got != 3")
    if result["ff15_sites"] != [hex(v) for v in FF15_SITES]:
        errs.append("ff15_sites mismatch")
    return errs


def render(result):
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, help="write JSON packet to this path")
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data)
    text = render(result)
    errs = expectation_errors(result)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    sys.stdout.write(text)
    if errs:
        for e in errs:
            print("EXPECT_FAIL", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
