#!/usr/bin/env python3
"""RE-037: USDC-as-base guard at 0x274f860 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * Carve 0x274f860..0x274f994 (308 bytes exclusive end at first int3;
    12-byte int3 pad then next function push-r15 at 0x274f9a0);
  * No GOT R_X86_64_RELATIVE for this entry; exactly 1 direct e8 caller
    at 0x23e81f2, 0 e9, 0 inbound ff15 via GOT;
  * Rule: refuse base token id 0 (USDC) via test rdi,rdi / je ->
    Err 0xdf + string 0x3eff61 / 29 cannot use USDC as base token;
  * Observed tags in carve: Err 0xdf (USDC refuse movw store),
    bounds Err 0xea (two jae OOB paths, movw stores), success 0xac
    (movw stores). Claims the USDC-as-base RULE only.

Adjacent: string also appears as inventory probes in merged #650 / #389
(no carve/rule claim). Duplicate string copies at 0x599641 / 0x715362
have LEAs outside this carve (not claimed). Output is sorted
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

FN = 0x274F860
FN_END = 0x274F994
CARVED_LEN = FN_END - FN
CARVED_SHA256 = (
    "28f03c901694e40ebd39d8c6c0e4fd149268f940fc60726f0ccf3aeb6ee8a3cc"
)
NEXT_FN = 0x274F9A0

GOT_SLOT = None
R_X86_64_RELATIVE = 8
DIRECT_E8_SITES = (0x23E81F2,)

OK_TAG = 0xAC
ERR_TAG = 0xDF
BOUNDS_ERR_TAG = 0xEA

TEST_VA = 0x274F876
JE_VA = 0x274F879
JE_TARGET = 0x274F95B
ERR_DF_VA = 0x274F95B
LEA_STR_VA = 0x274F960
STR_LEN_STORE_VA = 0x274F96B
STR_LEN_IMM = 0x1D
ERR_EA_VA_1 = 0x274F951
ERR_EA_VA_2 = 0x274F974
OK_AC_STACK_VA = 0x274F8F5
OK_AC_STORE_VA = 0x274F981

ERROR_STRING = (
    "usdc_as_base",
    0x3EFF61,
    b"cannot use USDC as base token",
)

DUP_STRING_VAS = (0x599641, 0x715362)
NOT_CLAIMED_LEAS = (
    (0x599641, (0x375EF8E,)),
    (0x715362, (0x4D72180, 0x4D722C0)),
)

KEY_INSNS = [
    (0x274F860, "4889f8", "mov rax, rdi (Result out-ptr)"),
    (0x274F863, "488b39", "mov rdi, [rcx] (load base token id)"),
    (0x274F876, "4885ff", "test rdi, rdi"),
    (0x274F879, "0f84dc000000", "je 0x274f95b (USDC/id0 refuse)"),
    (0x274F95B, "66c700df00", "movw [rax], 0xdf Err STORE"),
    (0x274F960, "488d0dfa05cafd", "lea rcx, [rip+ string 0x3eff61]"),
    (0x274F96B, "48c740101d000000", "mov qword [rax+0x10], 0x1d (len 29)"),
    (0x274F870, "0f83db000000", "jae 0x274f951 (bounds Err 0xea)"),
    (0x274F951, "66c700ea00", "movw [rax], 0xea bounds Err STORE"),
    (0x274F886, "0f83e8000000", "jae 0x274f974 (bounds Err 0xea)"),
    (0x274F974, "66c700ea00", "movw [rax], 0xea bounds Err STORE"),
    (0x274F8F5, "66c7842490000000ac00", "movw [rsp+0x90], 0xac success tag"),
    (0x274F981, "6641c707ac00", "movw [r15], 0xac success STORE"),
    (0x23E81F2, "e869763600", "direct e8 caller to entry"),
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

    direct_sites = count_direct_calls(data, segs, FN)
    direct_e8 = sorted(va for kind, va in direct_sites if kind == 0xE8)
    direct_e9 = sorted(va for kind, va in direct_sites if kind == 0xE9)

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
        "duplicate_copies_not_claimed": [hex(v) for v in DUP_STRING_VAS],
        "not_claimed_leas_of_duplicates": [
            {"string_va": hex(sv), "lea_vas": [hex(v) for v in leas]}
            for sv, leas in NOT_CLAIMED_LEAS
        ],
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

    test_bytes = read_va(data, segs, TEST_VA, 3)
    je_bytes = read_va(data, segs, JE_VA, 6)
    je_rel = struct.unpack_from("<i", je_bytes, 2)[0]
    je_tgt = JE_VA + 6 + je_rel
    err_df_bytes = read_va(data, segs, ERR_DF_VA, 5)
    strlen_bytes = read_va(data, segs, STR_LEN_STORE_VA, 8)
    ea1 = read_va(data, segs, ERR_EA_VA_1, 5)
    ea2 = read_va(data, segs, ERR_EA_VA_2, 5)
    ac_stack = read_va(data, segs, OK_AC_STACK_VA, 10)
    ac_store = read_va(data, segs, OK_AC_STORE_VA, 6)

    rule_match = (
        test_bytes.hex() == "4885ff"
        and je_bytes.hex() == "0f84dc000000"
        and je_tgt == JE_TARGET == ERR_DF_VA
        and err_df_bytes.hex() == "66c700df00"
        and lea_tgt == sva
        and strlen_bytes.hex() == "48c740101d000000"
    )

    rules = [
        {
            "name": "refuse_usdc_as_base",
            "claimed": True,
            "description": (
                "reject when base token id is 0 (USDC): "
                "test rdi,rdi / je -> Err 0xdf + string"
            ),
            "test_va": hex(TEST_VA),
            "test_bytes": test_bytes.hex(),
            "test_expected": "4885ff",
            "je_va": hex(JE_VA),
            "je_bytes": je_bytes.hex(),
            "je_expected": "0f84dc000000",
            "je_target": hex(je_tgt),
            "je_target_expected": hex(JE_TARGET),
            "proof": {
                "rdi_eq_0_takes_refuse": (
                    "test sets ZF when rdi==0; je taken -> 0x274f95b "
                    "Err 0xdf + lea string + len 0x1d"
                ),
                "rdi_neq_0_continues": (
                    "ZF clear when rdi!=0; je not taken -> falls through "
                    "to 0x274f87f"
                ),
            },
            "match": rule_match,
            "negative": "tamper test or je opcode/rel -> refuse pin fails",
            "err_string": "usdc_as_base",
        },
    ]

    negatives = {
        "test_rdi_match": test_bytes.hex() == "4885ff",
        "je_bytes_match": je_bytes.hex() == "0f84dc000000",
        "je_targets_err_df_block": je_tgt == ERR_DF_VA,
        "err_df_movw_store": err_df_bytes.hex() == "66c700df00",
        "string_exact": error_string["match"] and error_string["len"] == 29,
        "string_len_imm_0x1d": strlen_bytes.hex() == "48c740101d000000",
        "lea_targets_string": error_string["lea_in_carve"]["targets_string"],
        "bounds_ea_store_1": ea1.hex() == "66c700ea00",
        "bounds_ea_store_2": ea2.hex() == "66c700ea00",
        "ok_ac_stack_store": ac_stack.hex() == "66c7842490000000ac00",
        "ok_ac_final_store": ac_store.hex() == "6641c707ac00",
        "no_got_relative_for_entry": len(relative_to_entry) == 0,
        "occurrence_count_is_3": error_string["occurrence_count"] == 3,
    }

    adjacent_prior_work = {
        "inventory_only": [
            {
                "pr": 650,
                "note": (
                    "Merged #650 spot-meta inventory lists string VA "
                    "0x3eff61 / probe text as census only; no carve or "
                    "rule claim at 0x274f860."
                ),
            },
            {
                "pr": 389,
                "note": (
                    "Merged #389 inventory lists the string value "
                    "cannot use USDC as base token as a length-bearing "
                    "anchor only; no carve/rule claim for this helper."
                ),
            },
        ],
        "duplicate_string_leas_not_claimed": [
            {
                "string_va": hex(sv),
                "lea_vas": [hex(v) for v in leas],
                "note": "LEA of a packed duplicate copy; not this carve",
            }
            for sv, leas in NOT_CLAIMED_LEAS
        ],
    }

    result = {
        "abi": {
            "err_tag": hex(ERR_TAG),
            "err_tag_va": hex(ERR_DF_VA),
            "err_tag_bytes": err_df_bytes.hex(),
            "err_tag_kind": "movw_store",
            "bounds_err_tag": hex(BOUNDS_ERR_TAG),
            "bounds_err_sites": [
                {
                    "va": hex(ERR_EA_VA_1),
                    "bytes": ea1.hex(),
                    "kind": "movw_store",
                    "reached_by": "jae from 0x274f870 (index OOB)",
                },
                {
                    "va": hex(ERR_EA_VA_2),
                    "bytes": ea2.hex(),
                    "kind": "movw_store",
                    "reached_by": "jae from 0x274f886 (index OOB)",
                },
            ],
            "ok_tag": hex(OK_TAG),
            "ok_sites": [
                {
                    "va": hex(OK_AC_STACK_VA),
                    "bytes": ac_stack.hex(),
                    "kind": "movw_store",
                },
                {
                    "va": hex(OK_AC_STORE_VA),
                    "bytes": ac_store.hex(),
                    "kind": "movw_store",
                },
            ],
            "ok_note": (
                "Success tag 0xac is a movw STORE (stack then [r15]); "
                "not a compare-gate. Bounds Err 0xea are movw STOREs on "
                "jae OOB paths. Claimed rule uses Err 0xdf only."
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
        "claim": "refuse_usdc_as_base_rule_only",
        "component": "RE-037",
        "direct_call_sites": [hex(v) for v in direct_e8],
        "direct_calls": len(direct_e8) + len(direct_e9),
        "direct_e9_calls": len(direct_e9),
        "error_strings": [error_string],
        "extent": {
            "carve_note": (
                "Exclusive end 0x274f994 is the first int3 after the "
                "function body; 12-byte int3 pad then next function begins "
                "at push-r15 0x274f9a0. Claims refuse-USDC-as-base only."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_r15": next_fn_bytes[:2] == bytes([0x41, 0x57]),
            "next_fn_va": hex(next_fn_va),
        },
        "ff15_inbound_via_got": 0,
        "got_addend_match": False,
        "got_rela": None,
        "got_slot": GOT_SLOT,
        "got_relative_to_entry": relative_to_entry,
        "key_insns": key_insns,
        "key_insns_all_match": all(k["match"] for k in key_insns),
        "negatives": negatives,
        "rules": rules,
        "slot_ref_counts": {"call": 0, "jmp": 0, "mov": 0},
        "slot_refs": [],
        "string_len_immediate": {
            "va": hex(STR_LEN_STORE_VA),
            "bytes": strlen_bytes.hex(),
            "value": STR_LEN_IMM,
            "match": strlen_bytes.hex() == "48c740101d000000",
        },
        "unclaimed_observations": [
            {
                "name": "bounds_err_0xea",
                "note": (
                    "Two jae OOB paths store Err 0xea; observed and pinned "
                    "as ABI tags but NOT claimed as a rule (no diagnostic "
                    "string on those paths)."
                ),
            },
            {
                "name": "success_tag_0xac",
                "note": (
                    "Success path movw stores 0xac; pinned as ABI tag, "
                    "not a separate claimed rule."
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
        if s["occurrence_count"] != 3:
            errs.append("string occurrence_count != 3")
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
    if result["direct_calls"] != 1:
        errs.append("direct_calls != 1")
    if result["direct_call_sites"] != [hex(v) for v in DIRECT_E8_SITES]:
        errs.append("direct_call_sites mismatch")
    if result["got_slot"] is not None:
        errs.append("got_slot unexpectedly set")
    if result["got_relative_to_entry"]:
        errs.append("unexpected GOT RELATIVE for entry")
    if result["ff15_inbound_via_got"] != 0:
        errs.append("ff15_inbound_via_got != 0")
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

