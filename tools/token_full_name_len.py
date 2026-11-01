#!/usr/bin/env python3
"""RE-036: token full-name length + already-set guards at 0x2748b80 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * Carve 0x2748b80..0x2748c4e (206 bytes exclusive end at first int3;
    2-byte int3 pad then next function push-rbp at 0x2748c50);
  * No GOT R_X86_64_RELATIVE for this entry; exactly 1 direct e8 caller
    at 0x23e8565, 0 e9, 0 inbound ff15 via GOT;
  * Rule A (len 1..=50): add rdx,-0x33 / cmp rdx,-0x33 / ja Ok-path;
    else Err 0xdf + string 0x5996ec / 56
    "token full name must be between 1 and 50 characters long";
  * Rule B (already set): xor edx,edx; cmp [rax+rcx+0x68],rdx; jno
    -> Err 0xdf + string 0x5996d7 / 21 "full name already set";
  * Ok tag 0x186 is a movw STORE at 0x2748c0f (not a compare-gate).

Claims the RULES only. Adjacent: OUR RE-030 at 0x375f3d0 also LEAs the
length string inside its host carve, but THIS is a separate 206 B helper.
Merged #650 inventories this FDE start only (no carve/rule claim).
Output is sorted deterministic JSON. Stdlib only; no emulation.
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
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

FN = 0x2748B80
FN_END = 0x2748C4E
CARVED_LEN = FN_END - FN
CARVED_SHA256 = "64084d429162ad92eb0845b9185504e12fbed1ff1c8c0229e9240b667abf167e"
NEXT_FN = 0x2748C50

GOT_SLOT = None
R_X86_64_RELATIVE = 8
DIRECT_E8_SITES = (0x23E8565,)

OK_TAG = 0x186
ERR_TAG = 0xDF
ERR_TAG_VA = 0x2748BD6
OK_STORE_VA = 0x2748C0F

ADD_VA = 0x2748BB2
CMP_LEN_VA = 0x2748BB6
JA_VA = 0x2748BBA
LEN_IMM = 0x33
MOV_LEN_EAX_VA = 0x2748BBC
LEA_LEN_STR_VA = 0x2748BC1
STR_LEN_IMM = 0x38

OPT_XOR_VA = 0x2748BA5
OPT_CMP_VA = 0x2748BA7
OPT_JNO_VA = 0x2748BAC
MOV_SET_EAX_VA = 0x2748BCA
LEA_SET_STR_VA = 0x2748BCF
STR_SET_IMM = 0x15

ERROR_STRINGS = (
    (
        "token_full_name_len",
        0x5996EC,
        b"token full name must be between 1 and 50 characters long",
        LEA_LEN_STR_VA,
        STR_LEN_IMM,
    ),
    (
        "full_name_already_set",
        0x5996D7,
        b"full name already set",
        LEA_SET_STR_VA,
        STR_SET_IMM,
    ),
)

# Other LEAs of the length string outside this carve (not claimed).
ADJACENT_LEN_LEA_VAS = (0x375F424, 0x4D64A41, 0x4D64B11)

KEY_INSNS = [
    (0x2748B80, "415653", "prologue push r14; push rbx; push rax"),
    (0x2748BAE, "488b5310", "mov rdx, [rbx+0x10] (name len)"),
    (0x2748BB2, "4883c2cd", "add rdx, -0x33 (len - 51)"),
    (0x2748BB6, "4883facd", "cmp rdx, -0x33"),
    (0x2748BBA, "773e", "ja Ok-path (unsigned range 1..=50)"),
    (0x2748BBC, "b838000000", "mov eax, 0x38 (len-string length 56)"),
    (0x2748BC1, "488d0d240be5fd", "lea rcx, [rip+ string 0x5996ec]"),
    (0x2748BA5, "31d2", "xor edx, edx (Option None tag)"),
    (0x2748BA7, "483b540868", "cmp [rax+rcx+0x68], rdx (Option Some?)"),
    (0x2748BAC, "711c", "jno already-set Err path"),
    (0x2748BCA, "b815000000", "mov eax, 0x15 (already-set string len 21)"),
    (0x2748BCF, "488d0d010be5fd", "lea rcx, [rip+ string 0x5996d7]"),
    (0x2748BD6, "6641c706df00", "movw [r14], 0xdf Err"),
    (0x2748C0F, "6641c7068601", "movw [r14], 0x186 Ok STORE"),
    (0x23E8565, "e816063600", "direct e8 caller to entry"),
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
    """Find lea reg, [rip+disp32] sites whose resolved target equals target."""
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


def range_gate_accepts(length):
    """Mirror the unsigned add/cmp/ja gate: accept iff length in 1..=50."""
    rdx = (length + 0xFFFFFFFFFFFFFFCD) & 0xFFFFFFFFFFFFFFFF
    return rdx > 0xFFFFFFFFFFFFFFCD


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

    error_strings = []
    for name, sva, expected, lea_va, strlen_imm in ERROR_STRINGS:
        raw = read_va(data, segs, sva, len(expected))
        occ = string_occurrences(data, expected)
        lea_bytes = read_va(data, segs, lea_va, 7)
        lea_rel = struct.unpack_from("<i", lea_bytes, 3)[0]
        lea_tgt = lea_va + 7 + lea_rel
        all_leas = lea_rip_targets(data, segs, sva)
        error_strings.append(
            {
                "name": name,
                "va": hex(sva),
                "len": len(expected),
                "len_expected": strlen_imm,
                "bytes_hex": raw.hex(),
                "expected_hex": expected.hex(),
                "text": expected.decode("ascii"),
                "match": raw == expected and len(raw) == len(expected),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "occurrence_count": len(occ),
                "occurrences": occ,
                "lea_in_carve": {
                    "va": hex(lea_va),
                    "bytes": lea_bytes.hex(),
                    "target": hex(lea_tgt),
                    "targets_string": lea_tgt == sva,
                },
                "lea_rip_refs_all": [hex(v) for v in all_leas],
                "lea_rip_ref_count": len(all_leas),
            }
        )

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

    add_bytes = read_va(data, segs, ADD_VA, 4)
    cmp_len_bytes = read_va(data, segs, CMP_LEN_VA, 4)
    ja_bytes = read_va(data, segs, JA_VA, 2)
    opt_cmp_bytes = read_va(data, segs, OPT_CMP_VA, 5)
    opt_jno_bytes = read_va(data, segs, OPT_JNO_VA, 2)
    err_tag_bytes = read_va(data, segs, ERR_TAG_VA, 6)
    ok_store_bytes = read_va(data, segs, OK_STORE_VA, 6)

    range_proof = {
        "reject_0": not range_gate_accepts(0),
        "accept_1": range_gate_accepts(1),
        "accept_50": range_gate_accepts(50),
        "reject_51": not range_gate_accepts(51),
        "accept_count_1_to_50": sum(1 for n in range(1, 51) if range_gate_accepts(n)),
        "reject_outside": all(
            not range_gate_accepts(n) for n in (0, 51, 52, 100, 255)
        ),
    }

    rules = [
        {
            "name": "full_name_len_1_to_50",
            "claimed": True,
            "description": (
                "reject when name length not in 1..=50 via unsigned "
                "add/cmp -0x33 (51) / ja"
            ),
            "add_va": hex(ADD_VA),
            "add_bytes": add_bytes.hex(),
            "add_expected": "4883c2cd",
            "cmp_va": hex(CMP_LEN_VA),
            "cmp_bytes": cmp_len_bytes.hex(),
            "cmp_expected": "4883facd",
            "ja_va": hex(JA_VA),
            "ja_bytes": ja_bytes.hex(),
            "immediate": LEN_IMM,
            "immediate_meaning": "51 (unsigned wrap for range 1..=50)",
            "match": (
                add_bytes.hex() == "4883c2cd"
                and cmp_len_bytes.hex() == "4883facd"
                and ja_bytes.hex() == "773e"
                and range_proof["reject_0"]
                and range_proof["accept_1"]
                and range_proof["accept_50"]
                and range_proof["reject_51"]
            ),
            "negative": (
                "tamper add/cmp -0x33 immediate or ja -> range gate fails pin"
            ),
            "err_string": "token_full_name_len",
        },
        {
            "name": "full_name_already_set",
            "claimed": True,
            "description": (
                "reject when name Option is already Some "
                "(xor edx,edx; cmp [slot],rdx; jno)"
            ),
            "xor_va": hex(OPT_XOR_VA),
            "cmp_va": hex(OPT_CMP_VA),
            "cmp_bytes": opt_cmp_bytes.hex(),
            "cmp_expected": "483b540868",
            "jno_va": hex(OPT_JNO_VA),
            "jno_bytes": opt_jno_bytes.hex(),
            "jno_expected": "711c",
            "match": (
                opt_cmp_bytes.hex() == "483b540868"
                and opt_jno_bytes.hex() == "711c"
                and read_va(data, segs, OPT_XOR_VA, 2).hex() == "31d2"
            ),
            "negative": "tamper Option cmp or jno -> already-set pin fails",
            "err_string": "full_name_already_set",
        },
    ]

    negatives = {
        "len_add_imm_is_neg_0x33": add_bytes.hex() == "4883c2cd",
        "len_cmp_imm_is_neg_0x33": cmp_len_bytes.hex() == "4883facd",
        "len_ja_present": ja_bytes.hex() == "773e",
        "range_rejects_0_and_ge_51": range_proof["reject_0"]
        and range_proof["reject_51"],
        "range_accepts_1_through_50": range_proof["accept_count_1_to_50"] == 50,
        "option_cmp_match": opt_cmp_bytes.hex() == "483b540868",
        "option_jno_match": opt_jno_bytes.hex() == "711c",
        "err_tag_is_0xdf": err_tag_bytes.hex() == "6641c706df00",
        "ok_tag_is_movw_0x186": ok_store_bytes.hex() == "6641c7068601",
        "string_len_exact": error_strings[0]["match"]
        and error_strings[0]["len"] == 56,
        "string_already_set_exact": error_strings[1]["match"]
        and error_strings[1]["len"] == 21,
        "no_got_relative_for_entry": len(relative_to_entry) == 0,
        "lea_len_targets_string": error_strings[0]["lea_in_carve"]["targets_string"],
        "lea_set_targets_string": error_strings[1]["lea_in_carve"]["targets_string"],
    }

    adjacent_prior_work = {
        "component": "RE-030",
        "entry": "0x375f3d0",
        "carve": "0x375f3d0..0x375fa78",
        "note": (
            "Adjacent but separate spot-token deploy name/decimals guard. "
            "The same length string is also LEAd inside RE-030 host at "
            "0x375f424, but THIS packet pins the separate 206 B helper at "
            "0x2748b80, not that carve."
        ),
        "length_string_lea_outside_carve": [hex(v) for v in ADJACENT_LEN_LEA_VAS],
        "inventory_only": {
            "pr": 650,
            "note": (
                "Merged #650 spot-meta inventory lists FDE start 0x2748b80 "
                "as a census entry only; no carve or rule claim there "
                "(same pattern as RE-034)."
            ),
        },
    }

    result = {
        "abi": {
            "err_tag": hex(ERR_TAG),
            "err_tag_va": hex(ERR_TAG_VA),
            "err_tag_bytes": err_tag_bytes.hex(),
            "ok_tag": hex(OK_TAG),
            "ok_store_va": hex(OK_STORE_VA),
            "ok_store_bytes": ok_store_bytes.hex(),
            "ok_note": (
                "Ok 0x186 is a movw STORE at 0x2748c0f on the success path "
                "(not a compare-gate)"
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
        "claim": "token_full_name_len_and_already_set_rules_only",
        "component": "RE-036",
        "direct_call_sites": [hex(v) for v in direct_e8],
        "direct_calls": len(direct_e8) + len(direct_e9),
        "direct_e9_calls": len(direct_e9),
        "error_strings": error_strings,
        "extent": {
            "carve_note": (
                "Exclusive end 0x2748c4e is the first int3 after the "
                "function body (including cold unwind tail); 2-byte int3 "
                "pad then next function begins at push-rbp 0x2748c50. "
                "Claims full-name length 1..=50 and already-set only."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_rbp": next_fn_bytes[:1] == b"\x55",
            "next_fn_va": hex(next_fn_va),
        },
        "ff15_inbound_via_got": 0,
        "got_addend_match": False,
        "got_rela": None,
        "got_slot": GOT_SLOT,
        "got_relative_to_entry": relative_to_entry,
        "key_insns": key_insns,
        "key_insns_all_match": all(k["match"] for k in key_insns),
        "len_immediate": LEN_IMM,
        "negatives": negatives,
        "range_proof": range_proof,
        "rules": rules,
        "slot_ref_counts": {"call": 0, "jmp": 0, "mov": 0},
        "slot_refs": [],
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
            errs.append("string " + s["name"] + " occurrence_count != 1")
        if not s["lea_in_carve"]["targets_string"]:
            errs.append("string " + s["name"] + " lea target mismatch")
        if s["len"] != s["len_expected"]:
            errs.append("string " + s["name"] + " len_expected mismatch")
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
    rp = result["range_proof"]
    if not (
        rp["reject_0"]
        and rp["accept_1"]
        and rp["accept_50"]
        and rp["reject_51"]
        and rp["accept_count_1_to_50"] == 50
    ):
        errs.append("range_proof failed")
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
