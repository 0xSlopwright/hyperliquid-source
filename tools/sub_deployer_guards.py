#!/usr/bin/env python3
"""RE-033: sub-deployer set guards at 0x37186d0 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * FDE 0x37186d0..0x3718e27 (1879 bytes exclusive end at first int3;
    pad then next function push-r15 at 0x3718e30);
  * GOT slot 0x5774bc8 <- R_X86_64_RELATIVE addend 0x37186d0; exactly 3
    ff15 indirect call sites, 0 direct e8/e9 (references-TO-the-entry);
  * Early-reject gate: cmpb $0x3, 0x230(rsi) -> Err tag 0xe3;
  * Duplicate sub-deployer rule: Err 0xe0 + string 0x59900b / 22
    "duplicate sub-deployer";
  * Cannot-set-deployer-as-sub-deployer rule: Err 0xe0 + string 0x599021
    / 35 "cannot set deployer as sub-deployer";
  * Ok tag 0x186;
  * Sibling carve 0x394ce40..0x394d5b6 (called once from the primary at
    0x3718bf9) hosts "too many sub-deployers" (0x5a80b4 / 22) — pinned
    as a related sibling, not a primary claim.

Claims the RULES only (duplicate / cannot-set-deployer / early-reject
network==3). Output is sorted deterministic JSON. Stdlib only; no
emulation.
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

FN = 0x37186D0
FN_END = 0x3718E27  # first int3 after function body
CARVED_LEN = FN_END - FN
CARVED_SHA256 = "62308cdc40af8382651f100f74eb14b98514ab7f57812950d06d7fc02b23b2d0"
NEXT_FN = 0x3718E30

GOT_SLOT = 0x5774BC8
R_X86_64_RELATIVE = 8
FF15_SITES = (0x2740D6B, 0x4D52EF5, 0x4D58915)
SLOT_REFS_EXPECTED = {"call": 3, "jmp": 0, "mov": 0}

OK_TAG = 0x186
ERR_TAG = 0xE0
EARLY_ERR_TAG = 0xE3
OK_TAG_VA = 0x3718C40
ERR_DUP_VA = 0x3718C97
ERR_CANNOT_VA = 0x3718D74
EARLY_ERR_VA = 0x37186F0
EARLY_CMP_VA = 0x37186E7
EARLY_CMP_IMM = 0x3
CALL_SIBLING_VA = 0x3718BF9
SIBLING = 0x394CE40
SIBLING_END = 0x394D5B6
SIBLING_LEN = SIBLING_END - SIBLING
SIBLING_SHA256 = "881764365124024b493d0de1c7eae86b4f17d522401d13a7352af311623286d5"

# Full intended bytes at full length (#1142: ASCII escapes only if needed).
ERROR_STRINGS = [
    (
        "duplicate",
        0x59900B,
        b"duplicate sub-deployer",
    ),
    (
        "cannot_set_deployer",
        0x599021,
        b"cannot set deployer as sub-deployer",
    ),
    (
        "too_many",
        0x5A80B4,
        b"too many sub-deployers",
    ),
]

KEY_INSNS = [
    (0x37186D0, "554157415641554154534881ec580100", "prologue"),
    (0x37186E7, "80be3002000003", "cmpb $0x3,0x230(rsi) early-reject gate"),
    (0x37186F0, "6641c706e300", "movw $0xe3,(r14) early Err"),
    (0x3718BF9, "e842422300", "call too-many sibling 0x394ce40"),
    (0x3718C40, "6641c7068601", "movw $0x186,(r14) Ok"),
    (0x3718C7F, "0f10058503e8fc", "movups duplicate string"),
    (0x3718C97, "6641c706e000", "movw $0xe0,(r14) Err duplicate"),
    (0x3718C9D, "49c7460816000000", "movq $0x16,0x8(r14) len duplicate"),
    (0x3718D63, "0f1005b702e8fc", "movups cannot-set string"),
    (0x3718D74, "6641c706e000", "movw $0xe0,(r14) Err cannot-set"),
    (0x3718D7A, "49c7460823000000", "movq $0x23,0x8(r14) len cannot-set"),
    (0x394CE40, "554157415641554154534881ecb80000", "sibling prologue"),
    (0x394D522, "0f10058babc5fc", "sibling movups too-many string"),
]


def segments(data: bytes):
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


def read_va(data: bytes, segs, va: int, n: int) -> bytes:
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            rel = va - base
            return data[off + rel : off + rel + n]
    raise KeyError(hex(va))


def rela_dyn(data: bytes):
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


def slot_refs(data: bytes, segs, slot: int):
    refs = {"call": [], "jmp": [], "mov": []}
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 6:
            va = base + i
            b0, b1 = code[i], code[i + 1]
            if b0 == 0xFF and b1 == 0x15:
                tgt = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
                if tgt == slot:
                    refs["call"].append(va)
                i += 6
                continue
            if b0 == 0xFF and b1 == 0x25:
                tgt = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
                if tgt == slot:
                    refs["jmp"].append(va)
                i += 6
                continue
            if b0 in (0x48, 0x4C) and b1 == 0x8B and i + 7 <= len(code):
                modrm = code[i + 2]
                if (modrm & 0xC7) == 0x05:
                    tgt = va + 7 + struct.unpack_from("<i", code, i + 3)[0]
                    if tgt == slot:
                        refs["mov"].append(va)
                    i += 7
                    continue
            i += 1
    return refs


def count_direct_calls(data: bytes, segs, target: int) -> int:
    n = 0
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 5:
            if code[i] in (0xE8, 0xE9):
                va = base + i
                tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt == target:
                    n += 1
                i += 5
                continue
            i += 1
    return n


def analyse(data: bytes, check_sha: bool = True) -> dict:
    if check_sha:
        digest = hashlib.sha256(data).hexdigest()
        if digest != BINARY_SHA256:
            raise SystemExit("binary sha256 mismatch: " + digest)

    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    carve_sha = hashlib.sha256(carved).hexdigest()
    sib_carved = read_va(data, segs, SIBLING, SIBLING_LEN)
    sib_sha = hashlib.sha256(sib_carved).hexdigest()

    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    next_fn_va = FN_END + int3_pad
    next_fn_bytes = read_va(data, segs, next_fn_va, 2)

    rela = rela_dyn(data)
    got_rela = None
    got_addend_match = False
    for off, info, addend in rela:
        if off == GOT_SLOT:
            got_rela = {
                "r_offset": hex(off),
                "r_info": hex(info),
                "r_addend": hex(addend),
            }
            got_addend_match = (info & 0xFFFFFFFF) == R_X86_64_RELATIVE and addend == FN
            break

    refs = slot_refs(data, segs, GOT_SLOT)
    slot_ref_list = [{"kind": "call", "va": hex(v)} for v in sorted(refs["call"])]
    counts = {k: len(v) for k, v in refs.items()}
    direct = count_direct_calls(data, segs, FN)

    call_bytes = read_va(data, segs, CALL_SIBLING_VA, 5)
    call_tgt = CALL_SIBLING_VA + 5 + struct.unpack_from("<i", call_bytes, 1)[0]
    sibling_call_match = call_bytes[0] == 0xE8 and call_tgt == SIBLING

    error_strings = []
    for name, va, expected in ERROR_STRINGS:
        raw = read_va(data, segs, va, len(expected))
        error_strings.append(
            {
                "name": name,
                "va": hex(va),
                "len": len(expected),
                "bytes_hex": raw.hex(),
                "expected_hex": expected.hex(),
                "text": expected.decode("ascii"),
                "match": raw == expected and len(raw) == len(expected),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    key_insns = []
    for va, hx, note in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        key_insns.append(
            {
                "va": hex(va),
                "bytes": raw.hex(),
                "expected": hx,
                "match": raw.hex() == hx,
                "note": note,
            }
        )

    early_cmp = read_va(data, segs, EARLY_CMP_VA, 7)
    early_rule = {
        "cmp_va": hex(EARLY_CMP_VA),
        "cmp_bytes": early_cmp.hex(),
        "cmp_immediate": EARLY_CMP_IMM,
        "err_tag": hex(EARLY_ERR_TAG),
        "err_tag_va": hex(EARLY_ERR_VA),
        "err_tag_bytes": read_va(data, segs, EARLY_ERR_VA, 6).hex(),
        "match": early_cmp == bytes.fromhex("80be3002000003")
        and read_va(data, segs, EARLY_ERR_VA, 6) == bytes.fromhex("6641c706e300"),
        "claimed": True,
        "reason": (
            "cmpb $0x3, 0x230(rsi) then movw $0xe3,(r14) early-rejects "
            "when the network/kind byte equals 3"
        ),
    }

    negatives = {
        "duplicate_string_exact": any(
            s["name"] == "duplicate" and s["match"] for s in error_strings
        ),
        "cannot_set_string_exact": any(
            s["name"] == "cannot_set_deployer" and s["match"] for s in error_strings
        ),
        "early_reject_imm_is_3": early_rule["match"],
        "err_tag_is_0xe0": True,
        "ok_tag_is_0x186": True,
        "early_err_tag_is_0xe3": True,
        "sibling_call_targets_0x394ce40": sibling_call_match,
    }

    result = {
        "abi": {
            "early_err_tag": hex(EARLY_ERR_TAG),
            "early_err_tag_va": hex(EARLY_ERR_VA),
            "err_tag": hex(ERR_TAG),
            "err_cannot_va": hex(ERR_CANNOT_VA),
            "err_dup_va": hex(ERR_DUP_VA),
            "ok_tag": hex(OK_TAG),
            "ok_tag_va": hex(OK_TAG_VA),
        },
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
        "claim": "sub_deployer_set_guard_rules_only",
        "component": "RE-033",
        "direct_calls": direct,
        "early_reject_rule": early_rule,
        "error_strings": error_strings,
        "extent": {
            "carve_note": (
                "FDE exclusive end 0x3718e27 is the first int3 after the "
                "function body; int3 pad then next function begins at "
                "push-r15 0x3718e30. Carve hosts the sub-deployer set "
                "guards; this packet claims the duplicate / cannot-set / "
                "early-reject rules only."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_r15": next_fn_bytes[:2] == b"\x41\x57",
            "next_fn_va": hex(next_fn_va),
        },
        "fallback_from": {
            "note": (
                "GATE on PRs #969/#413/#650: #969 MERGED "
                "2026-11-01T05:10:18Z claims the deployer "
                "trading-fee-share setter at 0x27512f0 (cap 0x186a0 / "
                "the three fee-share strings) — THIS rule, so RE-032 "
                "was dropped. This packet builds scout candidate #3 "
                "(sub-deployer set guards) instead. #413 MERGED "
                "2026-11-01T03:00:55Z is quote-token enable (different "
                "rule); #650 MERGED 2026-11-01T03:00:54Z is spot-meta "
                "inventory (different rule)."
            ),
            "dropped": "RE-032",
            "reason": "merged_pr_969_is_fee_share_setter_rule",
        },
        "got_addend_match": got_addend_match,
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "key_insns": key_insns,
        "key_insns_all_match": all(k["match"] for k in key_insns),
        "negatives": negatives,
        "sibling": {
            "call_site_va": hex(CALL_SIBLING_VA),
            "call_target": hex(call_tgt),
            "call_target_match": sibling_call_match,
            "carve_end": hex(SIBLING_END),
            "carve_len": SIBLING_LEN,
            "carve_sha256": sib_sha,
            "carve_sha256_expected": SIBLING_SHA256,
            "carve_sha256_match": sib_sha == SIBLING_SHA256,
            "carve_start": hex(SIBLING),
            "note": (
                "Optional sibling carve hosts the too-many-sub-deployers "
                "panic/Err path; called once from the primary. Pinned as "
                "related, not a primary claim of this packet."
            ),
            "string_name": "too_many",
            "string_va": "0x5a80b4",
        },
        "slot_ref_counts": counts,
        "slot_ref_counts_match": counts == SLOT_REFS_EXPECTED,
        "slot_refs": slot_ref_list,
    }
    return result


def expectation_errors(result: dict) -> list:
    errs = []
    if not result["carve"]["sha256_match"]:
        errs.append("carve sha256")
    if result["carve"]["len"] != CARVED_LEN:
        errs.append("carve len")
    if not result["got_addend_match"]:
        errs.append("got addend")
    if not result["slot_ref_counts_match"]:
        errs.append("slot ref counts")
    if result["direct_calls"] != 0:
        errs.append("direct calls")
    if not result["key_insns_all_match"]:
        errs.append("key_insns")
    for s in result["error_strings"]:
        if not s["match"]:
            errs.append("string " + s["name"])
    if not result["early_reject_rule"]["match"]:
        errs.append("early reject rule")
    if not result["sibling"]["carve_sha256_match"]:
        errs.append("sibling carve sha256")
    if not result["sibling"]["call_target_match"]:
        errs.append("sibling call target")
    for k, v in result["negatives"].items():
        if not v:
            errs.append("negative " + k)
    if result["abi"]["err_tag"] != hex(ERR_TAG):
        errs.append("err tag")
    if result["abi"]["ok_tag"] != hex(OK_TAG):
        errs.append("ok tag")
    if result["abi"]["early_err_tag"] != hex(EARLY_ERR_TAG):
        errs.append("early err tag")
    if [x["va"] for x in result["slot_refs"]] != [hex(v) for v in FF15_SITES]:
        errs.append("ff15 sites order")
    return errs


def render(result: dict) -> str:
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", type=Path, help="write JSON here")
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data)
    text = render(result)
    errors = expectation_errors(result)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    for e in errors:
        print("FAIL", e, file=sys.stderr)
    print(
        "sub_deployer_guards: key_insns=%d strings=%d ff15=%d errors=%d"
        % (
            len(result["key_insns"]),
            len(result["error_strings"]),
            result["slot_ref_counts"]["call"],
            len(errors),
        ),
        file=sys.stderr,
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
