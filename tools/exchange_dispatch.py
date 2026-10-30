#!/usr/bin/env python3
"""RE-010: map the node #94 execute-action jump table to FDE-bounded callees.

Stdlib only. Reads the ELF, decodes the jump table of the dispatcher that the
can1357 reconstruction places at 0x2759240, finds the rel32 direct calls (and
RIP-relative indirect calls through RELATIVE-relocated slots) inside each
case arm, and compares them with the HandlerRef addresses written in
references/can1357-hl/l1/exchange/impl_execute_action.rs.

Addresses are virtual addresses of instruction starts (REX prefix included).
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DISPATCHER = 0x2759240
# mov rax,[r12]; lea rcx,[rax-0x74]; cmp rax,0x74; mov eax,0x14; cmovae rax,rcx
BIAS_BYTES = bytes.fromhex("498b0424" "488d488c" "4883f874" "b814000000" "480f43c1")
BIAS_AT = 0x2759298
# lea rcx,[rip+rel32]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax
LEA_AT = 0x27592AD
TAIL_BYTES = bytes.fromhex("48630481" "4801c8" "ffe0")
TAG_BASE = 0x74
DEFAULT_INDEX = 0x14
R_X86_64_RELATIVE = 8
RS_PATH = "references/can1357-hl/l1/exchange/impl_execute_action.rs"
HANDLER_RE = re.compile(
    r'HandlerRef::new\(\s*(\d+),\s*"([^"]*)",\s*"([^"]*)",\s*0x([0-9A-Fa-f_]+),\s*"([^"]*)"'
)


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise EvidenceError("not an ELF64 little-endian file")
        self.data = data
        phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
        self.loads = []
        for i in range(phnum):
            p_type, _f, p_off, p_va, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((p_va, p_off, p_filesz))
        raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        stro = raw[shstrndx][4]
        self.sections = {}
        for s in raw:
            end = data.index(b"\0", stro + s[0])
            self.sections[data[stro + s[0]:end].decode()] = (s[3], s[4], s[5])

    def off(self, va: int) -> int:
        for v, o, n in self.loads:
            if v <= va < v + n:
                return o + va - v
        raise EvidenceError(f"unmapped va {va:#x}")

    def read(self, va: int, n: int) -> bytes:
        o = self.off(va)
        return self.data[o:o + n]


def fde_index(elf: Elf):
    va, off, size = elf.sections[".eh_frame_hdr"]
    d = elf.data
    if d[off] != 1 or tuple(d[off + 1:off + 4]) != (0x1B, 0x03, 0x3B):
        raise EvidenceError("unexpected .eh_frame_hdr encodings")
    count = struct.unpack_from("<I", d, off + 8)[0]
    starts, ends = [], []
    prev = None
    for i in range(count):
        pc_rel, fde_rel = struct.unpack_from("<ii", d, off + 12 + 8 * i)
        start, fde_va = va + pc_rel, va + fde_rel
        fo = elf.off(fde_va)
        pc_begin = fde_va + 8 + struct.unpack_from("<i", d, fo + 8)[0]
        pc_range = struct.unpack_from("<I", d, fo + 12)[0]
        if pc_begin != start:
            raise EvidenceError(f"FDE pc_begin mismatch at {start:#x}")
        if prev is not None and start <= prev:
            raise EvidenceError(".eh_frame_hdr table not strictly sorted")
        prev = start
        starts.append(start)
        ends.append(start + pc_range)
    return starts, ends


def relative_relocs(elf: Elf) -> dict:
    _va, off, size = elf.sections[".rela.dyn"]
    out = {}
    for i in range(0, size, 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", elf.data, off + i)
        if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            out[r_off] = r_add
    return out


def containing(starts, ends, va):
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and va < ends[i]:
        return starts[i], ends[i]
    return None


def parse_reconstruction(text: str):
    rows = {}
    for m in HANDLER_RE.finditer(text):
        case = int(m.group(1))
        if case in rows:
            raise EvidenceError(f"duplicate HandlerRef case {case}")
        rows[case] = {
            "case": case,
            "wire_type": m.group(2),
            "rust_variant": m.group(3),
            "claimed_ea": int(m.group(4).replace("_", ""), 16),
            "claimed_symbol": m.group(5),
        }
    return rows


def arm_calls(elf, lo, hi, starts, ends, relocs):
    """Direct E8 calls to FDE starts and FF 15 calls through RELATIVE slots."""
    code = elf.read(lo, hi - lo)
    calls = []
    for i in range(len(code) - 4):
        va = lo + i
        if code[i] == 0xE8 and i + 5 <= len(code):
            tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
            if containing(starts, ends, tgt) and starts[bisect.bisect_left(starts, tgt)] == tgt:
                calls.append({"site": va, "kind": "rel32", "target": tgt})
        elif code[i] == 0xFF and code[i + 1] == 0x15 and i + 6 <= len(code):
            slot = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
            if slot in relocs:
                tgt = relocs[slot]
                calls.append({"site": va, "kind": "rip_slot", "slot": slot, "target": tgt})
    return calls


def entry_branches(elf, lo, first_call_site, flo, fhi):
    """jcc rel32 (0F 80..8F) between the arm entry and its first call, into the dispatcher."""
    end = first_call_site if first_call_site is not None else None
    out = []
    if end is None:
        return out
    code = elf.read(lo, end - lo)
    for i in range(len(code) - 5):
        if code[i] == 0x0F and 0x80 <= code[i + 1] <= 0x8F:
            tgt = lo + i + 6 + struct.unpack_from("<i", code, i + 2)[0]
            if flo <= tgt < fhi:
                out.append({"site": lo + i, "target": tgt})
    return out


def is_fde_start(starts, va):
    j = bisect.bisect_left(starts, va)
    return j < len(starts) and starts[j] == va


def classify(claim, calls, branch_calls, starts, ends):
    ea = claim["claimed_ea"]
    targets = [c["target"] for c in calls]
    if not targets and branch_calls and branch_calls[0]["target"] == ea:
        return "real_first_call_on_branch"
    if ea == DISPATCHER:
        return "inline_claim_no_call" if not calls else "inline_claim_but_arm_calls"
    if not is_fde_start(starts, ea):
        return "claimed_not_fde_start"
    if targets and targets[0] == ea:
        return "real_first_call"
    if ea in targets:
        return "real_called_not_first"
    return "fde_start_not_called_from_arm"


HEX_RE = re.compile(r"0x([0-9A-Fa-f_]{6,9})\b")
TEXT_LO, TEXT_HI = 0x1343C80, 0x1343C80 + 0x431C430


def survey_addresses(src_dir: Path, starts, ends):
    """Classify every .text-range hex literal in the reconstruction's exchange tree."""
    rows = []
    for path in sorted(src_dir.rglob("*.rs")):
        seen = set()
        for m in HEX_RE.finditer(path.read_text(encoding="utf-8")):
            va = int(m.group(1).replace("_", ""), 16)
            if not TEXT_LO <= va < TEXT_HI or va in seen:
                continue
            seen.add(va)
            cf = containing(starts, ends, va)
            if cf is None:
                kind = "no_fde"
            elif cf[0] == va:
                kind = "at_fde_start"
            else:
                kind = "inside_fde"
            rows.append({
                "file": path.relative_to(src_dir).as_posix(),
                "va": va,
                "kind": kind,
                "fde_start": cf[0] if cf else None,
                "fde_end": cf[1] if cf else None,
            })
    rows.sort(key=lambda r: (r["file"], r["va"]))
    return rows


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"
SOURCE = ROOT / RS_PATH


class EvidenceError(ValueError):
    pass


def build(data: bytes, rs: Path = SOURCE, expected_sha256: str = EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"unexpected binary sha256 {sha}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)
    fn = containing(starts, ends, DISPATCHER)
    if fn is None or fn[0] != DISPATCHER:
        raise EvidenceError("dispatcher is not an FDE start")
    lo, hi = fn
    if elf.read(BIAS_AT, len(BIAS_BYTES)) != BIAS_BYTES:
        raise EvidenceError("tag-bias idiom not found")
    lea = elf.read(LEA_AT, 7)
    if lea[:3] != b"\x48\x8d\x0d" or elf.read(LEA_AT + 7, len(TAIL_BYTES)) != TAIL_BYTES:
        raise EvidenceError("jump-table idiom not found")
    table = LEA_AT + 7 + struct.unpack_from("<i", lea, 3)[0]
    targets = []
    while True:
        rel = struct.unpack_from("<i", elf.read(table + 4 * len(targets), 4))[0]
        tgt = table + rel
        if not lo <= tgt < hi:
            break
        targets.append(tgt)
    if len(set(targets)) != len(targets):
        raise EvidenceError("duplicate jump-table targets")
    order = sorted(targets)
    claims = parse_reconstruction(rs.read_text(encoding="utf-8"))
    cases = []
    for idx, tgt in enumerate(targets):
        k = order.index(tgt)
        rend = order[k + 1] if k + 1 < len(order) else hi
        calls = arm_calls(elf, tgt, rend, starts, ends, relocs)
        branch_calls = []
        branches = []
        if not calls:
            branches = entry_branches(elf, tgt, rend, lo, hi)
            for br in branches:
                bk = bisect.bisect_right(order, br["target"])
                bend = order[bk] if bk < len(order) else hi
                br["calls"] = arm_calls(elf, br["target"], bend, starts, ends, relocs)
                branch_calls.extend(br["calls"])
        row = {
            "index": idx,
            "discriminant": TAG_BASE + idx,
            "arm": tgt,
            "arm_region_end": rend,
            "entry_branches": branches,
            "calls": [dict(c, target_fde_end=ends[bisect.bisect_left(starts, c["target"])]
                           if is_fde_start(starts, c["target"]) else None) for c in calls],
        }
        claim = claims.get(idx)
        if claim:
            ea = claim["claimed_ea"]
            cf = containing(starts, ends, ea)
            row["reconstruction"] = dict(
                claim,
                claimed_is_fde_start=is_fde_start(starts, ea),
                claimed_containing_fde=list(cf) if cf else None,
                status=classify(claim, calls, branch_calls, starts, ends),
            )
        cases.append(row)
    extra = sorted(set(claims) - set(range(len(targets))))
    if extra:
        raise EvidenceError(f"claims beyond table: {extra}")
    status_counts = {}
    for row in cases:
        if "reconstruction" in row:
            s = row["reconstruction"]["status"]
            status_counts[s] = status_counts.get(s, 0) + 1
    survey = survey_addresses(rs.parent, starts, ends)
    survey_counts = {}
    for r in survey:
        survey_counts[r["kind"]] = survey_counts.get(r["kind"], 0) + 1
    return {
        "address_survey": survey,
        "address_survey_counts": dict(sorted(survey_counts.items())),
        "binary_sha256": sha,
        "dispatcher": {"start": lo, "end": hi},
        "tag_base": TAG_BASE,
        "below_base_index": DEFAULT_INDEX,
        "jump_table": table,
        "table_entries": len(targets),
        "reconstruction_claims": len(claims),
        "status_counts": dict(sorted(status_counts.items())),
        "fde_count": len(starts),
        "cases": cases,
    }


ADDR_KEYS = {"start", "end", "jump_table", "arm", "arm_region_end", "site", "slot",
             "target", "target_fde_end", "fde_start", "fde_end", "claimed_ea", "claimed_containing_fde", "va"}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS) for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), sort_keys=True, indent=1) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default=str(TARGET))
    ap.add_argument("--source", default=str(SOURCE))
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    out = render(build(Path(a.binary).read_bytes(), Path(a.source)))
    if a.out:
        Path(a.out).write_bytes(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
