#!/usr/bin/env python3
"""Static FDE/instruction-boundary cross-check. Never executes captured code."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecmul as packet
from fde_extents import eh_frame_records

ROW = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.+)$")


def rows(text):
    result = {}
    for line in text.splitlines():
        hit = ROW.match(line)
        if hit:
            result[int(hit[1], 16)] = (bytes.fromhex(hit[2]), hit[3])
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--objdump", required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    blob = packet.TARGET.read_bytes()
    if hashlib.sha256(blob).hexdigest() != packet.BINARY_SHA256:
        raise ValueError("node94 digest mismatch")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _, fdes = eh_frame_records(blob)
    by_start = {row["start"]: row for row in fdes}
    starts = sorted(by_start)
    segs = packet.segments(blob)
    relas = {a: (i, v) for a, i, v in packet.rela_dyn(blob)}
    version = subprocess.check_output([args.objdump, "--version"], text=True).splitlines()[0]
    if "GNU objdump" not in version:
        raise ValueError("this review recipe requires GNU objdump")
    report = {"target_sha256": packet.BINARY_SHA256, "provider": version,
              "captured_execution": False, "ranges": [], "pins": [], "errors": []}
    all_rows = {}

    def disassemble(start, end):
        output = subprocess.check_output([
            args.objdump, "-d", "-M", "intel", "--insn-width=16",
            f"--start-address={start}", f"--stop-address={end}",
            "artifacts/node/94/hl-node"], cwd=ROOT, text=True)
        (args.output_dir / f"native-{start:x}.txt").write_text(output)
        return rows(output)

    ranges = [(packet.FN, packet.FN_END, "run_mul"), *packet.CALLEES,
              (0x4F1F8E0, 0x4F1F9B1, "field add/reduce via GOT 0x5777658"),
              (0x4F20020, 0x4F200E3, "field subtract/reduce via GOT 0x5777668")]
    ranges += [(w, by_start[w]["end"], "gas wrapper") for w, *_ in packet.WRAPPERS]
    for start, end, label in ranges:
        fde = by_start.get(start)
        decoded = disassemble(start, end)
        all_rows.update(decoded)
        record = {"start": hex(start), "end": hex(end), "label": label,
                  "actual_fde": fde, "fde_matches": fde is not None and fde["end"] == end,
                  "sha256": hashlib.sha256(packet.read_va(blob, segs, start, end - start)).hexdigest(),
                  "native_instructions": len(decoded), "call_or_jump": [], "feature_mnemonics": []}
        cursor = start
        while cursor in decoded:
            cursor += len(decoded[cursor][0])
        record["contiguous_complete_decode"] = cursor == end
        if not record["fde_matches"] or not record["contiguous_complete_decode"]:
            report["errors"].append(f"range or decode mismatch at {start:#x}")
        for address, (raw, asm) in decoded.items():
            mnemonic = asm.split()[0]
            if mnemonic in ("cpuid", "xgetbv", "adcx", "adox", "mulx"):
                record["feature_mnemonics"].append([hex(address), asm])
            if mnemonic == "call" or mnemonic.startswith("j"):
                entry = {"address": hex(address), "bytes": raw.hex(), "asm": asm}
                direct = re.match(r"\S+\s+([0-9a-f]+)\b", asm)
                if direct:
                    target = int(direct[1], 16)
                    entry["direct_target"] = hex(target)
                    if mnemonic.startswith("j") and start <= target < end and target not in decoded:
                        report["errors"].append(f"branch into an instruction at {address:#x}")
                if "[rip" in asm:
                    slot = int(re.search(r"#\s*([0-9a-f]+)", asm)[1], 16)
                    entry["slot"] = hex(slot)
                    entry["relocation"] = list(relas.get(slot, ()))
                record["call_or_jump"].append(entry)
        report["ranges"].append(record)
    for address, hx, label in packet.KEY_INSNS:
        raw = packet.read_va(blob, segs, address, len(hx) // 2)
        record = {"address": hex(address), "bytes": hx, "label": label,
                  "bytes_match": raw.hex() == hx}
        if address == packet.PAD[0]:
            record["kind"] = "explicit outside-FDE padding"
        else:
            if address not in all_rows:
                fde = by_start[starts[bisect.bisect_right(starts, address) - 1]]
                all_rows.update(disassemble(fde["start"], min(fde["end"], address + 32)))
            cursor = address
            while cursor < address + len(raw) and cursor in all_rows:
                cursor += len(all_rows[cursor][0])
            record["native_start"] = address in all_rows
            record["complete_instructions"] = cursor == address + len(raw)
            if not record["native_start"] or not record["complete_instructions"]:
                report["errors"].append(f"pin boundary mismatch at {address:#x}")
        if not record["bytes_match"]:
            report["errors"].append(f"pin bytes mismatch at {address:#x}")
        report["pins"].append(record)
    report["closure_slots"] = {hex(slot): list(relas[slot]) for slot in
                               (0x5776EF8, 0x5777640, 0x5777658, 0x5777668)}
    (args.output_dir / "native-review.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"FDEs={len(ranges)} pins={len(report['pins'])} errors={len(report['errors'])}")
    return bool(report["errors"])


if __name__ == "__main__":
    raise SystemExit(main())
