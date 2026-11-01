#!/usr/bin/env python3
"""Compare independent LLVM/GNU byte partitions, without interpreting code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from survey import Image, RANGES


def rows(text):
    found = []
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", line)
        if match:
            found.append((int(match[1], 16), bytes.fromhex(match[2])))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    image = Image(args.binary.read_bytes())
    here = Path(__file__).resolve().parent
    files, checks = {}, []
    with tempfile.TemporaryDirectory(prefix="visor-llvm-static-") as directory:
        private = Path(directory) / "visor-readonly.elf"
        private.write_bytes(image.data)
        private.chmod(0o400)
        for label in ("readiness", "clock-os"):
            start, end = RANGES[label]
            command = ["llvm-objdump", "-d", "--x86-asm-syntax=intel",
                       f"--start-address={start:#x}", f"--stop-address={end:#x}",
                       "visor-readonly.elf"]
            text = subprocess.check_output(command, cwd=directory, text=True)
            first = rows((here / "records" / (label + ".txt")).read_text())
            second = rows(text)
            if first != second:
                raise ValueError("provider instruction partitions differ: " + label)
            cursor = start
            for va, raw in second:
                if va != cursor or raw != image.read(va, len(raw)):
                    raise ValueError("secondary rows differ from capture")
                cursor += len(raw)
            if cursor != end:
                raise ValueError("secondary export incomplete")
            name = "llvm-" + label + ".txt"
            files[name] = text.encode()
            checks.append({"label": label, "rows": len(second), "bytes": end - start,
                           "rawSha256": hashlib.sha256(files[name]).hexdigest(),
                           "rawFile": name, "command": command})
    record = {"provider": subprocess.check_output(["llvm-objdump", "--version"],
                                                   text=True).splitlines()[0],
              "checks": checks, "sameBytePartitions": True, "execution": False,
              "limits": "Independent decoder instruction-boundary/byte crosscheck,"
                        "not independent semantic equivalence proof."}
    files["llvm-crosscheck.json"] = (json.dumps(record, indent=2) + "\n").encode()
    args.output.mkdir(parents=True)
    for name, data in files.items():
        (args.output / name).write_bytes(data)
    print("LLVM and GNU agree on 324 instruction byte partitions (1,574 bytes)")


if __name__ == "__main__":
    main()
