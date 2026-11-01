#!/usr/bin/env python3
"""Bind the Visor readiness deadline to one captured image; never execute it.

Only GNU readelf/objdump parse a private, non-executable copy of the admitted
snapshot. No instruction interpreter, emulator, network or captured process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

SHA256 = "89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"
SIZE = 8_305_392
RANGES = {
    "readiness": (0x5B41B0, 0x5B470D),
    "clock-calendar": (0x444600, 0x444705),
    "clock-os": (0x66EB20, 0x66EBE9),
    "epoch-difference": (0x66EA50, 0x66EB16),
    "duration-conversion": (0x330360, 0x330581),
    "time-addition": (0x445830, 0x445992),
    "date-addition": (0x444040, 0x44426C),
}
SLOTS = {
    0x7E5388: 0x444600,
    0x7E53C8: 0x330360,
    0x7E5390: 0x445830,
    0x7E5398: 0x444040,
}
CONTROLS = {
    "clock-argument-zero-and-call": (0x44460D, "31ffe80ca52200"),
    "clock-import-call": (0x66EB2D, "ff1545911700"),
    "clock-nanosecond-admission": (0x66EB38, "488b55e84881fa00ca9a3b730b"),
    "sixty-load": (0x5B437F, "f20f1005c1a3abff"),
    "signed-first-field": (0x5B4475, "8b1424413b170f9fc27431"),
    "unsigned-second-field": (0x5B44B1, "8b09394c24040f97c20f85e8000000"),
    "strict-unsigned-last-field": (0x5B44C0, "8b00394424080f87e4000000"),
    "fallback-first-field": (0x5B448D, "4c8d3d5083acff"),
    "false-return": (0x5B45A4, "31dbeb3e"),
    "common-return": (0x5B45E6, "89d84881c4c8000000"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data: bytes):
        # Authentication precedes all ELF offsets and native subprocesses.
        if len(data) != SIZE or digest(data) != SHA256:
            raise ValueError("Visor size/digest differs from the pinned capture")
        self.data = data
        phoff = struct.unpack_from("<Q", data, 32)[0]
        stride, count = struct.unpack_from("<HH", data, 54)
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * stride)
                      for i in range(count)]
        shoff = struct.unpack_from("<Q", data, 40)[0]
        stride, count = struct.unpack_from("<HH", data, 58)
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * stride)
                         for i in range(count)]

    def offset(self, va: int, size: int) -> int:
        found = [p[2] + va - p[3] for p in self.loads
                 if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[5]]
        if len(found) != 1:
            raise ValueError(f"ambiguous/unmapped file-backed range {va:#x}+{size}")
        return found[0]

    def read(self, va: int, size: int) -> bytes:
        offset = self.offset(va, size)
        return self.data[offset:offset + size]

    def relocations(self) -> dict[int, tuple[int, int, str]]:
        rows = {}
        for sec in self.sections:
            if sec[1] != 4:
                continue
            symbols = self.sections[sec[6]]
            strings = self.sections[symbols[6]]
            names = self.data[strings[4]:strings[4] + strings[5]]
            for at in range(sec[4], sec[4] + sec[5], sec[9]):
                slot, info, addend = struct.unpack_from("<QQq", self.data, at)
                index = info >> 32
                name = ""
                if index:
                    noff = struct.unpack_from("<I", self.data,
                                              symbols[4] + index * symbols[9])[0]
                    name = names[noff:names.index(0, noff)].decode("ascii")
                if slot in rows:
                    raise ValueError(f"duplicate relocation {slot:#x}")
                rows[slot] = (info & 0xFFFFFFFF, addend, name)
        return rows


def instruction_rows(text: str, image: Image, start: int, end: int) -> int:
    cursor, count = start, 0
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.+)$", line)
        if not match:
            continue
        va, raw = int(match[1], 16), bytes.fromhex(match[2])
        if va != cursor or not raw or va + len(raw) > end:
            raise ValueError("native rows do not exactly partition the FDE")
        if raw != image.read(va, len(raw)):
            raise ValueError("native instruction bytes differ from snapshot")
        cursor += len(raw)
        count += 1
    if cursor != end:
        raise ValueError("native instruction export is incomplete")
    return count


def survey(binary: Path) -> dict[str, bytes]:
    image = Image(binary.read_bytes())
    rel = image.relocations()
    for slot, target in SLOTS.items():
        if rel.get(slot) != (8, target, ""):
            raise ValueError(f"helper relocation differs at {slot:#x}")
    if rel.get(0x7E7C78) != (6, 0, "clock_gettime"):
        raise ValueError("clock import differs")
    for label, (va, raw) in CONTROLS.items():
        if image.read(va, len(bytes.fromhex(raw))).hex() != raw:
            raise ValueError(f"instruction control differs: {label}")
    if image.read(0x6E748, 8).hex() != "0000000000004e40":
        raise ValueError("duration constant differs")
    if image.read(0x7C7E4, 12).hex() != "ded6ff7f7f510100ffc99a3b":
        raise ValueError("fallback triple differs")
    versions = {}
    for tool in ("objdump", "readelf"):
        versions[tool] = subprocess.check_output([tool, "--version"], text=True).splitlines()[0]
        if "GNU" not in versions[tool]:
            raise ValueError(f"GNU {tool} required")
    output = {}
    records = {}
    with tempfile.TemporaryDirectory(prefix="visor-readiness-static-") as directory:
        private = Path(directory) / "visor.elf"
        private.write_bytes(image.data)
        private.chmod(0o400)
        frames = subprocess.check_output(["readelf", "--debug-dump=frames", "visor.elf"],
                                         cwd=directory, text=True)
        extents = [(int(m[1], 16), int(m[2], 16))
                   for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames)]
        for label, (start, end) in RANGES.items():
            if extents.count((start, end)) != 1:
                raise ValueError(f"expected exact unique FDE absent: {label}")
            command = ["objdump", "-d", "-w", "--insn-width=16",
                       f"--start-address={start:#x}", f"--stop-address={end:#x}", "visor.elf"]
            text = subprocess.check_output(command, cwd=directory, text=True)
            count = instruction_rows(text, image, start, end)
            name = f"{label}.txt"
            output[name] = text.encode("utf-8")
            records[label] = {"startVA": hex(start), "endVA": hex(end),
                              "fileOffset": hex(image.offset(start, end - start)),
                              "bytes": end - start, "sha256": digest(image.read(start, end - start)),
                              "nativeInstructionRows": count, "command": command,
                              "rawExport": name, "rawExportSha256": digest(output[name])}
        if private.read_bytes() != image.data:
            raise ValueError("private analysis snapshot changed")
    record = {"schema": 1, "targetSha256": SHA256, "targetBytes": SIZE,
              "addressCoordinates": "ELF virtual addresses; file-backed PT_LOAD offsets",
              "versions": versions, "ranges": records,
              "helperSlots": {hex(k): hex(v) for k, v in SLOTS.items()},
              "clockImport": {"slotVA": "0x7e7c78", "symbol": "clock_gettime", "type": 6},
              "durationData": {"va": "0x6e748", "bytes": "0000000000004e40", "binary64": 60.0},
              "fallbackData": {"va": "0x7c7e4", "bytes": "ded6ff7f7f510100ffc99a3b"},
              "controls": {k: {"va": hex(v[0]), "bytes": v[1]} for k, v in CONTROLS.items()},
              "capturedExecution": False, "emulation": False, "progressGateRequested": False}
    output["record.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve prior evidence")
    files = survey(args.binary)
    args.output.mkdir(parents=True)
    for name, data in files.items():
        (args.output / name).write_bytes(data)
    print(f"Bound {len(RANGES)} FDE extents; captured code not executed")


if __name__ == "__main__":
    main()
