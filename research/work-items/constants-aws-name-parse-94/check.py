#!/usr/bin/env python3
"""Re-check one node #94 static question about the aws-name parse cluster.

The question, left by research/work-items/constants, is whether the routine
entered at 0x164d630 rejects a backslash the way a quoted-string reader that
returns no value would, whether a value object has the externally tagged
shape of one string, a colon, the bytes n u l l, and a closing brace, and
where a failed parse's 0x20 fallback separates from a parsed name whose
discriminant is 32.

This reads the pinned ELF and its unwind records. It does not execute the
captured binary, decode a function census, or treat an FDE extent as a
function boundary.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts/node/94/hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 91774280
MASK = 0x100002600
MASK_BITS = (9, 10, 13, 32)

# Anchors already published by the constants packet.
CALLER_CALL = 0x164FCA8
ENTRY = 0x164D630

FDES = (
    (0x164D630, 0x164D73E),
    (0x164D740, 0x164D7F8),
    (0x164E930, 0x164F6AF),
    (0x164B3D0, 0x164B97A),
    (0x164BAD0, 0x164C554),
    (0x164B980, 0x164BAA3),
    (0x164E6D0, 0x164E7F3),
    (0x164E800, 0x164E92A),
    (0x164FB80, 0x164FE99),
    (0x4EBF970, 0x4EBFC06),
    (0x4EBEF70, 0x4EBF346),
    (0x4EBF4E0, 0x4EBF5B0),
    (0x4EBF5B0, 0x4EBF660),
)

# Quoted-string class table: every byte 0x00..0x1f, plus quote and backslash.
CLASS_SPECIAL = tuple(range(0x20)) + (0x22, 0x5C)
# Simple escapes that store one byte and return 0. "\\u" is a separate entry.
SIMPLE_ESCAPES = {
    0x22: 0x22,
    0x2F: 0x2F,
    0x5C: 0x5C,
    0x62: 0x08,
    0x66: 0x0C,
    0x6E: 0x0A,
    0x72: 0x0D,
    0x74: 0x09,
}


class Fail(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Fail(message)


def load():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == SIZE, f"size {len(data)} != {SIZE}")
    require(digest == SHA256, f"sha256 {digest} != {SHA256}")
    return data


def section_map(data):
    rows = sections(data)
    named = {}
    for row in rows:
        named.setdefault(row["name"], row)
    return rows, named


def read_va(data, rows, va, size):
    hits = [row for row in rows if row["type"] != 8 and row["address"] <= va < row["address"] + row["size"]]
    require(len(hits) == 1, f"VA {va:#x} maps to {len(hits)} sections")
    row = hits[0]
    off = row["offset"] + (va - row["address"])
    require(off + size <= row["offset"] + row["size"], f"read {va:#x}+{size} leaves {row['name']}")
    return data[off:off + size], row["name"]


def u32(buf, off=0):
    return struct.unpack_from("<I", buf, off)[0]


def i32(buf, off=0):
    return struct.unpack_from("<i", buf, off)[0]


def rel32_target(site, data, rows):
    raw, _ = read_va(data, rows, site, 5)
    require(raw[0] == 0xE8, f"{site:#x} is not a direct call: {raw.hex()}")
    return site + 5 + i32(raw, 1)


def rip_disp32(site, data, rows, opcode):
    raw, _ = read_va(data, rows, site, len(opcode) + 4)
    require(raw.startswith(opcode), f"{site:#x} opcode {raw.hex()} != {opcode.hex()}")
    disp = i32(raw, len(opcode))
    return site + len(opcode) + 4 + disp


def fde_at(fdes, start):
    hits = [row for row in fdes if row["start"] == start]
    require(len(hits) == 1, f"FDE start {start:#x} count {len(hits)}")
    return hits[0]


def movabs_sites(data, rows, start, end):
    blob, _ = read_va(data, rows, start, end - start)
    found = []
    # REX.W movabs r64, imm64. The register encoding varies; the immediate does not.
    for index in range(len(blob) - 10):
        if blob[index] in (0x48, 0x49) and 0xB8 <= blob[index + 1] <= 0xBF:
            imm = struct.unpack_from("<Q", blob, index + 2)[0]
            if imm == MASK:
                found.append(start + index)
    return found


def jump_table(data, rows, base, count):
    raw, name = read_va(data, rows, base, count * 4)
    require(name == ".rodata", f"jump table {base:#x} is in {name}")
    return [base + i32(raw, index * 4) for index in range(count)]


def measure(data):
    rows, named = section_map(data)
    _, fdes = eh_frame_records(data, rows)
    measured = []
    for start, end in FDES:
        row = fde_at(fdes, start)
        require(row["end"] == end, f"FDE {start:#x} ends {row['end']:#x}, expected {end:#x}")
        measured.append({"start": f"{start:#x}", "end": f"{end:#x}", "size": end - start})

    caller = rel32_target(CALLER_CALL, data, rows)
    require(caller == ENTRY, f"call at {CALLER_CALL:#x} targets {caller:#x}")
    walker = rel32_target(0x164D677, data, rows)
    require(walker == 0x164E930, f"entry calls {walker:#x}")
    depth, _ = read_va(data, rows, 0x164D66D, 5)
    require(depth == b"\xc6\x44\x24\x50\x80", f"depth seed {depth.hex()}")
    # A zero tag falls into the trailing scan. A non-whitespace byte stores
    # code 0x16, calls 0x164d740, and rewrites the tag to 1.
    trail, _ = read_va(data, rows, 0x164D67C, 5)
    require(trail == b"\x80\x3b\x00\x75\x59", f"trailing tag test {trail.hex()}")
    trail_err, _ = read_va(data, rows, 0x164D6FA, 12)
    require(trail_err[:8] == b"\x48\xc7\x44\x24\x58\x16\x00\x00", f"trailing code {trail_err.hex()}")
    trail_tag, _ = read_va(data, rows, 0x164D716, 2)
    require(trail_tag == b"\xb0\x01", f"trailing tag {trail_tag.hex()}")
    # cmp $0x20; ja; bt; jae. A byte above 0x20, or a clear mask bit, is not skipped.
    skip, _ = read_va(data, rows, 0x164D6B5, 12)
    require(skip == b"\x48\x83\xff\x20\x77\x3f\x48\x0f\xa3\xfe\x73\x39",
            f"wrapper whitespace decision {skip.hex()}")

    mask_sites = {start: movabs_sites(data, rows, start, end) for start, end in FDES[:8]}
    require(mask_sites[ENTRY] == [0x164D69B], f"wrapper mask sites {mask_sites[ENTRY]}")
    require(all(mask_sites[start] for start in (0x164E930, 0x164B3D0, 0x164E6D0, 0x164E800)),
            f"missing mask {mask_sites}")

    key_target = rip_disp32(0x164EAF3, data, rows, b"\x48\x3b\x05")
    require(key_target == 0x20A458, f"key compare target {key_target:#x}")
    key_bytes, _ = read_va(data, rows, 0x20A458, 8)
    require(key_bytes == b"aws_name", f"key bytes {key_bytes!r}")
    seed, _ = read_va(data, rows, 0x164E9F2, 5)
    require(seed == b"\xc6\x44\x24\x0f\x4c", f"unset seed store {seed.hex()}")
    brace, _ = read_va(data, rows, 0x164E9B7, 9)
    require(brace == b"\x83\xff\x7b\x0f\x85\xcb\x0a\x00\x00", f"object test {brace.hex()}")
    before, _ = read_va(data, rows, 0x164EAE7, 7)
    require(before == b"\x48\x83\x7c\x24\x20\x08\x75", f"length-8 test {before.hex()}")

    name, _ = read_va(data, rows, 0x2180FF, 9)
    require(name == b"NvTestnet", f"name bytes {name!r}")

    arms = jump_table(data, rows, 0x264A88, 76)
    require(len(set(arms)) == 76, "quote-path table arms are not unique")
    for index, arm in enumerate(arms):
        raw, _ = read_va(data, rows, arm, 7)
        require(raw[:4] == b"\xc6\x43\x01" + bytes([index]), f"arm {index} {raw.hex()} at {arm:#x}")
        require(raw[4:6] == b"\x31\xc0", f"arm {index} does not clear eax")
        require(0x164B3D0 <= arm < 0x164B97A, f"arm {index} leaves the value FDE")
    require(arms[32] == 0x164B820, f"index 32 arm is {arms[32]:#x}")
    # The value parser's first skip compares with '"' (0x22), not 0x20.
    # '{' , ':', and '}' are the tagged-form delimiters around the null checker.
    quote_bound, _ = read_va(data, rows, 0x164B403, 6)
    require(quote_bound == b"\x48\x83\xff\x22\x77\x6b", f"value bound {quote_bound.hex()}")
    open_brace, _ = read_va(data, rows, 0x164B474, 3)
    require(open_brace == b"\x83\xff\x7b", f"value brace {open_brace.hex()}")
    colon, _ = read_va(data, rows, 0x164B513, 4)
    require(colon == b"\x48\x83\xfe\x3a", f"colon {colon.hex()}")
    close_brace, _ = read_va(data, rows, 0x164B5B8, 9)
    require(close_brace == b"\x83\xfe\x7d\x0f\x85\x78\x03\x00\x00", f"close brace {close_brace.hex()}")
    tagged_store, _ = read_va(data, rows, 0x164B54A, 7)
    require(tagged_store == b"\x40\x88\x6b\x01\xc6\x03\x00", f"tagged store {tagged_store.hex()}")
    tagged_return, _ = read_va(data, rows, 0x164B5CE, 6)
    require(tagged_return == b"\x40\x88\x6b\x01\x31\xc0", f"tagged return {tagged_return.hex()}")
    status_cmp, _ = read_va(data, rows, 0x164E776, 4)
    require(status_cmp == b"\x83\x3c\x24\x02", f"string status compare {status_cmp.hex()}")
    escape_rax, _ = read_va(data, rows, 0x4EBFA49, 4)
    require(escape_rax == b"\x48\x85\xc0\x0f", f"escape result test {escape_rax.hex()}")

    lengths = jump_table(data, rows, 0x264BB8, 12)
    require(lengths[7] == 0x164BF97, f"length 9 dispatches to {lengths[7]:#x}")
    nv, _ = read_va(data, rows, 0x164BFD4, 30)
    require(nv[:10] == b"\x48\xb9" + b"NvTestne", f"NvTestnet immediate {nv[:10]!r}")
    require(nv[10:13] == b"\x48\x33\x0e", f"xor mem {nv[10:13].hex()}")
    require(nv[13:17] == b"\x0f\xb6\x7e\x08", f"ninth byte {nv[13:17].hex()}")
    require(nv[17:21] == b"\x48\x83\xf7\x74", f"xor 't' {nv[17:21].hex()}")
    require(nv[21:24] == b"\x48\x09\xcf", f"or {nv[21:24].hex()}")
    require(nv[24] == 0x0F and nv[25] == 0x84, f"je missing {nv[24:26].hex()}")
    je_at = 0x164BFD4 + 24
    store = je_at + 6 + i32(nv, 26)
    require(store == 0x164C3A4, f"NvTestnet je targets {store:#x}")
    stored, _ = read_va(data, rows, store, 6)
    require(stored == b"\xc6\x40\x01\x20\x31\xc9", f"discriminant store {stored.hex()}")

    slot = rip_disp32(0x164E770, data, rows, b"\xff\x15")
    # The instruction is call *disp32(%rip). Confirm the slot, then the reloc.
    require(slot == 0x576ECA0, f"string GOT slot {slot:#x}")
    rela = named[".rela.dyn"]
    rela_bytes = data[rela["offset"]:rela["offset"] + rela["size"]]
    addends = {}
    for index in range(0, len(rela_bytes), 24):
        offset, info, addend = struct.unpack_from("<QQq", rela_bytes, index)
        if offset in (0x576ECA0, 0x57770A8) and (info & 0xFFFFFFFF) == 8:
            addends[offset] = addend
    require(addends.get(0x576ECA0) == 0x4EBF970, f"string addend {addends}")
    require(addends.get(0x57770A8) == 0x7CAAC8, f"class-table addend {addends}")
    table, table_name = read_va(data, rows, 0x7CAAC8, 256)
    require(table_name == ".rodata", table_name)
    special = tuple(index for index, byte in enumerate(table) if byte)
    require(special == CLASS_SPECIAL, f"class special {special}")
    require(all(byte == 1 for byte in table if byte), "class flags are not 1")

    backslash, _ = read_va(data, rows, 0x4EBF9F4, 16)
    require(backslash[:3] == b"\x83\xf9\x5c", f"backslash cmp {backslash[:3].hex()}")
    flagged, _ = read_va(data, rows, 0x4EBF9C5, 7)
    require(flagged == b"\x80\x7c\x0d\x00\x00\x75\x24", f"class flag branch {flagged.hex()}")
    quote_end, _ = read_va(data, rows, 0x4EBFAD9, 3)
    require(quote_end == b"\x83\xf9\x22", f"closing quote {quote_end.hex()}")
    quoted_ok, _ = read_va(data, rows, 0x4EBFB29, 7)
    require(quoted_ok == b"\x48\xc7\x03\x01\x00\x00\x00", f"quoted status {quoted_ok.hex()}")
    special_err, _ = read_va(data, rows, 0x4EBFB45, 9)
    require(special_err == b"\x48\xc7\x44\x24\x10\x10\x00\x00\x00", f"special code {special_err.hex()}")
    eof_err, _ = read_va(data, rows, 0x4EBFAAE, 9)
    require(eof_err == b"\x48\xc7\x44\x24\x10\x04\x00\x00\x00", f"eof code {eof_err.hex()}")
    escape_call = rel32_target(0x4EBFA44, data, rows)
    require(escape_call == 0x4EBEF70, f"escape callee {escape_call:#x}")
    status, _ = read_va(data, rows, 0x4EBFB5B, 7)
    require(status == b"\x48\xc7\x03\x02\x00\x00\x00", f"status 2 {status.hex()}")
    writer, _ = read_va(data, rows, 0x4EBF51A, 7)
    require(writer == b"\x49\xc7\x06\x02\x00\x00\x00", f"writer status {writer.hex()}")

    escape_base = 0x7CA728
    escape_arms = jump_table(data, rows, escape_base, 0x54)
    decoded = {}
    reject = 0
    for index, arm in enumerate(escape_arms):
        byte = index + 0x22
        if byte in SIMPLE_ESCAPES:
            window, _ = read_va(data, rows, arm, 32)
            marker = b"\x42\xc6\x04\x30" + bytes([SIMPLE_ESCAPES[byte]])
            require(marker in window, f"escape {byte:#x} store missing in {window.hex()}")
            decoded[f"{byte:#x}"] = f"{SIMPLE_ESCAPES[byte]:#x}"
        elif byte == 0x75:
            require(arm == 0x4EBF103, f"\\\\u entry {arm:#x}")
        else:
            require(arm == 0x4EBF149, f"escape {byte:#x} targets {arm:#x}")
            reject += 1
    require(reject == 0x54 - len(SIMPLE_ESCAPES) - 1, reject)
    epilogue, _ = read_va(data, rows, 0x4EBF0F2, 2)
    require(epilogue == b"\x31\xc0", f"success epilogue {epilogue.hex()}")
    err, _ = read_va(data, rows, 0x4EBF149, 8)
    require(err == b"\x48\xc7\x04\x24\x0c\x00\x00\x00", f"escape error {err.hex()}")

    null_checks = (
        (0x164E86D, b"\x41\x83\xf9\x6e"),  # 'n'
        (0x164E897, b"\x40\x80\xfe\x75"),  # 'u'
        (0x164E8AF, b"\x41\x80\xf8\x6c"),  # 'l'
        (0x164E8C7, b"\x80\xf9\x6c"),      # 'l'
        (0x164E8CC, b"\x31\xc0"),          # xor eax, eax
    )
    for site, opcode in null_checks:
        raw, _ = read_va(data, rows, site, len(opcode))
        require(raw == opcode, f"null check {site:#x} is {raw.hex()}")

    # Unquoted token table, index = byte - 0x5b, used by the value skipper.
    tokens = jump_table(data, rows, 0x265044, 33)
    require(tokens[1] == 0x164EDDE, f"unquoted backslash {tokens[1]:#x}")
    require(tokens[0] == tokens[32] == 0x164EC1F, "bracket arms moved")
    nondigit, _ = read_va(data, rows, 0x164F52C, 8)
    require(nondigit == b"\x48\xc7\x44\x24\x10\x0a\x00\x00", f"nondigit code {nondigit.hex()}")

    close, _ = read_va(data, rows, 0x164F192, 8)
    require(close[:5] == b"\x80\x7c\x24\x0f\x4c", f"seed compare {close.hex()}")
    cleared, _ = read_va(data, rows, 0x164F240, 2)
    require(cleared == b"\x31\xdb", f"close clears ebx {cleared.hex()}")
    success, _ = read_va(data, rows, 0x164F447, 12)
    require(success == b"\x0f\xb6\x44\x24\x0f\x88\x41\x01\x31\xc0\x88\x01",
            f"success return {success.hex()}")

    cmov, _ = read_va(data, rows, 0x164FD9D, 15)
    require(cmov == b"\x41\x0f\xb6\xc5\x40\x84\xed\xbd\x20\x00\x00\x00\x0f\x44\xe8",
            f"caller select {cmov.hex()}")
    tag, _ = read_va(data, rows, 0x164FCAD, 21)
    require(tag == b"\x0f\xb6\x6c\x24\x18\x44\x0f\xb6\x6c\x24\x19\x40\x80\xfd\x01\x0f\x85\xc8\x00\x00\x00",
            f"caller tag load {tag.hex()}")
    early, _ = read_va(data, rows, 0x164FC56, 3)
    require(early == b"\x40\xb5\x20", f"file-read fallback {early.hex()}")

    missing_slot = rip_disp32(0x164F19F, data, rows, b"\xff\x15")
    require(missing_slot == 0x5770B20, f"missing-key slot {missing_slot:#x}")
    # Reuse the rela scan for this one slot.
    missing_addend = None
    for index in range(0, len(rela_bytes), 24):
        offset, info, addend = struct.unpack_from("<QQq", rela_bytes, index)
        if offset == 0x5770B20 and (info & 0xFFFFFFFF) == 8:
            missing_addend = addend
            break
    require(missing_addend == 0x164B980, f"missing-key addend {missing_addend}")
    sentinel, _ = read_va(data, rows, 0x164B9E9, 6)
    require(sentinel[:3] == b"\x3c\x4c\x74", f"0x4c sentinel {sentinel.hex()}")
    ud2, _ = read_va(data, rows, 0x164BA5F, 2)
    require(ud2 == b"\x0f\x0b", f"missing-key ud2 {ud2.hex()}")

    return {
        "target_sha256": SHA256,
        "target_size": SIZE,
        "fdes": measured,
        "caller_call": f"{CALLER_CALL:#x}",
        "entry": f"{ENTRY:#x}",
        "walker": f"{walker:#x}",
        "whitespace_mask": f"{MASK:#x}",
        "whitespace_bits": list(MASK_BITS),
        "whitespace_sites": {f"{start:#x}": [f"{site:#x}" for site in sites]
                             for start, sites in mask_sites.items() if sites},
        "aws_name_rodata": "0x20a458",
        "nvtestnet_rodata": "0x2180ff",
        "quote_table": "0x264a88",
        "quote_table_count": 76,
        "quote_index_32": "0x164b820",
        "nvtestnet_compare": "0x164bfd4",
        "nvtestnet_store": "0x164c3a4",
        "nvtestnet_discriminant": 32,
        "class_table": "0x7caac8",
        "class_special": [f"{byte:#x}" for byte in special],
        "simple_escapes": decoded,
        "unicode_escape_entry": "0x4ebf103",
        "rejected_escape_count": reject,
        "escape_reject_code": 12,
        "string_failure_status": 2,
        "unquoted_backslash_target": "0x164edde",
        "unquoted_nondigit_code": 10,
        "caller_fallback": 32,
        "missing_key_helper": "0x164b980",
        "unset_seed": 76,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the measured record")
    parser.add_argument("--check", type=Path, help="require this JSON to match the measurement")
    args = parser.parse_args()
    try:
        record = measure(load())
    except Fail as error:
        print(f"fail: {error}", file=sys.stderr)
        return 1
    text = json.dumps(record, indent=2) + "\n"
    if args.check:
        require_text = args.check.read_text(encoding="utf-8")
        if require_text != text:
            print("fail: evidence.json does not match the binary", file=sys.stderr)
            return 1
        print(f"ok {args.check}")
        return 0
    if args.json:
        sys.stdout.write(text)
    else:
        print(
            "ok "
            f"fdes={len(record['fdes'])} "
            f"escapes={len(record['simple_escapes'])} "
            f"rejected_escapes={record['rejected_escape_count']} "
            f"quote_arms={record['quote_table_count']} "
            f"fallback={record['caller_fallback']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
