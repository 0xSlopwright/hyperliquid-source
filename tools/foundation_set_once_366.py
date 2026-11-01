#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 set-once cell evidence packet.

The single window is [0x1515a30, 0x1515a63), 51 bytes, followed by thirteen
int3 padding bytes up to the next FDE at 0x1515a70. It implements the
set-once protocol already bound for the five windows of
research/work-items/foundation-set-once-94, with its own cell fields and
range: out-of-range input returns 0 and touches nothing, an unset cell
stores the input and returns al 8, a set cell returns 8 when the stored
value matches and 1 when it differs. This checker verifies retained bytes
and data relationships only; it never executes target code, never decodes
a general function inventory, and makes no reconstruction claim.

One precision note the checker locks in: on the store arm the window sets
only the low byte of eax (mov $8, %al), so the full eax on that path is
((input - 1) & 0xFFFFFF00) | 8, not a clean 8. The compare and
out-of-range arms set eax fully (mov $1/%eax with cmove, xor %eax/%eax),
so they return clean 1/8 and 0. Callers that consume only al see 8 on the
store arm; the simulation models the full eax honestly.

Run from the repository root:

    python3 tools/foundation_set_once_366.py \
        --check research/work-items/foundation-set-once-366-94/evidence.json
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x1515a30, 0x1515a63
NEXT_START = 0x1515a70
WINDOW = bytes.fromhex(
    '488d46ff483d6d0100007717837f60017514397764b908000000b8010000000f44c1c331c0'
    'c3c7476001000000897764b008c3')
PADDING = b'\xcc' * 13
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e4440100300082003300000000000000')
FDE_VA = 0xcf59f8
CIE_VA = 0xce1518
LO, HI = 1, 366
FLAG_OFF, VALUE_OFF = 0x60, 0x64


def require(condition, message):
    if not condition:
        raise ValueError(message)


def simulate(flag, value, original):
    """Model the window's observable behaviour.

    flag/value are the cell state (u32 flag, u32 value); original is the
    rsi input. Returns (al, eax, new_flag, new_value_or_None). Inputs
    outside 1..366 return 0 and touch nothing; input 0 wraps under the
    window's own (rsi - 1) unsigned compare and is out of range too.
    """
    if not 1 <= original <= 366:
        return 0, 0, flag, None
    if flag != 1:
        # Store arm: flag becomes 1, value becomes the input, al is 8,
        # and the upper eax bytes are the residue of (original - 1).
        return 8, ((original - 1) & 0xFFFFFF00) | 8, 1, original
    if value == original:
        return 8, 8, flag, None
    return 1, 1, flag, None


def analyze(data, ev):
    """Structural checks, separate from identity so corruption controls
    reach them."""
    require(hashlib.sha256(data).hexdigest() == SHA256,
            'target digest mismatch')
    require(ev['target_sha256'] == SHA256, 'evidence digest mismatch')
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    w = read(START, END - START)
    require(w == WINDOW, 'Window changed at %s' % hex(START))
    require(len(w) == END - START, 'Window length changed')
    pad = read(END, NEXT_START - END)
    require(pad == PADDING, 'Padding changed at %s' % hex(END))
    eh = by_name['.eh_frame']
    fde_off = eh['offset'] + (FDE_VA - eh['address'])
    require(data[fde_off:fde_off + len(FDE)] == FDE, 'FDE record changed')
    cie_off = eh['offset'] + (CIE_VA - eh['address'])
    require(data[cie_off:cie_off + len(CIE)] == CIE, 'CIE record changed')
    # Window: lea rax, [rsi-1]; cmp $0x16d, rax; ja out-of-range return 0.
    require(w[0:4] == b'\x48\x8d\x46\xff', 'Range lea changed')
    require(w[4:10] == b'\x48\x3d\x6d\x01\x00\x00', 'Range compare changed')
    require(w[10] == 0x77 and START + 10 + 2 + w[11] == 0x1515a53,
            'Out-of-range branch changed')
    require(w[11] == 0x17, 'Out-of-range displacement changed')
    # Window: cmpl $1, 0x60(rdi); jne store arm.
    require(w[12:16] == b'\x83\x7f\x60\x01', 'Flag compare changed')
    require(w[16] == 0x75 and START + 16 + 2 + w[17] == 0x1515a56,
            'Store branch changed')
    require(w[17] == 0x14, 'Store displacement changed')
    # Window: cmp %esi, 0x64(rdi); cmove selects 8 on equality, else 1.
    require(w[18:21] == b'\x39\x77\x64', 'Value compare changed')
    require(w[21:26] == b'\xb9\x08\x00\x00\x00', 'Equal value changed')
    require(w[26:31] == b'\xb8\x01\x00\x00\x00', 'Mismatch value changed')
    require(w[31:34] == b'\x0f\x44\xc1' and w[34] == 0xc3,
            'Compare return changed')
    # Window: out-of-range arm zeroes eax and returns.
    require(w[35:37] == b'\x31\xc0' and w[37] == 0xc3,
            'Out-of-range return changed')
    # Window: store arm writes flag 1 and the input value, returns al 8.
    require(w[38:45] == b'\xc7\x47\x60\x01\x00\x00\x00', 'Flag store changed')
    require(w[45:48] == b'\x89\x77\x64', 'Value store changed')
    require(w[48:51] == b'\xb0\x08\xc3', 'Store return changed')
    # Evidence cross-checks.
    win = ev['window']
    require(win['start_va'] == hex(START), 'Evidence start changed')
    require(win['end_va_exclusive'] == hex(END), 'Evidence end changed')
    require(win['bytes'] == END - START, 'Evidence length changed')
    require(win['sha256'] == hashlib.sha256(WINDOW).hexdigest(),
            'Evidence window hash changed')
    require(win['padding_int3_bytes'] == len(PADDING),
            'Evidence padding changed')
    require(win['next_fde_start'] == hex(NEXT_START),
            'Evidence next FDE changed')
    cell = ev['cell']
    require(cell['flag_offset'] == hex(FLAG_OFF), 'Evidence flag changed')
    require(cell['value_offset'] == hex(VALUE_OFF), 'Evidence value changed')
    require(cell['valid_inputs']['lo'] == LO, 'Evidence range low changed')
    require(cell['valid_inputs']['hi'] == HI, 'Evidence range high changed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', required=True)
    args = parser.parse_args()
    with open(args.check) as fh:
        ev = json.load(fh)
    with open(TARGET, 'rb') as fh:
        data = fh.read()
    analyze(data, ev)
    print('foundation-set-once-366 evidence OK')


if __name__ == '__main__':
    main()
