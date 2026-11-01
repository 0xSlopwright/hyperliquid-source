"""heartbeat_status run() must decode a private snapshot of the admitted bytes.

Sibling of the merged snapshot packets and the open snapshot PRs
(#1094, #1095, #1103, #1105, #1109, #1110, own #1100/#1111/#1112): this
non-*_static tool admitted the target once (artifacts.check +
static_controls/relocations on the bytes read into memory) but then ran
readelf/objdump against the target *path* — including a streamed full
.text disassembly — so the emitted frames/objdump/relocations output
was bound to whatever the path served at decode time while records.json
stamped the admitted digest.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check/static_controls/relocations/mapped) is stubbed here; what this
test verifies is exactly the defect's surface — which file the decoders
open. The wrappers swap the binary file's bytes (same size) at the
first decoder call, modelling a replacement between admission and
decode, and record the path each decoder was given plus the bytes at
that path at call time.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import heartbeat_status as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64
PAIRS = [(tool.START, tool.END),
         (tool.CALLER_START, tool.CALLER_END),
         (tool.HELPER_START, tool.HELPER_END)]


def fde_line(start, end):
    return f'FDE pc={start:016x}..{end:016x}\n'


class FakePopen:
    def __init__(self, lines):
        self.stdout = lines

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self):
        return 0


class DecoderSnapshotTests(unittest.TestCase):
    def run_generate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        binary = root / 'hl-node'
        binary.write_bytes(ADMITTED)
        out = root / 'out'
        calls = []
        swapped = []

        def note(cmd):
            if not swapped:
                binary.write_bytes(SWAPPED)
                swapped.append(True)
            path = cmd[-1]
            calls.append((path, Path(path).read_bytes()))

        def fake_check_output(cmd, text=True, encoding=None):
            note(cmd)
            if '-wf' in cmd:
                return ''.join(fde_line(s, e) for s, e in PAIRS)
            if '-d' in cmd:
                return 'canned disassembly\n'
            if '-rW' in cmd:
                return ('000000000576e488  0000000000000000 R_X86_64_GLOB_DAT '
                        'memcmp@GLIBC_2.2.5\n')
            raise AssertionError(f'unexpected decoder call: {cmd}')

        def fake_popen(cmd, stdout=None, text=False, encoding=None):
            note(cmd)
            lines = ['  4876fd9: e8 01 02 03 04 call 4726a50\n',
                     '  487734c: e8 01 02 03 04 call 4726a50\n']
            return FakePopen(lines)

        orig = (tool.check, tool.static_controls, tool.relocations,
                tool.mapped, tool.subprocess.check_output,
                tool.subprocess.Popen)
        tool.check = lambda binary_, item: None
        tool.static_controls = lambda data: {}
        tool.relocations = lambda data: [{'slot_va': hex(0x576e488)}]
        # mapped already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.mapped = lambda data, va, size: (0, b'\x00' * size)
        tool.subprocess.check_output = fake_check_output
        tool.subprocess.Popen = fake_popen
        try:
            result = tool.run(binary, out)
        finally:
            (tool.check, tool.static_controls, tool.relocations,
             tool.mapped, tool.subprocess.check_output,
             tool.subprocess.Popen) = orig
        return binary, out, calls, result

    def test_decoders_do_not_open_the_target_path(self):
        binary, out, calls, _ = self.run_generate()
        # readelf frames + streamed objdump + readelf rela + 3 range objdump
        self.assertEqual(len(calls), 6)
        for path, _ in calls:
            self.assertNotEqual(path, str(binary))

    def test_decoders_read_the_admitted_bytes(self):
        binary, out, calls, result = self.run_generate()
        for path, seen in calls:
            self.assertEqual(seen, ADMITTED)
        self.assertEqual(result['target_bytes'], len(ADMITTED))
        records = json.loads((out / 'records.json').read_text())
        self.assertEqual(records['target_bytes'], len(ADMITTED))
        self.assertTrue((out / 'frames.txt').exists())
        self.assertTrue((out / 'relocations.txt').exists())


if __name__ == '__main__':
    unittest.main()
