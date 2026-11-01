"""cguard generate() must decode a private snapshot of the admitted bytes.

Sibling packets (api_suffix_static, critical_message_static,
funding_bucket_static, hourly_rotation_static, unique_value_static)
already decode a private snapshot, and open PRs #1094 (build_mode_route)
and #1095 (latency_sample) fix the same gap in two more packets: this
tool admitted the target once (artifacts.check + controls/relocations on
the bytes read into memory) but then ran readelf/objdump against the
target *path*, so the emitted frames/objdump/relocations output was
bound to whatever the path served at decode time while records.json
stamped the admitted digest.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check/controls/relocations) is stubbed here; what this test verifies is
exactly the defect's surface — which file the decoders open. The wrapper
swaps the binary file's bytes (same size) at the first decoder call,
modelling a replacement between admission and decode, and records the
path each decoder was given plus the bytes at that path at call time.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import cguard_consistency_static as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64


def fde_line(start, end):
    return f'FDE pc={start:016x}..{end:016x}\n'


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

        real_check_output = tool.subprocess.check_output

        def fake_check_output(cmd, text=True, encoding=None):
            if not swapped:
                binary.write_bytes(SWAPPED)
                swapped.append(True)
            path = cmd[-1]
            calls.append((path, Path(path).read_bytes()))
            if cmd[0] == 'readelf' and '-wf' in cmd:
                return ''.join(fde_line(s, e) for _, (s, e) in tool.RANGES.items())
            if cmd[0] == 'objdump':
                return 'canned disassembly\n'
            if cmd[0] == 'readelf':
                lines = [f'{slot:x}  RELATIVE\n' for slot in tool.RELATIVE]
                lines.append('576e378  RELATIVE\n')
                return ''.join(lines)
            return real_check_output(cmd, text=text)

        orig_check, orig_controls, orig_relocations = tool.check, tool.controls, tool.relocations
        orig_read_va = tool.read_va
        orig_subprocess = tool.subprocess.check_output
        tool.check = lambda binary_, identity: None
        tool.controls = lambda data: None
        tool.relocations = lambda data: []
        # read_va already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.read_va = lambda data, va, length: (0, b'\x00' * length)
        tool.subprocess.check_output = fake_check_output
        try:
            result = tool.generate(binary, out)
        finally:
            tool.check, tool.controls, tool.relocations = orig_check, orig_controls, orig_relocations
            tool.read_va = orig_read_va
            tool.subprocess.check_output = orig_subprocess
        return binary, out, calls, result

    def test_decoders_do_not_open_the_target_path(self):
        binary, out, calls, _ = self.run_generate()
        self.assertEqual(len(calls), 5)  # readelf frames + 3 objdump + readelf rela
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
