"""receiver_poll generate() must decode a private snapshot of the admitted bytes.

Sibling of the merged snapshot packets (api_suffix_static,
critical_message_static, funding_bucket_static, hourly_rotation_static,
unique_value_static), open #1094 (build_mode_route), open #1095
(latency_sample), open #1103 (liner_init), open #1105 (file_tracker_init),
open #1109 (rate_maintenance) and own #1100 (cguard_consistency): this
tool admitted the target once (artifacts.check + controls/tables/
relocations on the bytes read into memory) but then ran readelf/objdump
against the target *path*, so the emitted frames/objdump/relocations
output was bound to whatever the path served at decode time while
records.json stamped the admitted digest.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check/instruction_controls/tables/relocations/read_va) is stubbed here;
what this test verifies is exactly the defect's surface — which file
the decoders open. The wrapper swaps the binary file's bytes (same size)
at the first decoder call, modelling a replacement between admission
and decode, and records the path each decoder was given plus the bytes
at that path at call time.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import receiver_poll_static as tool

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
                lines.append('5777378  RELATIVE\n')
                return ''.join(lines)
            raise AssertionError(f'unexpected decoder call: {cmd}')

        orig = (tool.check, tool.instruction_controls, tool.tables,
                tool.relocations, tool.read_va, tool.subprocess.check_output)
        tool.check = lambda binary_, identity: None
        tool.instruction_controls = lambda data: None
        tool.tables = lambda data: []
        tool.relocations = lambda data: []
        # read_va already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.read_va = lambda data, va, length: (0, b'\x00' * length)
        tool.subprocess.check_output = fake_check_output
        try:
            result = tool.generate(binary, out)
        finally:
            (tool.check, tool.instruction_controls, tool.tables,
             tool.relocations, tool.read_va,
             tool.subprocess.check_output) = orig
        return binary, out, calls, result

    def test_decoders_do_not_open_the_target_path(self):
        binary, out, calls, _ = self.run_generate()
        self.assertEqual(len(calls), 8)  # readelf frames + 6 objdump + readelf rela
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
