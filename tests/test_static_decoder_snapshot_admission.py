"""The exact private bytes consumed by native decoders must pass admission too."""
from contextlib import nullcontext
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from artifacts import check
from elf_index import sections

MODULES = ('build_mode_route_static', 'latency_sample_static', 'liner_init_static',
           'cguard_consistency_static', 'file_tracker_init_static', 'rate_maintenance_static',
           'receiver_poll_static', 'short_string_static', 'truncated_debug_static', 'heartbeat_status')
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


class StopBeforeDecode(Exception):
    pass


class SnapshotAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        if cls.data.startswith(b'version https://git-lfs.github.com/spec/v1'):
            raise unittest.SkipTest('materialize authenticated node94 capture')
        if hashlib.sha256(cls.data).hexdigest() != SHA94:
            raise AssertionError('node94 digest changed')
        # Change an unconsumed compiler-comment byte, leaving structural and
        # bounded instruction controls intact. Only identity should reject it.
        comment = next(s for s in sections(cls.data) if s['name'] == '.comment')
        changed = bytearray(cls.data)
        changed[comment['offset']] ^= 1
        cls.changed = bytes(changed)

    def exercise(self, module, replace_after_admission):
        tool = importlib.import_module(module)
        seen = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'input.elf'
            binary.write_bytes(self.data)

            def admit(path, identity):
                check(path, identity)
                seen.append(Path(path))
                if Path(path) == binary and replace_after_admission:
                    binary.write_bytes(self.changed)

            def before_decode(command, **kwargs):
                self.assertNotEqual(Path(command[-1]), binary)
                self.assertEqual(Path(command[-1]).read_bytes(), self.data)
                raise StopBeforeDecode()

            with mock.patch.object(tool, 'check', side_effect=admit), \
                    mock.patch.object(tool.subprocess, 'check_output', side_effect=before_decode):
                # The truncated-debug resolver is independent of this data race.
                context = mock.patch.object(tool, 'gnu', side_effect=lambda n: n) if hasattr(tool, 'gnu') else nullcontext()
                with context:
                    action = getattr(tool, 'generate', None) or tool.run
                    if replace_after_admission:
                        with self.assertRaisesRegex(ValueError, 'size/SHA-256 mismatch'):
                            action(binary, root / 'out')
                    else:
                        with self.assertRaises(StopBeforeDecode):
                            action(binary, root / 'out')
            self.assertEqual(len(seen), 1 if replace_after_admission else 2)
            if not replace_after_admission:
                self.assertNotEqual(seen[1], binary)
                self.assertFalse(seen[1].exists(), 'private snapshot leaked after decoder failure')

    def test_replacement_between_admission_and_read_is_rejected(self):
        for name in MODULES:
            with self.subTest(module=name):
                self.exercise(name, True)

    def test_valid_snapshot_is_admitted_and_cleaned_on_decoder_failure(self):
        for name in MODULES:
            with self.subTest(module=name):
                self.exercise(name, False)


if __name__ == '__main__':
    unittest.main()
