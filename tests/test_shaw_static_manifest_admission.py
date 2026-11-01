"""New collectors share the repository's ambiguity rejection at admission."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node94_version_requirements as versions
import rate_lookup_result_static as rate


class SharedManifestAdmissionTests(unittest.TestCase):
    def test_ambiguous_manifests_fail_before_any_target_read(self):
        documents = [
            ('{"files": [], "files": []}', 'Duplicate key'),
            ('{"files": [{"path": "x"}, {"path": "x"}]}', 'Duplicate path'),
        ]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'provenance').mkdir()
            for document, message in documents:
                (root / 'provenance/artifacts.json').write_text(document)
                with self.subTest(collector='versions', message=message):
                    with self.assertRaisesRegex(ValueError, message):
                        versions.generate(root)
                with self.subTest(collector='rate', message=message):
                    with mock.patch.object(rate, 'ROOT', root):
                        with self.assertRaisesRegex(ValueError, message):
                            rate.generate(root / 'absent-target', root / 'absent-output')
                self.assertFalse((root / 'absent-output').exists())


if __name__ == '__main__':
    unittest.main()
