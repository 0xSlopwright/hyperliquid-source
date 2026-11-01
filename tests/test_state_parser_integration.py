"""Boundary controls for the composed ELF parser hardening changes."""
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
MODULES = []
for name in ("consensus_wire", "state_roots", "info_request_path", "exchange_dispatch"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    MODULES.append(module)


class ComposedBoundsTests(unittest.TestCase):
    def test_short_magic_prefix_never_indexes_missing_header_fields(self):
        for module in MODULES:
            for size in range(6):
                with self.subTest(parser=module.__name__, size=size):
                    with self.assertRaises(module.EvidenceError):
                        module.Elf(b"\x7fELF\x02\x01"[:size])

    def test_declared_fde_header_must_also_fit_file(self):
        for module in MODULES:
            for available in (0, 3, 4, 8, 11):
                with self.subTest(parser=module.__name__, available=available):
                    elf = object.__new__(module.Elf)
                    elf.data = (b"\x01\x1b\x03\x3b" + b"\0" * 8)[:available]
                    elf.sections = {".eh_frame_hdr": (0x1000, 0, 12)}
                    with self.assertRaises(module.EvidenceError):
                        module.fde_index(elf)


if __name__ == "__main__":
    unittest.main()
