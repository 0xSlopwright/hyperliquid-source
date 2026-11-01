"""Exercise harness control callbacks only; no emulator or captured execution."""
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from crypto_emulation_guard import run_bounded


class FakeEngine:
    def __init__(self, events=(), complete=True):
        self.events = events
        self.complete = complete
        self.hooks = {}
        self.rip = 0
        self.stopped = False

    def hook_add(self, kind, callback):
        self.hooks[kind] = callback
        return kind

    def hook_del(self, handle):
        self.hooks.pop(handle)

    def emu_stop(self):
        self.stopped = True

    def emu_start(self, start, stop, **limits):
        self.rip = start
        for kind, address, size in self.events:
            callback = self.hooks[kind]
            if kind == 1:
                callback(self, address, size, None)
            else:
                callback(self, 0, address, size, 0, None)
            if self.stopped:
                return
        if self.complete:
            self.rip = stop

    def reg_read(self, _register):
        return self.rip


class CryptoEmulationGuardTests(unittest.TestCase):
    def setUp(self):
        unicorn = types.ModuleType("unicorn")
        unicorn.UC_HOOK_CODE = 1
        unicorn.UC_HOOK_MEM_WRITE = 2
        const = types.ModuleType("unicorn.x86_const")
        const.UC_X86_REG_RIP = 3
        self.modules = patch.dict(sys.modules, {"unicorn": unicorn, "unicorn.x86_const": const})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def run_fixture(self, engine):
        run_bounded(engine, 0x1000, 0x9000, code_ranges=((0x1000, 0x1100),),
                    writable_ranges=((0x4000, 0x4100),), timeout=100, count=10)

    def test_completed_return_and_allowed_write(self):
        engine = FakeEngine(((1, 0x1000, 4), (2, 0x40f8, 8), (1, 0x10ff, 1)))
        self.run_fixture(engine)
        self.assertEqual(engine.hooks, {})

    def test_timeout_or_instruction_limit_is_not_completion(self):
        engine = FakeEngine(complete=False)
        with self.assertRaisesRegex(ValueError, "before the return sentinel"):
            self.run_fixture(engine)
        self.assertEqual(engine.hooks, {})

    def test_instruction_escape_and_boundary_crossing(self):
        for address, size in ((0xfff, 1), (0x1100, 1), (0x10ff, 2), (0x1000, 0)):
            with self.subTest(address=address, size=size):
                engine = FakeEngine(((1, address, size),))
                with self.assertRaisesRegex(ValueError, "instruction escaped"):
                    self.run_fixture(engine)
                self.assertEqual(engine.hooks, {})

    def test_write_escape_and_boundary_crossing(self):
        for address, size in ((0x1000, 1), (0x3fff, 1), (0x40ff, 2), (0x4000, 0)):
            with self.subTest(address=address, size=size):
                engine = FakeEngine(((2, address, size),))
                with self.assertRaisesRegex(ValueError, "write escaped"):
                    self.run_fixture(engine)
                self.assertEqual(engine.hooks, {})

    def test_engine_failure_removes_callbacks(self):
        engine = FakeEngine()
        with patch.object(engine, "emu_start", side_effect=RuntimeError("backend error")):
            with self.assertRaisesRegex(RuntimeError, "backend error"):
                self.run_fixture(engine)
        self.assertEqual(engine.hooks, {})




if __name__ == "__main__":
    unittest.main()
