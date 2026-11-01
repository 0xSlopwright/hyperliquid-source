#!/usr/bin/env python3
"""Replay the original host-harness failures with fake modules; no target execution."""
import builtins
import hashlib
import json
from pathlib import Path
import struct
import sys
import types
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
source_path = HERE / 'originals/tools/bn254_ecadd.py'
source = source_path.read_bytes()
tool = types.ModuleType('original_ecadd')
tool.__file__ = str(source_path)
exec(compile(source, str(source_path), 'exec'), tool.__dict__)

class BackendReached(Exception):
    pass

real_import = builtins.__import__
def trapped(name, *args, **kwargs):
    if name == 'crypto_emulation_guard':
        raise BackendReached
    return real_import(name, *args, **kwargs)

reached = False
with patch('builtins.__import__', side_effect=trapped):
    try:
        tool.emulate(b'not an ELF', [], [], bytes(128), 150, 1000, allow_execution=True)
    except BackendReached:
        reached = True

u = types.ModuleType('unicorn')
x = types.ModuleType('unicorn.x86_const')
guard = types.ModuleType('crypto_emulation_guard')
for i, name in enumerate(('UC_ARCH_X86', 'UC_HOOK_CODE', 'UC_MODE_64', 'UC_PROT_ALL')):
    setattr(u, name, i)
for i, name in enumerate(('FS_BASE', 'R8', 'RAX', 'RCX', 'RDI', 'RDX', 'RIP', 'RSI', 'RSP')):
    setattr(x, 'UC_X86_REG_' + name, i)
u.UcError = type('FakeUcError', (Exception,), {})

class Fake:
    def __init__(self, *args): self.mem, self.reg, self.hooks = {}, {}, []
    def mem_map(self, *args): pass
    def mem_write(self, address, data): self.mem.update((address+i, b) for i, b in enumerate(data))
    def mem_read(self, address, size): return bytes(self.mem.get(address+i, 0) for i in range(size))
    def reg_write(self, reg, value): self.reg[reg] = value
    def reg_read(self, reg): return self.reg.get(reg, 0)
    def hook_add(self, kind, hook, **kwargs): self.hooks.append(hook); return len(self.hooks)
    def hook_del(self, hook): pass

u.Uc = Fake
expected = tool.enc(*tool.ref_add(tool.G, tool.TWO_G)).hex()
def fake_run(mu, start, stop, **kwargs):
    sp = mu.reg_read(x.UC_X86_REG_RSP)
    mu.mem_write(sp, struct.pack('<Q', tool.MALLOC_RET))
    mu.reg_write(x.UC_X86_REG_RDI, 64)
    mu.hooks[0](mu, tool.MALLOC, 4, None)
    mu.mem_write(0x60000100, struct.pack('<5Q', 1, tool.HEAP, 64, 0, 150))
    mu.mem_write(tool.HEAP, bytes.fromhex(expected))
    mu.reg_write(x.UC_X86_REG_RIP, start)
    raise ValueError('controlled incomplete return')

guard.run_bounded = fake_run
with patch.dict(sys.modules, {'unicorn': u, 'unicorn.x86_const': x, 'crypto_emulation_guard': guard}):
    result = tool.emulate(b'', [], [], tool.enc(*tool.G, *tool.TWO_G), 150, 1000,
                          allow_execution=True)
record = {
    'scope': 'Host-only fake backend; no Unicorn or captured instruction execution.',
    'source_sha256': hashlib.sha256(source).hexdigest(),
    'untrusted_bytes_reach_backend_import': reached,
    'fake_result': result,
    'original_positive_predicates': {
        'g_plus_2g_output_check_passes': result['output_hex'] == expected,
        'gas_equal_limit_kind_and_gas_check_passes': (result['kind'], result['gas_used']) == ('ok', 150),
    },
}
print(json.dumps(record, indent=2, sort_keys=True))
