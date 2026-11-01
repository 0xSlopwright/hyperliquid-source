"""Bounds for explicitly authorized, offline crypto fixture emulation.

Importing this module never imports Unicorn or executes captured instructions.
The caller must separately obtain authorization before invoking the runner.
"""


def run_bounded(mu, start, stop, *, code_ranges, writable_ranges, timeout, count):
    """Require in-range instructions/writes and a completed return to stop."""
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_RIP

    if timeout <= 0 or count <= 0:
        raise ValueError("positive timeout and instruction count required")
    ranges = tuple(code_ranges)
    writes = tuple(writable_ranges)
    if not ranges or any(a >= b for a, b in (*ranges, *writes)):
        raise ValueError("nonempty bounded ranges required")

    def contains(intervals, address, size):
        return size > 0 and any(a <= address and address + size <= b for a, b in intervals)

    if not contains(ranges, start, 1) or contains(ranges, stop, 1):
        raise ValueError("entry must be inside and return sentinel outside code")
    errors = []

    def code_hook(engine, address, size, _user):
        if not contains(ranges, address, size):
            errors.append(f"instruction escaped allowed range at {address:#x}")
            engine.emu_stop()

    def write_hook(engine, _access, address, size, _value, _user):
        if not contains(writes, address, size):
            errors.append(f"write escaped synthetic memory at {address:#x}")
            engine.emu_stop()

    hooks = []
    try:
        hooks.append(mu.hook_add(UC_HOOK_CODE, code_hook))
        hooks.append(mu.hook_add(UC_HOOK_MEM_WRITE, write_hook))
        mu.emu_start(start, stop, timeout=timeout, count=count)
        if errors:
            raise ValueError(errors[0])
        if mu.reg_read(UC_X86_REG_RIP) != stop:
            raise ValueError("emulation stopped before the return sentinel")
    finally:
        for hook in hooks:
            mu.hook_del(hook)
