"""Print printable-ASCII context windows around byte patterns in a file.

usage: python3 -I ctx.py FILE WINDOW PATTERN [PATTERN ...]
"""
import re
import sys

path, window, patterns = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
data = open(path, "rb").read()


def show(chunk):
    return "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)


for pat in patterns:
    hits = [m.start() for m in re.finditer(re.escape(pat.encode()), data)]
    print(f"=== {pat!r}: {len(hits)} hit(s)")
    for off in hits[:6]:
        lo, hi = max(0, off - window), min(len(data), off + len(pat) + window)
        print(f"--- @0x{off:x}")
        print(show(data[lo:hi]))
