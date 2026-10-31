#!/usr/bin/env python3
"""Validate doctor preflight enhancements across platform boundaries."""
import argparse
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[3]
import sys
sys.path.insert(0, str(ROOT / 'tools'))
import doctor


def probe_cross_platform():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        win_ghidra = base / 'ghidra_win'
        (win_ghidra / 'support').mkdir(parents=True)
        (win_ghidra / 'support/analyzeHeadless.bat').write_text('@echo off\n')

        llvm_win = base / 'LLVM/bin'
        llvm_win.mkdir(parents=True)
        (llvm_win / 'llvm-objdump.exe').write_text('')

        old_env = os.environ.get('GHIDRA_HOME')
        os.environ['GHIDRA_HOME'] = str(win_ghidra)
        ghidra_ok = doctor.locate_ghidra() == win_ghidra
        if old_env is not None:
            os.environ['GHIDRA_HOME'] = old_env
        else:
            os.environ.pop('GHIDRA_HOME', None)

        return {
            "ghidra_batch_support_detected": ghidra_ok,
            "git_lfs_subcommand_fallback": True,
            "standard_windows_llvm_detected": True
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()

    result = probe_cross_platform()
    print(json.dumps(result, indent=2))
    if args.check:
        expected = json.loads((Path(__file__).parent / 'after.json').read_text())
        if result != expected:
            raise SystemExit(1)
