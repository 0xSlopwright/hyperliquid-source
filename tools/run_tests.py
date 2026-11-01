#!/usr/bin/env python3
"""Run the complete flat unittest file set with fresh imports for every file.

Some tests retain full captured images in module globals. Sequential children
release that memory after each file without changing any tests or suppressing
their ordinary unittest output. Packages need a separate discovery design;
refuse them instead of silently omitting their tests or load_tests hooks.
"""
import argparse
import fnmatch
from pathlib import Path
import re
import subprocess
import sys


VALID_MODULE = re.compile(r'[_a-z]\w*\.py$', re.IGNORECASE)


def test_files(start):
    start = start.resolve()
    if not start.is_dir():
        raise ValueError('test start directory does not exist: ' + str(start))
    if any(start.rglob('__init__.py')):
        raise ValueError('isolated discovery requires a flat test directory, without packages')
    matching = [p for p in start.rglob('*.py') if p.is_file()
                and VALID_MODULE.match(p.name) and fnmatch.fnmatch(p.name, 'test*.py')]
    if any(p.parent != start for p in matching):
        raise ValueError('isolated discovery requires a flat test directory, without nested tests')
    return sorted(matching)


def run(start):
    files = test_files(start)
    # The stdlib helper also preserves -O/-B/-W/-X, as for multiprocessing.
    python = [sys.executable, *subprocess._args_from_interpreter_flags()]
    failed = 0
    # Even an empty directory keeps this interpreter's standard unittest result.
    for ordinal, path in enumerate(files or [None], 1):
        if path is not None:
            print(f'\n[{ordinal}/{len(files)}] {path.name}', file=sys.stderr, flush=True)
        command = [*python, '-m', 'unittest', 'discover', '-s', str(start.resolve()),
                   '-p', path.name if path is not None else 'test*.py', '-v']
        try:
            child = subprocess.Popen(command)
            try:
                returncode = child.wait()
            except BaseException:
                # Unlike Popen's special KeyboardInterrupt context exit, this
                # explicitly reaps the child even for a parent-only interrupt.
                child.kill()
                child.wait()
                raise
        except OSError as error:
            print(f'Could not start unittest child: {error}', file=sys.stderr, flush=True)
            failed += 1
        else:
            if returncode:
                print(f'Unittest child exited with status {returncode}',
                      file=sys.stderr, flush=True)
                failed += 1
    print(f'\nIsolated unittest discovery: {len(files)} files attempted; {failed} failed.',
          file=sys.stderr, flush=True)
    return int(bool(failed))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('start_directory', nargs='?', type=Path, default=Path('tests'))
    args = parser.parse_args(argv)
    try:
        return run(args.start_directory)
    except ValueError as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        print('\nInterrupted; unittest inventory is incomplete.', file=sys.stderr, flush=True)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
