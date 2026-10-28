#!/usr/bin/env python3
"""Verify immutable imported files and source repository commit pins."""
import json
from pathlib import Path
import subprocess
from artifacts import check

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'provenance/imports.json').read_text())
for item in manifest['files']:
    check(root / item['path'], item)
for repo in json.loads((root / 'provenance/sources.json').read_text())['repositories']:
    actual = subprocess.check_output(['git', '-C', str(root / repo['path']), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != repo['commit']:
        raise ValueError(f"Source commit mismatch: {repo['path']}")
    dirty = subprocess.check_output(['git', '-C', str(root / repo['path']), 'status', '--porcelain'], text=True)
    if dirty:
        raise ValueError(f"Modified source reference: {repo['path']}")
print(f"Verified {len(manifest['files'])} imported files and all pinned source repositories.")
