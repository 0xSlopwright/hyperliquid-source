#!/usr/bin/env python3
"""Verify immutable imported files and source repository commit pins."""
import json
from pathlib import Path
import subprocess
import sys

from artifacts import check

SETUP = 'run git submodule update --init --recursive'


def git(root, path, *args):
    try:
        return subprocess.check_output(['git', '-C', str(root / path), *args], text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise ValueError(f'Unreadable pinned source: {path}; {SETUP}') from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate key in provenance manifest: {key}')
        result[key] = value
    return result


def _load(root, name):
    return json.loads((root / 'provenance' / name).read_text(),
                      object_pairs_hook=_unique_object)


def verify(root):
    manifest = _load(root, 'imports.json')
    paths = [item['path'] for item in manifest['files']]
    if len(set(paths)) != len(paths):
        raise ValueError('Duplicate path in imports manifest')
    manifest = json.loads((root / 'provenance/imports.json').read_text())
    if not isinstance(manifest, dict) or 'files' not in manifest:
        raise ValueError('Invalid import manifest')
def load_manifest(root, name):
    path = root / 'provenance' / name
    if not path.is_file():
        raise ValueError(f'Missing manifest: provenance/{name}')
    return json.loads(path.read_text())


def verify(root):
    manifest = load_manifest(root, 'imports.json')
    for item in manifest['files']:
        if not isinstance(item, dict) or 'path' not in item:
            raise ValueError('Invalid import manifest record')
        check(root / item['path'], item)
    for repo in _load(root, 'sources.json')['repositories']:
    for repo in json.loads((root / 'provenance/sources.json').read_text())['repositories']:
        if not isinstance(repo, dict) or 'path' not in repo or 'commit' not in repo:
            raise ValueError('Invalid source repository record')
    sources = json.loads((root / 'provenance/sources.json').read_text())
    if not isinstance(sources, dict) or 'repositories' not in sources:
        raise ValueError('Invalid sources manifest')
    for repo in sources['repositories']:
    for repo in load_manifest(root, 'sources.json')['repositories']:
        if not (root / repo['path'] / '.git').exists():
            raise ValueError(f'Missing pinned source: {repo["path"]}; {SETUP}')
        if git(root, repo['path'], 'rev-parse', 'HEAD') != repo['commit']:
            raise ValueError(f"Source commit mismatch: {repo['path']}")
        if git(root, repo['path'], 'status', '--porcelain'):
            raise ValueError(f"Modified source reference: {repo['path']}")
    print(f"Verified {len(manifest['files'])} imported files and all pinned source repositories.")


if __name__ == '__main__':
    try:
        verify(Path(__file__).resolve().parents[1])
    except (ValueError, OSError) as error:
        print(f'verify_imports: {error}', file=sys.stderr)
        sys.exit(1)
