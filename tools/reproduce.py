#!/usr/bin/env python3
"""Regenerate inventories and the preserved heuristic literal classification."""
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = root / 'work/reproduced'
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(root / 'tools/artifacts.py'), 'verify'], check=True)
for release in ['94', '115']:
    name = f'hl-node-{release}.inventory.json'
    subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/inv.py'),
                    str(root / f'artifacts/node/{release}/hl-node'), str(out / name)], check=True)
    if json.loads((out / name).read_text()) != json.loads((root / 'research/imported' / name).read_text()):
        raise ValueError(f'Inventory differs: {name}')
name = 'can1357-literal-classes.json'
subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/drift.py'),
                str(root / 'references/can1357-hl'), str(root / 'artifacts/node/94/hl-node'),
                str(root / 'artifacts/node/115/hl-node'), str(out / name)], check=True)
old = json.loads((root / 'research/imported' / name).read_text())
new = json.loads((out / name).read_text())
def canonical(d):
    return sorted((i['crate'], i['literal'], i['class']) for i in d['items'])
if old['counts'] != new['counts'] or canonical(old) != canonical(new):
    raise ValueError('Classification differs from imported evidence; retain both and investigate')
print('Inventories and classification reproduce the imported evidence.')
