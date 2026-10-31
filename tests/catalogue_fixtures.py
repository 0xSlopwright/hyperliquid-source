"""Valid unrelated inputs for catalogue metadata corruption controls."""
import hashlib
import json
from test_research_tools import fixture

GATES = ('mapped', 'built', 'behavior', 'identity')


def prepare_inputs(root):
    progress_path = root / 'research/progress.json'
    progress = json.loads(progress_path.read_text())
    progress['gates'] = {gate: gate for gate in GATES}
    for row in progress['components'].values():
        row['gates'] = {gate: False for gate in GATES}
    progress_path.write_text(json.dumps(progress))
    data = bytes(fixture())
    records = []
    for release, relative in [('94', 'artifacts/node/94/hl-node'),
                              ('115', 'artifacts/node/115/hl-node'),
                              ('visor', 'artifacts/visor/captured/hl-visor')]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        records.append({'path': relative, 'size': len(data),
                        'sha256': hashlib.sha256(data).hexdigest()})
        name = f'hl-node-{release}' if release != 'visor' else 'hl-visor'
        path = root / f'research/imported/{name}.inventory.json'
        inventory = json.loads(path.read_text())
        if isinstance(inventory, dict) and 'fde_count_eh_frame_hdr' in inventory:
            inventory['fde_count_eh_frame_hdr'] = 1
            path.write_text(json.dumps(inventory))
    path = root / 'provenance/artifacts.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({'files': records}))
