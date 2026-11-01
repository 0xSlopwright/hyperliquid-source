import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

root = Path('<repo>')
output = Path(__file__).resolve().parent / 'suite'
output.mkdir(exist_ok=True)
sys.path.insert(0, str(root / 'tools'))
from run_tests import test_files

files = test_files(root / 'tests')
changes = json.loads((output.parent / 'full-file-changes.json').read_text())
added = {Path(x.split('\t')[1]).name for rows in changes.values() for x in rows if '\ttests/' in x}
files.sort(key=lambda p: (p.name not in added, p.name))
results = []
started = time.monotonic()

def run(path):
    begin = time.monotonic()
    command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(root / 'tests'), '-p', path.name, '-v']
    log = output / (path.stem + '.log')
    with log.open('wb') as handle:
        process = subprocess.run(command, cwd=root, stdout=handle, stderr=subprocess.STDOUT)
    content = log.read_bytes()
    counts = re.findall(rb'^Ran (\d+) tests? in ', content, re.M)
    skips = re.findall(rb'^OK \(skipped=(\d+)\)', content, re.M)
    return dict(module=path.name, source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                returncode=process.returncode, tests=int(counts[-1]) if counts else 0,
                skips=int(skips[-1]) if skips else 0,
                seconds=round(time.monotonic()-begin, 3),
                log_sha256=hashlib.sha256(content).hexdigest())

def save():
    record = dict(method='Complete tools/run_tests.py test_files inventory; same fresh unittest discover command per file, sixteen concurrent isolated subprocesses. This is the complete make test inventory, scheduled concurrently without changing the per-file unittest commands.',
                  discovered_modules=len(files), completed_modules=len(results),
                  reported_tests=sum(r['tests'] for r in results), skips=sum(r['skips'] for r in results),
                  failed_modules=[r['module'] for r in results if r['returncode']],
                  seconds=round(time.monotonic()-started, 3),
                  results=sorted(results,key=lambda r:r['module']))
    (output / 'results.json').write_text(json.dumps(record,indent=2)+'\n')

with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    pending = [pool.submit(run, path) for path in files]
    for task in concurrent.futures.as_completed(pending):
        result = task.result()
        results.append(result)
        save()
        print(f"{len(results)}/{len(files)} {result['module']}: {result['returncode']}",flush=True)

sys.exit(int(any(r['returncode'] for r in results)))
