#!/usr/bin/env python3
"""Two fixed recipes on a separately pinned offline Linux provider; build-only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',type=Path,required=True)
    p.add_argument('--prefix',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    if args.out.exists():raise ValueError('Preserve previous results; output must be new')
    sys.path.insert(0,str(args.repo/'tools'))
    import libcore_pad_codegen as m
    pins=json.loads((m.PACKET/'provider-pins.json').read_text())['records']
    records=[];differences=[]
    def record_pins():
        result=[]
        for row in pins:
            path=args.prefix/row['path'] if row['scope']=='prefix' else Path(row['path'])
            if not path.exists():actual=dict(path=row['path'],scope=row['scope'],missing=True)
            else:actual=dict(row,bytes=path.stat().st_size,mode=oct(path.stat().st_mode&0o777),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            if row['scope']=='prefix' and actual!=row:raise ValueError('Official prefix differs: '+str(path))
            result.append(actual)
        return result
    before=record_pins()
    for expected,actual in zip(pins,before):
        if actual!=expected:differences.append(dict(expected=expected,actual=actual))
    target=(args.repo/'artifacts/node/94/hl-node').read_bytes()
    core=(args.prefix/m.CORE_PATH).read_bytes()
    m.captured(target);m.core_member(core)
    if m.sha(m.SOURCE.read_bytes())!=m.SOURCE_SHA:raise ValueError('Fixed authored wrapper differs')
    if 0 not in os.sched_getaffinity(0):raise ValueError('CPU0 unavailable')
    os.sched_setaffinity(0,{0})
    if m.headroom()<=1<<30:raise ValueError('Insufficient cgroup headroom')
    args.out.mkdir();(args.out/'tmp').mkdir()
    environment=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',TZ='UTC',TMPDIR=str(args.out/'tmp'))
    recipes=m.recipes(args.prefix/'bin/rustc',m.SOURCE,args.out)
    freeze=dict(recipes=recipes,environment=environment,source_sha256=m.SOURCE_SHA,target_sha256=m.TARGET_SHA,core_sha256=m.CORE_SHA,provider=before,original_provider_differences=differences,scope='Supplemental Linux container replay; original exact-host provenance not reproduced',trace_limitation='No strace available in this existing offline image; successful-read trace not claimed')
    m.write_json(args.out/'freeze.json',freeze)
    for recipe in recipes:
        directory=args.out/recipe['name'];directory.mkdir()
        started=time.monotonic();minimum=m.headroom();stop_reason=None
        with (directory/'stdout').open('xb') as out,(directory/'stderr').open('xb') as err:
            child=subprocess.Popen(recipe['argv'],cwd=directory,env=environment,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            while child.poll() is None:
                minimum=min(minimum,m.headroom())
                if minimum<1<<30 or time.monotonic()-started>60:
                    stop_reason='memory_headroom' if minimum<1<<30 else '60_second_wall_time'
                    os.killpg(child.pid,signal.SIGTERM);break
                time.sleep(.1)
            try:code=child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);code=child.wait()
        result=dict(name=recipe['name'],argv=recipe['argv'],exit=code,stop_reason=stop_reason,seconds=time.monotonic()-started,minimum_headroom=minimum)
        records.append(result);m.write_json(directory/'build-result.json',result)
        if code or stop_reason:raise ValueError('Fixed recipe failed; no tuning/retry: '+recipe['name'])
    report=m.inspect_existing(args.out/'default',args.out/'thin',target,core)
    after=record_pins()
    if after!=before:raise ValueError('Provider changed during builds')
    report.update(supplemental_provider='Pinned read-only Linux container and official Rust1.94.1 prefix',original_exact_host_reproduced=False,provider_before_after_equal=True,build_results=records,original_provider_differences=differences,objects_executed=False)
    m.write_json(args.out/'report.json',report)
    print(json.dumps(dict(status='PASS supplemental build-only replay',candidate_counts={k:len(v['candidates']) for k,v in report['recipes'].items()})))


if __name__=='__main__':main()
