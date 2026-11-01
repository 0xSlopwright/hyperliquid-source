import csv,hashlib,importlib,json,re,subprocess,sys
from pathlib import Path
base=Path(__file__).resolve().parent;root=base.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(root/'tools'))
provider=Path('/opt/homebrew/Cellar/binutils/2.47/bin/objdump');output=base/'decoder-native';output.mkdir(exist_ok=True)
packets=[]
changes=json.loads((base/'full-file-changes.json').read_text())
selected=[]
for name,pr in {'staking_core_writer':1268,'bridge_evm_block_step':1269,'set_global_oracle':1271}.items():
    paths=[Path(x.split('\t',1)[1])for x in changes[str(pr)]]
    selected.append((name,next(p.parent.name for p in paths if p.name in ('functions.tsv','function-rows.tsv'))))
for name,packet in selected:
    tool=importlib.import_module(name);image=tool.load_image();rows=[]
    inventory=root/'research/work-items'/packet/'functions.tsv'
    if inventory.exists():
        bounds=[(int(r.get('start',r.get('function')),16),int(r['end'],16))for r in csv.DictReader(inventory.open(),delimiter='\t')]
    else:
        grouped={}
        for r in csv.DictReader((inventory.parent/'function-rows.tsv').open(),delimiter='\t'):
            grouped.setdefault(r.get('subject',r.get('function')),[]).append((int(r['address'],16),int(r['size'])))
        bounds=[(min(a for a,n in rs),max(a+n for a,n in rs))for rs in grouped.values()]
    for start,end in bounds:
        command=[str(provider),'-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(tool.BINARY)]
        native=subprocess.check_output(command,text=True);(output/f'{name}-{start:x}.txt').write_text(native)
        reference={int(m[1],16):bytes.fromhex(m[2]) for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',native,re.M)}
        cursor=start;matched=0;unsupported=None
        def read(va,count):
            offset=image.offset(va);return bytes(image.blob[offset:offset+count])
        while cursor<end:
            try:instruction=tool.decode(read,cursor)
            except tool.EvidenceError as error:unsupported=str(error);break
            assert reference.get(cursor)==read(cursor,instruction.size),(name,hex(cursor),reference.get(cursor),instruction.size)
            matched+=1;cursor=instruction.next
        assert cursor<=end
        fde = image.fde(start)
        rows.append({'fde_start':hex(fde[0]), 'fde_end':hex(fde[1]), 'declared_range_is_full_fde': (start,end)==fde, 'start':hex(start),'end':hex(end),'matched_instruction_rows':matched,'decoded_prefix_end':hex(cursor),'full_body_decoded':cursor==end,'unsupported':unsupported,'native_export_sha256':hashlib.sha256(native.encode()).hexdigest()})
    packets.append({'packet':packet,'fde_bodies':len(rows),'matched_instruction_rows':sum(r['matched_instruction_rows'] for r in rows),'full_body_decoded':sum(r['full_body_decoded'] for r in rows),'rows':rows})
result={'target_sha256':tool.SHA256,'provider_sha256':hashlib.sha256(provider.read_bytes()).hexdigest(),'packets':packets,'limits':'Instruction byte partitions only, for the custom decoder prefix in each declared FDE. Unsupported tails are explicit and not credited. This is not independent instruction semantics, all-input behavior or complete component equivalence.'}
(output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({p['packet']:{k:v for k,v in p.items() if k not in ['rows','packet']} for p in packets}))
