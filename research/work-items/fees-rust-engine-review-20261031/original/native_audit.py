from pathlib import Path
import subprocess,sys,json,re,hashlib,struct,csv
w=Path.cwd();d=w.parent/'fees-engine-1150-review/native';d.mkdir(exist_ok=True);sys.path.insert(0,str(w/'tools'));from fde_extents import eh_frame_records
data=(w/'artifacts/node/94/hl-node').read_bytes();assert hashlib.sha256(data).hexdigest()=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f';fdes={r['start']:r for r in eh_frame_records(data)[1]}
starts=[0x37130b0,0x3742460,0x3743df0,0x3743020,0x3742070,0x3745a60,0x3596da0,0x379a610,0x37153f0,0x36e2d90,0x3718e30]
phoff=struct.unpack_from('<Q',data,32)[0];phsize,phnum=struct.unpack_from('<HH',data,54);segs=[]
for i in range(phnum):
 o=phoff+i*phsize
 if struct.unpack_from('<I',data,o)[0]==1:off,va=struct.unpack_from('<QQ',data,o+8);size=struct.unpack_from('<Q',data,o+32)[0];segs.append((va,off,size))
def read(va,n):
 for base,off,size in segs:
  if base<=va and va+n<=base+size:return data[off+va-base:off+va-base+n]
 raise ValueError(hex(va))
pins={}
for packet in ['trade-fee','fill-ledger','rate-grid','unit-conversion','fee-scale']:
 for row in csv.DictReader((w/('research/work-items/fees-'+packet+'-94/instructions.tsv')).open(),delimiter='\t'):
  va=int(row['va'],16);raw=bytes.fromhex(row['bytes'])
  if va in pins:assert pins[va]==raw
  pins[va]=raw
rows=[]
for start in starts:
 end=fdes[start]['end'];cmd=['/opt/homebrew/opt/binutils/bin/gobjdump','-d','-Mintel','--insn-width=16',f'--start-address={start:#x}',f'--stop-address={end:#x}','artifacts/node/94/hl-node'];out=subprocess.check_output(cmd,text=True);(d/f'{start:x}.txt').write_text(out);decoded=[]
 for ln in out.splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)$',ln)
  if m:
   va=int(m[1],16);raw=bytes.fromhex(m[2]);decoded.append((va,raw,m[3]));assert raw==read(va,len(raw));assert pins[va]==raw,(hex(va),pins.get(va),raw)
 assert decoded[0][0]==start and decoded[-1][0]+len(decoded[-1][1])==end
 assert all(a[0]+len(a[1])==b[0] for a,b in zip(decoded,decoded[1:]))
 rows.append({'start':hex(start),'end':hex(end),'fde':hex(fdes[start]['fde']),'bytes':end-start,'sha256':hashlib.sha256(read(start,end-start)).hexdigest(),'native_instructions':len(decoded),'all_retained_decoder_instruction_boundaries_and_bytes_match':True,'command':cmd})
(d/'audit.json').write_text(json.dumps({'target_sha256':hashlib.sha256(data).hexdigest(),'objdump_version':subprocess.check_output(['/opt/homebrew/opt/binutils/bin/gobjdump','--version'],text=True).splitlines()[0],'functions':rows},indent=2)+'\n');print('native functions',len(rows),'instructions',sum(r['native_instructions'] for r in rows))
