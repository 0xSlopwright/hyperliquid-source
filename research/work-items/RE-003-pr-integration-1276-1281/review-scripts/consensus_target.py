import csv,hashlib,json,pathlib,re,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'));import block_admission_path as t
out=b/'consensus-target';out.mkdir(exist_ok=True);image=t.load_image();result=t.analyse(image,mutate=False,vectors=300);files=t.render(result,image);comp=[]
for name,text in files.items():
 (out/name).write_text(text);old=(r/'research/work-items/RE-008-block-admission-94'/name).read_text()
 if name=='evidence.json':
  a=json.loads(old);a.pop('mutations');equal=a==json.loads(text)
 else:equal=old==text
 assert equal,name
 comp.append({'file':name,'equal':equal,'comparison':'excluding pre-existing mutation statistics'if name=='evidence.json'else 'byte-for-byte','sha256':hashlib.sha256(text.encode()).hexdigest()})
native=[]
for row in csv.DictReader((out/'functions.tsv').open(),delimiter='\t'):
 start,end=int(row['function'],16),int(row['end'],16);text=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(t.BINARY)],text=True);(out/f'{start:x}.txt').write_text(text);reference={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)};cursor=start;matched=0;unsupported=None
 def read(a,n):o=image.offset(a);return bytes(image.blob[o:o+n])
 while cursor<end:
  try:ins=t.decode(read,cursor)
  except t.EvidenceError as e:unsupported=str(e);break
  assert reference.get(cursor)==read(cursor,ins.size),(hex(cursor),ins.size)
  cursor=ins.next;matched+=1
 native.append({'start':hex(start),'end':hex(end),'matched_instruction_rows':matched,'decoded_prefix_end':hex(cursor),'complete_range':cursor==end,'unsupported':unsupported,'native_export_sha256':hashlib.sha256(text.encode()).hexdigest()})
report={'target_sha256':t.SHA256,'cases':456,'files':comp,'native':native,'matched_instruction_rows':sum(x['matched_instruction_rows']for x in native),'complete_ranges':sum(x['complete_range']for x in native),'mutations_rerun':False,'captured_execution':False,'scope':'Existing bounded Python row evaluator with documented stubs; native instruction partition check of declared ranges. No live cryptography, target execution or full CFG closure.'};(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print('456 cases reproduced;',len(comp),'files;',report['matched_instruction_rows'],'native rows; complete',report['complete_ranges'])
