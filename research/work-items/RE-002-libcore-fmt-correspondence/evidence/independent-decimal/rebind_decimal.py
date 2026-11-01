from pathlib import Path
import os,sys,json,struct,hashlib,time,gc
from peer_parse import *
OUT=Path(__file__).parent
TARGET=Path('/tmp/hl-libcore-fmt-correspondence-20261101/checkout/artifacts/node/94/hl-node')
TARGET_SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def physical(s):return {k:getattr(s,k)for k in ['st_dev','st_ino','st_size','st_mode','st_mtime_ns']}
def uleb(b,p):
 v=0;s=0
 while True:
  x=b[p];p+=1;v|=(x&127)<<s;s+=7
  if not x&128:return v,p
  assert s<=70

def sleb(b,p):
 v=0;s=0
 while True:
  x=b[p];p+=1;v|=(x&127)<<s;s+=7
  if not x&128:return (v-(1<<s)if x&64 else v),p
  assert s<=70

def encoded(b,p,enc,base):
 fmt=enc&15;start=p
 if fmt==0:v=struct.unpack_from('<Q',b,p)[0];p+=8
 elif fmt==1:v,p=uleb(b,p)
 elif fmt==2:v=struct.unpack_from('<H',b,p)[0];p+=2
 elif fmt==3:v=struct.unpack_from('<I',b,p)[0];p+=4
 elif fmt==4:v=struct.unpack_from('<Q',b,p)[0];p+=8
 elif fmt==9:v,p=sleb(b,p)
 elif fmt==10:v=struct.unpack_from('<h',b,p)[0];p+=2
 elif fmt==11:v=struct.unpack_from('<i',b,p)[0];p+=4
 elif fmt==12:v=struct.unpack_from('<q',b,p)[0];p+=8
 else:raise ValueError(('encoding',enc))
 app=enc&0x70
 if app==0x10:v+=base+start
 else:assert app==0
 return v,p

def selected_frames(t,wanted):
 sec=t.byname['.eh_frame'];b=t.section_bytes(sec);p=0;cies={};found={};total=0
 while p<len(b):
  start=p;n=struct.unpack_from('<I',b,p)[0];p+=4
  if n==0:break
  assert n!=0xffffffff and p+n<=len(b)
  end=p+n;link=struct.unpack_from('<I',b,p)[0];p+=4
  if link==0:
   ver=b[p];p+=1;z=b.index(b'\0',p);aug=b[p:z].decode('ascii');p=z+1;code,p=uleb(b,p);data,p=sleb(b,p)
   if ver==1:ret=b[p];p+=1
   else:ret,p=uleb(b,p)
   encoding=0
   if aug.startswith('z'):
    length,p=uleb(b,p);augend=p+length
    for c in aug[1:]:
     if c=='R':encoding=b[p];p+=1
     elif c=='L':p+=1
     elif c=='P':enc=b[p];p+=1;_,p=encoded(b,p,enc,sec['va'])
     else:raise ValueError(('CIE augmentation',aug))
    assert p==augend
   else:assert aug==''
   cies[start]={'encoding':encoding,'augmentation':aug,'raw':b[start:end],'file_offset':sec['offset']+start}
  else:
   cieoff=start+4-link;cie=cies[cieoff];address,p=encoded(b,p,cie['encoding'],sec['va']);length,p=encoded(b,p,cie['encoding']&15,sec['va']);total+=1
   if address in wanted:found[address]={'start':address,'end':address+length,'bytes':length,'FDE_file_offset':sec['offset']+start,'FDE_raw_sha256':sha(b[start:end]),'FDE_raw_bytes':len(b[start:end]),'CIE_file_offset':cie['file_offset'],'CIE_raw_sha256':sha(cie['raw']),'CIE_raw_bytes':len(cie['raw']),'CIE_encoding':cie['encoding'],'CIE_augmentation':cie['augmentation']}
  p=end
 assert set(found)==set(wanted)
 return found,total

def relocation_rows(e,section):
 result=[]
 for s in e.sh:
  if s['type']==4 and s['info']==section['index']:result.extend(e.relas(s))
 return result

def compare_body(e,t,section,target_va,count):
 official=e.section_bytes(section);assert len(official)==count
 target,off=t.virtual(target_va,count);rows=relocation_rows(e,section);mask=set();fields=[]
 for r in rows:
  assert r['type']in(2,9)and r['addend']==-4
  x=r['offset'];assert 0<=x and x+4<=count and not mask.intersection(range(x,x+4));mask.update(range(x,x+4));destination=target_va+x+4+struct.unpack_from('<i',target,x)[0]
  fields.append({**r,'field_width_bytes':4,'official_field_hex':official[x:x+4].hex(),'target_field_hex':target[x:x+4].hex(),'target_field_va':target_va+x,'target_file_offset':off+x,'target_RIP_destination':destination,'width_basis':'AMD64 ABI R_X86_64_PC32 or R_X86_64_GOTPCREL: signed 32-bit relocation field; P+4+disp for linked RIP-relative operands'})
 differences=[x for x,(a,b)in enumerate(zip(official,target))if a!=b];unexplained=[x for x in differences if x not in mask]
 assert not unexplained
 return {'official_section':section,'target_range':[target_va,target_va+count],'target_file_offset':off,'official_body_sha256':sha(official),'target_body_sha256':sha(target),'relocations':fields,'actual_relocation_bytes':len(mask),'nonRELA_bytes':count-len(mask),'all_nonRELA_equal':all(official[i]==target[i]for i in range(count)if i not in mask),'raw_differing_bytes':len(differences),'unexplained_difference_offsets':unexplained,'whole_body_raw_equal':official==target}

def main():
 start=time.monotonic();headroom=int(Path('/sys/fs/cgroup/memory.max').read_text())-int(Path('/sys/fs/cgroup/memory.current').read_text());assert headroom>1<<30
 ar_before=physical(AR.stat());member,archive=archive_member();ar_after=physical(AR.stat());assert ar_before==ar_after;e=ELF(member)
 with TARGET.open('rb')as f:
  before=physical(os.fstat(f.fileno()));data=f.read();after=physical(os.fstat(f.fileno()))
 assert before==after and len(data)==91774280 and sha(data)==TARGET_SHA
 t=ELF(data);primary,=[s for s in e.sh if '$u64$'in s['name']and '_fmt_inner' in s['name']and s['size']==444]
 decimal=compare_body(e,t,primary,0x1570470,444);assert len(decimal['relocations'])==9 and decimal['actual_relocation_bytes']==36 and decimal['nonRELA_bytes']==408 and decimal['raw_differing_bytes']==36
 # Resolve actual PC32 data fields and GOTPCREL slots from relocation rows.
 pcrel=[r for r in decimal['relocations']if r['type']==2];gots=[r for r in decimal['relocations']if r['type']==9];assert len(pcrel)==6 and len(gots)==3
 data_groups={}
 for r in pcrel:
  s=e.sh[r['symbol']['section_index']];key=(s['index'],r['symbol']['value']+r['addend']+4);data_groups.setdefault(key,[]).append(r)
 assert len(data_groups)==2
 pair_key,=[k for k in data_groups if e.sh[k[0]]['size']==200];location_key,=[k for k in data_groups if e.sh[k[0]]['size']==24]
 assert pair_key[1]==location_key[1]==0
 pair_refs=data_groups[pair_key];location_refs=data_groups[location_key]
 assert len({r['target_RIP_destination']for r in pair_refs})==1 and len({r['target_RIP_destination']for r in location_refs})==1
 pair_va=pair_refs[0]['target_RIP_destination'];loc_va=location_refs[0]['target_RIP_destination'];pair_target,pair_off=t.virtual(pair_va,200);pair_official=e.section_bytes(e.sh[pair_key[0]]);assert pair_target==pair_official==b''.join(f'{i:02d}'.encode()for i in range(100))
 location_target,loc_off=t.virtual(loc_va,24);location_official=e.section_bytes(e.sh[location_key[0]]);assert location_target==location_official;pointer,length,line,column=struct.unpack('<QQII',location_target);assert pointer==0 and length==75 and line==599 and column==5
 path_rela,=relocation_rows(e,e.sh[location_key[0]]);assert path_rela['offset']==0 and path_rela['type']==1;path_section=e.sh[path_rela['symbol']['section_index']];path_offset=path_rela['symbol']['value']+path_rela['addend'];path_official=e.section_bytes(path_section)[path_offset:path_offset+length]
 got_slots={r['target_RIP_destination']for r in gots};assert len(got_slots)==1;got=next(iter(got_slots));assert got==0x576dfc8
 required={loc_va,got};actual={}
 for s in t.sh:
  if s['type']==4:
   for rel in t.relas(s):
    if rel['offset']in required:
     assert rel['offset']not in actual;actual[rel['offset']]=rel
 assert set(actual)==required
 for rel in actual.values():assert rel['type']==8 and rel['symbol_index']==0
 path_va=actual[loc_va]['addend'];path_target,path_file_off=t.virtual(path_va,length);assert path_target==path_official;assert path_target.decode('ascii')=='/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/num.rs'
 guard_va=actual[got]['addend'];assert guard_va==0x157b64f;symbol_keys={(r['symbol']['section_index'],r['symbol']['value'],r['symbol']['size'])for r in gots};assert len(symbol_keys)==1;guard_idx,guard_sym_offset,guard_size=next(iter(symbol_keys));assert guard_sym_offset==0 and guard_size==61
 guard=compare_body(e,t,e.sh[guard_idx],guard_va,guard_size);assert len(guard['relocations'])==3 and guard['actual_relocation_bytes']==12 and guard['nonRELA_bytes']==49 and guard['raw_differing_bytes']==12
 frames,frame_count=selected_frames(t,{0x1570470,guard_va});assert frames[0x1570470]['bytes']==444 and frames[guard_va]['bytes']==61
 guard['further_callees_data_and_behavior_qualified']=False;guard['context_only_not_in_1456_primary_denominator']=True
 result={'schema':'independent-libcore-decimal-data-callee-correspondence-v1','status':'PASS_STATIC_FACTS_ONLY','archive':archive,'official_archive_physical_before':ar_before,'official_archive_physical_after':ar_after,'target':{'path':str(TARGET),'bytes':len(data),'sha256':sha(data),'physical_before':before,'physical_after':after,'single_immutable_object_for_all_target_facts':True},'decimal':decimal,'pairs':{'target_VA':pair_va,'target_file_offset':pair_off,'official_section_index':pair_key[0],'bytes':200,'raw_equal':True,'sha256':sha(pair_target)},'location':{'target_VA':loc_va,'target_file_offset':loc_off,'official_section_index':location_key[0],'bytes':24,'raw_equal':True,'sha256':sha(location_target),'raw_pointer':pointer,'path_length':length,'line':line,'column':column,'official_pointer_RELA':path_rela,'target_pointer_RELATIVE':actual[loc_va]},'path':{'target_VA':path_va,'target_file_offset':path_file_off,'official_section_index':path_section['index'],'official_section_relative_offset':path_offset,'bytes':length,'raw_equal':True,'sha256':sha(path_target),'ASCII':path_target.decode()},'guard_GOT_slot':{'VA':got,'RELATIVE':actual[got]},'guard61_context':guard,'target_FDEs':frames,'target_FDEs_scanned':frame_count,'scope_denominators':{'decimal_primary_bytes':444,'decimal_excluded_actual_RELA_bytes':36,'decimal_compared_nonRELA_bytes':408,'data_raw_bytes':299,'guard_context_bytes':61,'guard_context_actual_RELA_bytes':12,'guard_context_nonRELA_bytes':49,'author_main1456_qualified_here_in_full':False},'headroom_before':headroom,'seconds':time.monotonic()-start,'limitations':['Compatible official artifact correspondence only; no unique original compiler/source/build flags/crate/type/ABI identity.','No Rust build, target execution, emulator, inference-source reading/copying, Git/PR/CI operations.','No source reconstruction or component/gate completion claim.','Guard61 is separate context; its further data, callees and behavior remain unqualified.','This independent peer does not qualify the other390+622 primary spans or their combined1456 denominator.']}
 (OUT/'INDEPENDENT-DECIMAL-DATA-CALLEE-REVIEW.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'status':result['status'],'seconds':result['seconds'],'decimal_nonRELA':decimal['nonRELA_bytes'],'guard_context_nonRELA':guard['nonRELA_bytes'],'pairs_va':hex(pair_va),'location_va':hex(loc_va),'path_va':hex(path_va),'FDEs_scanned':frame_count,'receipt_sha256':sha((OUT/'INDEPENDENT-DECIMAL-DATA-CALLEE-REVIEW.json').read_bytes())}))
 del t,data,e,member;gc.collect()
if __name__=='__main__':main()
