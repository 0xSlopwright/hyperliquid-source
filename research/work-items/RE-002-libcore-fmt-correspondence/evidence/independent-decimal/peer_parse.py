from pathlib import Path
import hashlib,struct
sha=lambda d:hashlib.sha256(d).hexdigest()
AR=Path('/tmp/hl-rem-rust-1.94.1-20261031/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib')
AR_SHA='ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
MEMBER='core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o'
def archive_member():
 a=AR.read_bytes();assert sha(a)==AR_SHA and a[:8]==b'!<arch>\n';pos=8;names=b'';found=[]
 while pos<len(a):
  h=a[pos:pos+60];assert len(h)==60 and h[58:60]==b'`\n';n=int(h[48:58]);start=pos+60;body=a[start:start+n];assert len(body)==n;name=h[:16].decode('ascii').rstrip()
  if name=='//':names=body
  elif name.startswith('/')and name[1:].isdigit():name=names[int(name[1:]):].split(b'/\n',1)[0].decode()
  else:name=name.rstrip('/')
  if name==MEMBER:found.append((body,{'archive':str(AR),'archive_sha256':sha(a),'archive_bytes':len(a),'member_name':name,'member_header_offset':pos,'member_data_offset':start,'member_bytes':n,'member_sha256':sha(body)}))
  pos=start+n+(n%2)
 assert pos==len(a)and len(found)==1;return found[0]
def cstr(b,n):return b[n:b.index(b'\0',n)].decode('ascii')
class ELF:
 def __init__(self,b):
  self.b=b;assert b[:6]==b'\x7fELF\x02\x01';assert struct.unpack_from('<H',b,18)[0]==62
  self.typ=struct.unpack_from('<H',b,16)[0];self.shoff=struct.unpack_from('<Q',b,40)[0];es,n,ss=struct.unpack_from('<HHH',b,58);assert es==64 and n and ss<n
  self.sh=[]
  for i in range(n):
   vals=struct.unpack_from('<IIQQQQIIQQ',b,self.shoff+64*i);self.sh.append(dict(zip(['name_index','type','flags','va','offset','size','link','info','alignment','entry_size'],vals),index=i,header_file_offset=self.shoff+64*i))
  names=self.section_bytes(self.sh[ss]);
  for s in self.sh:s['name']=cstr(names,s['name_index'])
  self.byname={s['name']:s for s in self.sh}
  self.symtabs={}
  for s in self.sh:
   if s['type']in(2,11):
    assert s['entry_size']==24;strings=self.section_bytes(self.sh[s['link']]);syms=[]
    for off in range(0,s['size'],24):
     name,info,other,idx,value,size=struct.unpack_from('<IBBHQQ',b,s['offset']+off);syms.append({'name':cstr(strings,name),'info':info,'other':other,'section_index':idx,'value':value,'size':size,'file_offset':s['offset']+off})
    self.symtabs[s['index']]=syms
  self.ph=[]
  po=struct.unpack_from('<Q',b,32)[0];pe,pn=struct.unpack_from('<HH',b,54)
  if pn:
   assert pe==56
   for i in range(pn):self.ph.append(dict(zip(['type','flags','offset','va','pa','file_size','memory_size','alignment'],struct.unpack_from('<IIQQQQQQ',b,po+56*i))))
 def section_bytes(self,s):
  assert s['type']!=8;out=self.b[s['offset']:s['offset']+s['size']];assert len(out)==s['size'];return out
 def virtual(self,va,n):
  matches=[p for p in self.ph if p['type']==1 and p['va']<=va and va+n<=p['va']+p['file_size']];assert len(matches)==1
  p=matches[0];off=p['offset']+va-p['va'];return self.b[off:off+n],off
 def relas(self,s):
  assert s['type']==4 and s['entry_size']==24
  for off in range(0,s['size'],24):
   ro,ri,ad=struct.unpack_from('<QQq',self.b,s['offset']+off);idx=ri>>32;row={'offset':ro,'type':ri&0xffffffff,'symbol_index':idx,'addend':ad,'record_file_offset':s['offset']+off,'relocation_section_index':s['index'],'relocation_section':s['name'],'target_section_index':s['info']}
   if s['link']in self.symtabs:row['symbol']=self.symtabs[s['link']][idx]
   yield row
