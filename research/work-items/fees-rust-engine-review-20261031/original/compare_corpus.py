from pathlib import Path
import sys,struct,json,subprocess,csv,collections
w=Path.cwd();d=w.parent/'fees-engine-1150-review';sys.path.insert(0,str(w/'tools'))
import fees_trade_fee as trade,fees_fill_ledger as ledger,fees_rate_grid as grid,fees_unit_conversion as unit,fees_fee_scale as scale
rows=[];skipped=collections.Counter();counts=collections.Counter()
def f(x):return str(struct.unpack('<Q',struct.pack('<d',x))[0])
def add(kind,i,toks,want):rows.append((kind,i,' '.join(map(str,toks)),want));counts[kind]+=1
def recipient(tag,amount,address):return f'1 {amount} {address.hex()}' if tag else '0 - -'
def enums(records,mapping):return ','.join(mapping[x] for x in records)
old=list(csv.DictReader((w/'research/work-items/fees-trade-fee-94/vectors.tsv').open(),delimiter='\t'))
for i,(v,pin) in enumerate(zip(trade.all_vectors(),old)):
 assert trade.digest_of(v)==pin['input_digest'];z=trade.model(v,(1.0,0.1))
 if z['exit']!='ok':skipped['trade:'+z['exit']]+=1;continue
 c=v['ctx'];tok=[v['side'],*map(f,c['base']),f(c['discount']),f(c['share']),f(c['f90']),f(c['f98']),len(c['table'])]
 for a,b in c['table']:tok += [f(a),f(b)]
 entries=v['entries'] if c['entries_on'] else {};tok+=[len(entries)]
 for owner,e in entries.items():
  values=e['values'][:e.get('claim',len(e['values']))] if e['values'] or e.get('rooted') else []
  tok += [owner.hex(),e['tag'],*map(f,e['rates']),e['d'],int(bool(e['d']))]
  if e['d']:tok+=list(map(f,e['over']))
  tok += [f(e['key']),f(e['w70']),e['flag'],int(bool(e['flag']&1))]
  if e['flag']&1:tok += [e['referrer'].hex()]
  tok += [len(values),*values]
 tok += [v['user'].hex(),v['ntli'],int(bool(v.get('b4c',v.get('tk')))),int(bool(v['flag'])),int(v['builder'] is not None)]
 if v['builder']:tok += [v['builder'][0],v['builder'][1].hex()]
 if v['side']=='perp':tok += [int(bool(v['full'])),f(v['x']),int(v['dep_tag']==3),int(bool(v['trial']))]
 else:tok += [v['cat'],f(v['weight']),int(bool(v['al'])),int(bool(v['bpl']))]
 want=f"{recipient(z['tag'],z['ref'],z['referrer'])} {recipient(z['btag'],z['bamt'],z['baddr'])} {z['gross']} {z['rebate']} {z['extra']}"
 if v['side']=='perp':want+=f" {z['deployer']} {z['protocol']}"
 want+=' |'+enums(z['records'],{trade.LOC_SUM:'W',trade.LOC_TOTAL:'G',trade.LOC_NET_B:'P'})
 add('trade',i,tok,want)
for i,v in enumerate(grid.point_vectors()):
 p=grid.point_model(v);tok=['grid',*[f(v[k]) for k in ['L','r','k','a','c','m']],v['n']]
 want='panic' if p['exit']=='panic' else ' '.join([p['exit']]+[str(p.get(k,'-')) for k in ['d','keep','a','net','f','fk','whole']])+' |'+enums(p['recorded'],{grid.LOC_NTLI:'S',grid.LOC_SUM:'U'})
 add('grid',i,tok,want)
for i,(group,v) in enumerate(unit.all_vectors()):
 p=unit.model(v)
 if v['asset']//10000!=v['dex'] or v['asset']%10000>=v['assets_len']:skipped['unit:asset admission outside API']+=1;continue
 if v['ntli']<0:want='error:NegativeNotional'
 elif 'scaled' in p:want=f"{p['scaled']} {p['unscaled']}"
 elif p['status']==f"panic:{unit.LOCATIONS['abs']:#x}":want='error:RateProductAbsoluteOverflow'
 else:raise ValueError(p)
 add('unit',i,['unit',v['ntli'],f(v['rate']),v['trial'],f(v['trial_m']),int(not v['flag29'])],want)
for i,v in enumerate(scale.all_vectors()):
 if 'scale' not in v:skipped['scale:other packet behavior']+=1;continue
 add('scale',i,['scale',f(v['scale'])],str(not(v['scale']<0 or v['scale']>3)).lower())
old=list(csv.DictReader((w/'research/work-items/fees-fill-ledger-94/vectors.tsv').open(),delimiter='\t'))
for i,(v,pin) in enumerate(zip(ledger.all_vectors(),old)):
 assert ledger.digest_of(v)==pin['input_digest']
 if any(not t for t in v['tables'].values()) or any(not t for t in v['builders'].values()):skipped['ledger:preexisting empty bucket not seedable by API']+=1;continue
 tables,builders,events,order=ledger.apply_model(v);tok=['ledger',sum(map(len,v['tables'].values()))]
 for a,tab in v['tables'].items():
  for k,ws in tab.items():tok += [a.hex(),k,*ws]
 tok += [sum(map(len,v['builders'].values()))]
 for a,tab in v['builders'].items():
  for k,n in tab.items():tok += [a.hex(),k,n]
 r=v['rec'];tok += [v['user'].hex(),v['key'],r['tag'],r['ref'],r['ref_addr'].hex(),r['btag'],r['bamt'],r['b_addr'].hex(),r['gross'],r['rebate'],r['extra']]
 vals=';'.join(f'{a.hex()}:{k}:'+','.join(map(str,ws)) for a,tab in sorted(tables.items()) for k,ws in sorted(tab.items()))
 bs=';'.join(f'{a.hex()}:{k}:{n}' for a,tab in sorted(builders.items()) for k,n in sorted(tab.items()))
 creates=len(tables)-len(v['tables'])+sum(map(len,tables.values()))-sum(map(len,v['tables'].values()))+len(builders)-len(v['builders'])+sum(map(len,builders.values()))-sum(map(len,v['builders'].values()))
 add('ledger',i,tok,f'{vals} |{bs} |{len(events)} |{creates}')
(d/'corpus-input.txt').write_text('\n'.join(r[2] for r in rows)+'\n');(d/'corpus-expected.txt').write_text('\n'.join(r[3] for r in rows)+'\n')
p=subprocess.run([str(d/'compare-driver')],input='\n'.join(r[2] for r in rows)+'\n',text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);(d/'corpus-actual.txt').write_text(p.stdout);(d/'corpus-stderr.txt').write_text(p.stderr)
actual=p.stdout.splitlines();bad=[{'kind':r[0],'index':r[1],'input':r[2],'expected':r[3],'actual':got} for r,got in zip(rows,actual) if r[3]!=got]
report={'counts':dict(counts),'skipped':dict(skipped),'driver_returncode':p.returncode,'actual_rows':len(actual),'expected_rows':len(rows),'mismatches':bad};(d/'corpus-comparison.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({**report,'mismatches':bad[:3]},indent=2));assert p.returncode==0 and len(actual)==len(rows)
