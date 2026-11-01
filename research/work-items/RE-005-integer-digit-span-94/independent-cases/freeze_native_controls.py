"""Freeze actual tiny native anchors only; no target execution or decoding."""
from pathlib import Path
import hashlib,json
BASE=Path('/tmp/hl-primitive-value-intake-20261031/actual-selected-metadata')
OUT=Path(__file__).resolve().parent
raws={0x1570470:(BASE/'0x1570470.bin').read_bytes(),0x14f7660:(BASE/'0x14f7660.bin').read_bytes()}
controls=[
 ('decimal-small-route-threshold999',0x1570470,0x1570487,'e8030000','e7030000','999 must remain a three-digit tail, not enter a padded four-digit group'),
 ('decimal-reciprocal-M-minus-one',0x1570470,0x157049a,'4b598638d6c56d34','4a598638d6c56d34','At10000, floor(10000*(M-1)/2^75)=0 rather than1'),
 ('decimal-quotient-shift10',0x1570470,0x15704ca,'0b','0a','Changes the actual quotient expression, not a rendered operand only'),
 ('decimal-remainder-multiplier10001',0x1570470,0x15704cd,'10270000','11270000','Quotient/remainder identity for10000 no longer follows'),
 ('decimal-pair-reciprocal5242',0x1570470,0x15704da,'7b140000','7a140000','Remainder100 has floor(5242*100/2^19)=0 instead of1'),
 ('decimal-first-group-store-minus-four',0x1570470,0x15704ef,'fd','fc','Actual first group store shifts into preserved prefix; n1000 witness'),
 ('decimal-group-offset-step-minus-five',0x1570470,0x157054f,'fc','fb','Eight-digit boundary loses contiguous four-byte-group invariant'),
 ('decimal-store-base-step-minus-five',0x1570470,0x1570553,'fc','fb','Subsequent group store coordinates no longer follow declared suffix'),
 ('decimal-repeat-threshold9999998',0x1570470,0x1570557,'7f969800','7e969800','9999999 repeats another group and violates minimal digit span'),
 ('decimal-repeat-JAE-not-JA',0x1570470,0x157055f,'87','83','Equality9999999 must not repeat'),
 ('decimal-tail-threshold8',0x1570470,0x157056a,'09','08','9 must remain one digit, not zero-padded pair'),
 ('decimal-tail-reciprocal5242',0x1570470,0x1570584,'7b140000','7a140000','At100, floor(5242*floor(100/4)/2^17)=0 instead of1'),
 ('decimal-tail-postshift16',0x1570470,0x157058b,'11','10','Changes actual hundreds expression'),
 ('decimal-tail-first-store-minus-three',0x1570470,0x15705a6,'fe','fd','Two-digit10 changes an untouched prefix byte and misses an output byte'),
 ('decimal-zero-JNE-not-JE',0x1570470,0x15705c9,'74','75','Zero must store one digit0 and return19'),
 ('decimal-final-digit-mask7',0x1570470,0x15705da,'0f','07','Single digit9 would select1 rather than9'),
 ('decimal-final-pair-first-not-second',0x1570470,0x15705e6,'01','00','Single digit7 must select pair07 second byte7'),
 ('selector-bit24-not25',0x14f7660,0x14f7671,'02','01','Literal flags25/24 become distinguishable; field is actual lowDWORD'),
 ('selector-lower-priority-JE-not-JNE',0x14f7660,0x14f7672,'75','74','Both flags set must choose lower branch first'),
 ('selector-bit27-not26',0x14f7660,0x14f7678,'04','08','Literal flags26/27 become distinguishable'),
 ('selector-decimal-capacity19',0x14f7660,0x14f768a,'14','13','Breaks qualified capacity20 core bridge, not claimed original short-capacity behavior'),
 ('selector-decimal-add-not-sub-start',0x14f7660,0x14f7694,'29','01','Forwarded digit length must be20-start, not20+start'),
 ('selector-decimal-base-plus3',0x14f7660,0x14f769d,'04','03','Forwarded digits pointer must use actualSP+4+start'),
 ('selector-lower-alphabet-plus1',0x14f7660,0x14f76be,'5e','5f','Actual table RIP target changes; n0 lower table lookup witness'),
 ('selector-lower-nibble-mask7',0x14f7660,0x14f76d4,'0f','07','Nibble15 must selectf, not7'),
 ('selector-lower-shift3',0x14f7660,0x14f76d8,'04','03','Value16 must produce digit span10, not20'),
 ('selector-lower-store-plus20',0x14f7660,0x14f76e1,'13','14','Physical hex suffix endsB+16, notB+17'),
 ('selector-lower-JAE-not-JA',0x14f7660,0x14f76ec,'77','73','Value15 needs one digitf, not a leading0f'),
 ('selector-prefix-length1',0x14f7660,0x14f7731,'02','01','Raw prefix argument length changes; no rendered-prefix inference'),
]
records=[]
for label,start,address,before,after,witness in controls:
 old,new=bytes.fromhex(before),bytes.fromhex(after);at=address-start
 if len(old)!=len(new) or raws[start][at:at+len(old)]!=old:raise ValueError('Actual native mutation anchor mismatch: '+label)
 records.append({'label':label,'body_start':start,'address':address,'before':before,'after':after,'witness':witness,'execution':'Fresh tiny native decode/static validation after producer API freeze; never execute the captured bytes','claim':'Counterfactual checker/operand proof control; not a target bug or mutation-derived original runtime claim'})
report={'schema':'independent-digit-native-control-design-v1','status':'ANCHORS FROZEN; actual validation not run until collector API/proof freeze','controls':records,'control_count':len(records),'primary_converter_controls':sum(v['body_start']==0x1570470 for v in records),'separate_selector_controls':sum(v['body_start']==0x14f7660 for v in records),'additional_listing_controls':['Authentic raw span plus a changed rendered byte','Authentic raw span plus wrong first coordinate','Omitted real padding row must violate complete coverage','Authentic raw branch bytes plus forged rendered target prose must not change raw parameters/CFG/store/mathematics; arbitrary mnemonic prose is outside semantic authority and independent rejection is not claimed.'],'additional_table_controls':[{'table':'decimal-pairs','offset':1,'before':'30','after':'31','witness':'Zero digit changes from0 to1; table is captured evidence, not regenerated implementation input'},{'table':'nibble-table-25','offset':10,'before':'61','after':'41','witness':'Lowercase10 must supplya, notA'},{'table':'nibble-table-26','offset':10,'before':'41','after':'61','witness':'Uppercase10 must supplyA, nota'},{'table':'base16-prefix','offset':1,'before':'78','after':'58','witness':'Raw argument must containx; no downstream rendering claim'}],'excluded_behavior':['Original short capacities and guard-call helper157b64f','Opaque downstream15723b0 body/return effects','Captured execution/PC-register interpreter','Private ABI/nominal formatter types/complete G/rendered output/gates'],'listing_authority_clarification':'Frozen STATIC-API b58917b1 clarified after pre-API control design: byte/address/coverage bind; raw operand/CFG proof is authoritative, production native prose comes only from owned GNU output.','new_rust_implementation_read':False,'compiler_or_native_tools_launched':False,'target_files_copied':False}
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode();(OUT/'NATIVE-CONTROL-DESIGN.json').write_bytes(raw)
print(json.dumps({'controls':len(records),'sha256':hashlib.sha256(raw).hexdigest(),'path':str(OUT/'NATIVE-CONTROL-DESIGN.json')},sort_keys=True))
