import hashlib,json,pathlib,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'));import block_admission_path as t
out=b/'consensus-client';(out/'src').mkdir(parents=True,exist_ok=True)
(out/'Cargo.toml').write_text('[package]\nname="consensus-review-client"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nnode94-consensus-admission={path='+json.dumps(str(r/'src/node94-consensus-admission'))+'}\n')
def arr(bs):return '['+','.join(str(n)for n in bs)+']'
def a(v):return 'ValidatorAddress('+arr(t.addr_bytes(v))+')'
def bh(v):return 'BlockHash('+arr(t.word_bytes(v))+')'
def th(v):return 'TransactionHash('+arr(t.word_bytes(v))+')'
def vec(xs):return 'vec!['+','.join(xs)+']'
def sig(s,who,digest):
 recovered=t.recovered(s,who,digest);raw=bytearray(72)
 if recovered is None:raw[20]=1
 else:raw[:20]=recovered
 return 'SignatureBytes('+arr(raw)+')'
def qc(q):
 return 'Qc{votes:'+vec('QcVote{signer:'+a(who)+',signature:'+sig(s,who,t.digest_qc(q))+'}'for who,s in q.votes)+f',hardfork:Hardfork{{version:{q.version}u64,start_round:Round({q.start}u64)}},round:Round({q.round}u64),block_hash:'+bh(q.hash)+'}'
def tc(c):return 'Tc{round:Round('+str(c.round)+'u64),votes:'+vec('TimeoutVote{qc:'+qc(v.qc)+f',round:Round({v.round}u64),signer:'+a(v.signer)+',signature:'+sig(v.sig,v.signer,t.digest_vote(v))+'}'for v in c.votes)+'}'
def block(v):return 'SignedBlock{transaction_hashes:'+vec(th(n)for n in v.hashes)+',qc:'+qc(v.qc)+',tc:'+('None'if v.tc is None else 'Some('+tc(v.tc)+')')+f',round:Round({v.round}u64),proposer:'+a(v.proposer)+',signature:'+sig(v.sig,v.proposer,t.digest_block(v))+'}'
header='''use std::collections::{BTreeMap,BTreeSet};
use node94_consensus_admission::*;
struct Auth { leader:ValidatorAddress, error:Option<u8> }
fn recover(s:&SignatureBytes)->Result<ValidatorAddress,AuthenticationError>{if s.0[20]!=0 {Err(AuthenticationError::BlockSignature)}else{let mut a=[0;20];a.copy_from_slice(&s.0[..20]);Ok(ValidatorAddress(a))}}
impl AdmissionAuthenticator for Auth {
 fn expected_proposer(&self,_:Round,_:&[ValidatorAddress])->Result<ValidatorAddress,AuthenticationError>{match self.error{Some(n)=>Err(AuthenticationError::proposer(Some(n))),None=>Ok(self.leader)}}
 fn recover_qc_vote_signer(&self,_:&Qc,s:&SignatureBytes)->Result<ValidatorAddress,AuthenticationError>{recover(s)}
 fn recover_timeout_vote_signer(&self,_:&Qc,_:Round,s:&SignatureBytes)->Result<ValidatorAddress,AuthenticationError>{recover(s)}
 fn recover_block_signer(&self,b:&SignedBlock)->Result<ValidatorAddress,AuthenticationError>{recover(&b.signature)}
}
fn status(r:&Result<RegistrationOutcome,VerificationFailure>)->String{match r{Ok(_)=>"ok".into(),Err(VerificationFailure::Rejected(e))=>format!("err:{}",e.target_tag().unwrap()),Err(VerificationFailure::Fatal(FatalAdmissionError::StakeOverflow))=>"panic:stake overflow".into(),Err(VerificationFailure::Fatal(FatalAdmissionError::NewerHardforkWithQuorum))=>"panic:newer hardfork".into()}}
'''
cases=t.named_cases()+t.vector_cases(300);assert len(cases)==456;functions=[];fixtures=[]
for i,c in enumerate(cases):
 label,w=t.spec_run(c);res=w['result'];expected='ok'if res[0]=='ok'else 'err:'+str(res[1])if res[0]=='err'else 'panic:'+res[1]
 lines=[f'fn case_{i}() {{',f'let name={json.dumps(c.name)};']
 snapshots='BTreeMap::from(['+','.join(f'(Round({rd}u64),StakeSnapshot{{stakes:BTreeMap::from(['+','.join('('+a(k)+f',{v}u64)'for k,v in stakes.items())+'])})'for rd,stakes in c.stakes.items())+'])'
 lines+=['let history=StakeHistory{'+f'base_round:Round({c.base}u64),hardfork:Hardfork{{version:{c.version}u64,start_round:Round({c.start}u64)}},estimated_valid_until:Round({c.valid_until}u64),snapshots:'+snapshots+'};','let auth=Auth{leader:'+a(c.leader)+',error:'+('None'if c.leader_error is None else f'Some({c.leader_error-t.NONE_TAG}u8)')+'};',f'let mut state=ConsensusState::new(Round({c.committed}u64));']
 lines+=['state.transactions=BTreeMap::from(['+','.join('('+th(n)+',TransactionRecord::Known)'for n in c.txs)+']);','state.blocks=BTreeMap::from(['+','.join('('+bh(v.key)+',RegisteredBlock{block:'+block(v)+'})'for v in c.stored)+']);','state.requested_blocks=BTreeSet::from(['+','.join(bh(n)for n in c.rows)+']);',f'state.forwarding_disabled={str(c.forward_off).lower()};state.forward_channel.closed={str(c.closed).lower()};state.forward_channel.waker_registered={str(c.waker).lower()};','let before=state.clone();','let block='+block(c.block)+';',f'let now=EventTime{{date:{c.now[0]}u64,seconds:{c.now[1]}u64,nanoseconds:{c.now[2]}u64}};','let result=admit_and_register(&mut state,&history,&auth,'+bh(c.block.key)+',&block,now);',f'assert_eq!(status(&result),{json.dumps(expected)},"{{}}",name);']
 lines+=['assert_eq!(state.blocks.keys().copied().collect::<Vec<_>>(),'+vec(bh(n)for n in w['blocks'])+',"blocks {}",name);','assert_eq!(state.transactions.keys().copied().collect::<Vec<_>>(),'+vec(th(n)for n in sorted(w['txs']))+',"txs {}",name);','assert_eq!(state.requested_blocks.iter().copied().collect::<Vec<_>>(),'+vec(bh(n)for n in w['rows'])+',"requests {}",name);',f'assert_eq!(state.forward_channel.wake_count,{w["wakes"]},"wakes {{}}",name);']
 if res[0]=='ok':
  unknown=[n for n in c.block.hashes if n not in c.txs];lines+=['let success=result.unwrap();','assert_eq!(success.unknown_transactions,'+vec(th(n)for n in unknown)+',"unknown order {}",name);',f'assert_eq!(success.request_removed,{str(c.block.key in c.rows).lower()},"request {{}}",name);',f'assert_eq!(state.forward_channel.records.len(),{int(not c.forward_off and not c.closed)},"queue {{}}",name);']
  for n in set(unknown):lines+=['assert_eq!(state.transactions.get(&'+th(n)+'),Some(&TransactionRecord::UnknownPlaceholder{observed_at:now}),"placeholder {}",name);']
 else:lines+=['assert_eq!(state,before,"failure atomicity {}",name);']
 lines+=['}'];functions.append('\n'.join(lines));fixtures.append({'case':c.name,'expected':expected,'scope':'Result class/tag, block/transaction/request keys, unknown order, placeholder event time, forwarding count/wakes, failure atomicity. Error payload and logging/allocator/channel internals excluded.'})
source=header+'\n'+'\n'.join(functions)+'\nfn main(){\n'+'\n'.join(f'case_{i}();'for i in range(len(cases)))+'\nprintln!("456 retained admission cases agree");}\n';(out/'src/main.rs').write_text(source);(out/'fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
results=[]
for mode in ['debug','release']:
 cmd=['cargo','+1.94.1','run','--offline','--manifest-path',str(out/'Cargo.toml')]+(['--release']if mode=='release'else[]);log=out/(mode+'.log');start=time.monotonic()
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,stdout=h,stderr=subprocess.STDOUT)
 results.append({'mode':mode,'returncode':p.returncode,'seconds':round(time.monotonic()-start,2),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()});print(mode,p.returncode,flush=True)
report={'cases':len(cases),'profiles':results,'client_sha256':hashlib.sha256(source.encode()).hexdigest(),'fixtures_sha256':hashlib.sha256((out/'fixtures.json').read_bytes()).hexdigest(),'limits':'Client compares the Rust reconstruction with the retained static spec and its authentication fixtures, not live cryptography or captured execution. Authentication stub supplies previously derived recovered addresses. Native row evaluator separately establishes bounded packet agreement. Logging, allocator/pointer/channel internals and error payloads excluded.'};(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(any(x['returncode']for x in results))
