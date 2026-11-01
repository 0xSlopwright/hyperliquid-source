use node94_fees::*;
use std::io::{self, BufRead};
struct Input<'a>(std::str::SplitWhitespace<'a>);
impl<'a> Input<'a> {
 fn s(&mut self)-> &'a str {self.0.next().unwrap()}
 fn u(&mut self)->u64 {self.s().parse().unwrap()}
 fn i(&mut self)->i64 {self.s().parse().unwrap()}
 fn b(&mut self)->bool {self.u()!=0}
 fn f(&mut self)->f64 {f64::from_bits(self.u())}
 fn a(&mut self)->Address {let s=self.s();let mut a=[0;20];for(i,x)in a.iter_mut().enumerate(){*x=u8::from_str_radix(&s[2*i..2*i+2],16).unwrap();}Address(a)}
 fn rates(&mut self)->FeeRates {FeeRates::new(MarketRates::new(self.f(),self.f()),MarketRates::new(self.f(),self.f()))}
}
fn addr(a:Address)->String {a.0.iter().map(|v|format!("{v:02x}")).collect()}
fn rec(r:Option<FeeRecipient>)->String {r.map_or_else(||"0 - -".into(),|r|format!("1 {} {}",r.amount,addr(r.address)))}
fn events(e:&[ArithmeticEvent])->String {e.iter().map(|x|match x {ArithmeticEvent::WindowSumSaturated{..}=>"W",ArithmeticEvent::GrossWithBuilderSaturated=>"G",ArithmeticEvent::ProtocolSplitSaturated=>"P",ArithmeticEvent::RateGridSignedSaturated=>"S",ArithmeticEvent::RateGridUnsignedSaturated=>"U",_=>"L"}).collect::<Vec<_>>().join(",")}
fn run(line:&str)->String {
 let mut p=Input(line.split_whitespace());let kind=p.s();
 let out=match kind {
 "perp"|"spot"=>{
  let default_rates=p.rates();let low_volume_discount=p.f();let flagged_referrer_share=p.f();let multiplier_90=p.f();let multiplier_98=p.f();let n=p.u();let mut tiers=vec![];for _ in 0..n {tiers.push(VolumeTier{minimum_anchor:p.f(),share:p.f()});}
  let mut e=FeeEngine::new(FeeSchedule{default_rates,volume_tiers:tiers,low_volume_discount,flagged_referrer_share,multiplier_90,multiplier_98}).unwrap();
  let n=p.u();for _ in 0..n {let owner=p.a();let row_tag=p.u()as u32;let current=p.rates();let previous_tag=p.u()as u32;let previous=if p.b(){Some(p.rates())}else{None};let volume_anchor=p.f();let carried_weight=p.f();let binding_flags=p.u()as u8;let referrer=if p.b(){Some(p.a())}else{None};let n=p.u();let mut volume_words=vec![];for _ in 0..n{volume_words.push(p.u());}e.insert_profile(owner,FeeProfile{row_tag,row:RateRow{current,previous,previous_tag,volume_anchor,carried_weight},binding_flags,referrer,volume_words});}
  let payer=p.a();let notional=p.i();let role=if p.b(){LiquidityRole::Maker}else{LiquidityRole::Taker};let flagged=p.b();let builder=if p.b(){Some(BuilderFee{rate_units:p.u(),address:p.a()})}else{None};
  if kind=="perp" {let asset_scale=if p.b(){AssetFeeScale::Full}else{AssetFeeScale::Tenth};let deployer_scale=p.f();let deployer_deleted=p.b();let trial=p.b();let c=e.compute_perp(PerpFill{payer,notional,role,flagged,builder,asset_scale,deployer_scale,deployer_deleted,trial}).unwrap();let r=c.value;format!("{} {} {} {} {} {} {} |{}",rec(r.referrer),rec(r.builder),r.gross,r.rebate,r.extra,r.deployer,r.protocol,events(&c.events))}
  else {let category=SpotCategory(p.u()as u8);let category_weight=p.f();let aligned_quote=p.b();let quote_leg=p.b();let c=e.compute_spot(SpotFill{payer,notional,role,flagged,builder,category,category_weight,aligned_quote,quote_leg}).unwrap();let r=c.value;format!("{} {} {} {} {} |{}",rec(r.referrer),rec(r.builder),r.gross,r.rebate,r.extra,events(&c.events))}
 },
 "unit"=>{let input=VolumeConversionInput{notional:p.i(),rate:p.f(),trial:p.b(),trial_multiplier:p.f(),tenth_scale:p.b()};match volume_conversion(input){Ok(v)=>format!("{} {}",v.value.scaled,v.value.unscaled),Err(e)=>format!("error:{e:?}")}},
 "grid"=>{let input=RateGridInput{lowest_cross_rate:p.f(),referral_share:p.f(),max_keep:p.f(),lowest_add_rate:p.f(),first_cross_rate:p.f(),scale:p.f(),notional:p.u()};match validate_rate_grid_point(input){Err(_)=>"panic".into(),Ok(v)=>{let (tag,r)=match v.value {RateGridOutcome::Pass(r)=>("ok",r),RateGridOutcome::RejectDiscountedFee(r)=>("discounted_fee",r),RateGridOutcome::RejectNet(r)=>("ntli",r),RateGridOutcome::RejectMaximumFee(r)=>("max_fee",r),RateGridOutcome::RejectRounding(r)=>("rounding",r)};format!("{} {} {} {} {} {} {} {} |{}",tag,r.discounted_fee,r.keep,r.add.map_or("-".into(),|v|v.to_string()),r.net.map_or("-".into(),|v|v.to_string()),r.maximum_fee.map_or("-".into(),|v|v.to_string()),r.maximum_keep.map_or("-".into(),|v|v.to_string()),r.whole.map_or("-".into(),|v|v.to_string()),events(&v.events))}}},
 "scale"=>deployer_scale_in_target_range(p.f()).to_string(),
 "ledger"=>{let mut l=FeeLedger::default();let n=p.u();let mut queries=vec![];for _ in 0..n {let owner=p.a();let token=p.u();let s=TokenFeeState{volume:p.u(),unclaimed:p.u(),claimed:p.u(),rewarded_to_referrer:p.u(),rewarded_fees:p.u(),trial_extra:p.u()};l.insert_token_state(owner,token,s);queries.push((owner,token));}let n=p.u();let mut bqueries=vec![];for _ in 0..n{let owner=p.a();let token=p.u();l.insert_collected_builder_fee(owner,token,p.u());bqueries.push((owner,token));}let payer=p.a();let token=p.u();let rt=p.u();let ra=p.u();let raddr=p.a();let bt=p.u();let ba=p.u();let baddr=p.a();let rec=FillFeeRecord{referrer:LedgerCredit{tag:rt,amount:ra,address:Some(raddr)},builder:LedgerCredit{tag:bt,amount:ba,address:Some(baddr)},gross:p.u(),rebate:p.u(),extra:p.u()};let r=l.apply(payer,token,rec).unwrap();queries.push((payer,token));if rt as u32==1{queries.push((raddr,token));}if bt as u8!=0&&ba!=0{queries.push((baddr,token));bqueries.push((baddr,token));}queries.sort();queries.dedup();bqueries.sort();bqueries.dedup();let vals=queries.iter().map(|(a,t)|{let s=l.token_state(*a,*t).unwrap();format!("{}:{}:{},{},{},{},{},{}",addr(*a),t,s.volume,s.unclaimed,s.claimed,s.rewarded_to_referrer,s.rewarded_fees,s.trial_extra)}).collect::<Vec<_>>().join(";");let bs=bqueries.iter().map(|(a,t)|format!("{}:{}:{}",addr(*a),t,l.collected_builder_fee(*a,*t).unwrap())).collect::<Vec<_>>().join(";");format!("{} |{} |{} |{}",vals,bs,r.events.len(),r.value.creations.len())},
 _=>panic!("bad kind")};assert!(p.0.next().is_none(),"unconsumed fixture");out
}
fn main(){for line in io::stdin().lock().lines(){println!("{}",run(&line.unwrap()));}}
