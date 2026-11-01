use node94_action_delay::{evaluate, select_curve, short_default_tail, Curve, Guard};
fn label(c: Curve) -> &'static str {
    match c { Curve::Default20=>"default20", Curve::Medium12=>"medium12", Curve::Eighth=>"eighth" }
}
#[test]
fn target_dispatch_partition() {
    let mut patterns=0u64;
    for line in include_str!("../dispatch.tsv").lines().filter(|l|!l.starts_with('#')) {
        let f:Vec<_>=line.split('\t').collect();
        let ml:u8=f[0].parse().unwrap(); let mh:u8=f[1].parse().unwrap();
        let al:i32=f[2].parse().unwrap(); let ah:i32=f[3].parse().unwrap();
        patterns+=(u64::from(mh)-u64::from(ml)+1)*((i64::from(ah)-i64::from(al)+1) as u64);
        for mode in ml..=mh {
            for action in [al,ah,(i64::from(al)+(i64::from(ah)-i64::from(al))/2) as i32] {
                let c=select_curve(mode,action);
                assert_eq!(label(c),f[4],"mode={mode} action={action}");
                assert_eq!(c==Curve::Default20 && short_default_tail(action),f[5]=="1");
            }
        }
    }
    assert_eq!(patterns,1u64<<40); // Abstract partition size, not execution count.
}
#[test]
fn retained_exact_arithmetic_vectors() {
    for line in include_str!("../target-vectors.tsv").lines().filter(|l|!l.starts_with('#')) {
        let f:Vec<_>=line.split('\t').collect();
        let result=evaluate(f[1].parse().unwrap(),f[2].parse().unwrap(),
            f64::from_bits(u64::from_str_radix(f[3],16).unwrap()));
        match result {
            Err(Guard::Weight)=>assert_eq!(f[4],"error_weight","case {}",f[0]),
            Err(Guard::Duration)=>assert_eq!(f[4],"error_duration","case {}",f[0]),
            Ok(t)=> {
                assert_eq!(label(t.curve),f[4],"case {}",f[0]);
                assert_eq!(t.short_tail,f[5]=="1");
                for (v,expected) in [t.fused,t.raw_weight,t.weight,t.base,t.output].iter().zip(&f[6..]) {
                    assert_eq!(v.to_bits(),u64::from_str_radix(expected,16).unwrap(),"case {}",f[0]);
                }
            }
        }
    }
}
#[test]
fn reviewer_dispatch_and_unsigned_tail_regressions() {
    assert_eq!(select_curve(1,0),Curve::Default20);
    assert_eq!(select_curve(2,0),Curve::Medium12);
    assert_eq!(select_curve(3,0),Curve::Eighth);
    assert!(evaluate(1,-1,0.001).unwrap().short_tail);
    assert!(!evaluate(2,3,0.001).unwrap().short_tail);
    assert_eq!(evaluate(0,0,f64::NAN).unwrap_err(),Guard::Weight);
    assert_eq!(evaluate(0,0,f64::NEG_INFINITY).unwrap_err(),Guard::Weight);
    assert_eq!(evaluate(0,0,f64::INFINITY).unwrap().output,f64::INFINITY);
}
