extern crate node94_huf_fast_state;
use node94_huf_fast_state::{initialize, AddressMap, State};
use std::io::{self, BufRead};
fn number(s: &str) -> u64 { u64::from_str_radix(s, 16).expect("private input integer") }
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" { return Vec::new(); }
    assert_eq!(s.len() % 2, 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).expect("private input byte")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line=line.expect("private input line");
        let f:Vec<_>=line.split('|').collect();assert_eq!(f.len(),9);
        let map=AddressMap {state:number(f[1]),output:number(f[2]),input:number(f[3]),table:number(f[4])};
        let length=number(f[5]);let h:[u8;4]=bytes(f[6]).try_into().expect("four header bytes");
        let data=bytes(f[7]);let words:Vec<_>=f[8].split(',').map(number).collect();
        let mut state:State=words.try_into().expect("nineteen words");
        let result=initialize(&mut state,map,length,&data,h);
        match result { Ok(status)=>print!("{}|S:{:016x}|",f[0],status), Err(_)=>print!("{}|D|",f[0]) }
        for (i,word) in state.iter().enumerate() {if i!=0 {print!(",");} print!("{:016x}",word);}
        println!();
    }
}
