//! Real stdin/stdout driver for the independently authored checked component.
use node94_huf_fast_state::{initialize, AddressMap};
use std::io::{self, BufRead};

fn number(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s, 16).map_err(|_| "bad hex u64".into())
}
fn bytes(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" { return Ok(Vec::new()); }
    if s.len() % 2 != 0 || !s.is_ascii() { return Err("bad hex bytes".into()); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex byte".into())).collect()
}
fn request(line: &str) -> Result<String, String> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 8 { return Err("expected 8 fields".into()); }
    let address = AddressMap { state: number(fields[0])?, output: number(fields[1])?, input: number(fields[2])?, table: number(fields[3])? };
    let length = number(fields[4])?;
    let header: [u8; 4] = bytes(fields[5])?.try_into().map_err(|_| "header must have four bytes")?;
    let input = bytes(fields[6])?;
    let mut state: [u64; 19] = fields[7].split(',').map(number).collect::<Result<Vec<_>, _>>()?.try_into().map_err(|_| "state must have 19 words")?;
    let status = match initialize(&mut state, address, length, &input, header) {
        Ok(raw) => format!("status {raw:016x}"),
        Err(error) => format!("domain {error:?}"),
    };
    let words = state.iter().map(|value| format!("{value:016x}")).collect::<Vec<_>>().join(",");
    Ok(format!("{status}\t{words}"))
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|e| e.to_string()).and_then(|line| request(&line));
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => { eprintln!("invalid request: {error}"); std::process::exit(2); }
        }
    }
}
