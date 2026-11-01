//! Offline corpus driver for project-authored Rust only; no captured code.
use node94_action_delay::{Curve, Guard, evaluate};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("read vector");
        if line.starts_with('#') || line.is_empty() { continue; }
        let fields: Vec<_> = line.split('\t').collect();
        let id = fields[0];
        let mode: u8 = fields[1].parse().expect("mode");
        let action: i32 = fields[2].parse().expect("action");
        let input = f64::from_bits(u64::from_str_radix(fields[3], 16).expect("bits"));
        match evaluate(mode, action, input) {
            Ok(t) => {
                let kind = match t.curve { Curve::Default20 => "default20", Curve::Medium12 => "medium12", Curve::Eighth => "eighth" };
                println!("{id}\t{kind}\t{}\t{:016x}\t{:016x}\t{:016x}\t{:016x}\t{:016x}",
                         u8::from(t.short_tail), t.fused.to_bits(), t.raw_weight.to_bits(),
                         t.weight.to_bits(), t.base.to_bits(), t.output.to_bits());
            }
            Err(Guard::Weight) => println!("{id}\terror_weight"),
            Err(Guard::Duration) => println!("{id}\terror_duration"),
        }
    }
}
