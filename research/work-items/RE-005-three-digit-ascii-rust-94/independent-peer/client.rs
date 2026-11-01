extern crate node94_three_digit_ascii;

use std::{env, fs, process};

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.len() % 2 != 0 {
        return Err("odd hex input length".into());
    }
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = nibble(pair[0]).ok_or("invalid hex input")?;
            let low = nibble(pair[1]).ok_or("invalid hex input")?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("expected only one runtime stimulus path".into());
    }
    let input = fs::read_to_string(&args[1]).map_err(|error| error.to_string())?;
    for (index, line) in input.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            return Err(format!("line {} needs id/left/slice/right", index + 1));
        }
        let left = decode_hex(fields[1])?;
        let middle = decode_hex(fields[2])?;
        let right = decode_hex(fields[3])?;
        let mut backing = Vec::with_capacity(left.len() + middle.len() + right.len());
        backing.extend_from_slice(&left);
        backing.extend_from_slice(&middle);
        backing.extend_from_slice(&right);
        let before = backing.clone();
        let result = node94_three_digit_ascii::parse_three_digits(
            &backing[left.len()..left.len() + middle.len()],
        );
        if backing != before {
            return Err(format!("input container changed at line {}", index + 1));
        }
        println!("{} {}", fields[0], result);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("independent input-only client: {error}");
        process::exit(2);
    }
}
