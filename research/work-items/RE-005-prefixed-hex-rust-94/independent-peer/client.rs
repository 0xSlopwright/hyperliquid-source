extern crate node94_prefixed_hex;

use node94_prefixed_hex::encode_prefixed_hex;
use std::{env, fs};

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" { return Vec::new(); }
    assert_eq!(text.len() % 2, 0, "even hex input required");
    text.as_bytes().chunks_exact(2).map(|part| {
        u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap()
    }).collect()
}

fn hex(data: &[u8]) -> String {
    if data.is_empty() { return "-".to_string(); }
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 2, "one input-only stimulus file required");
    let input = fs::read_to_string(&args[1]).unwrap();
    for line in input.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 8, "id mode and six byte vectors required");
        let mode = match fields[1] {
            "0" => false,
            "1" => true,
            _ => panic!("mode must be zero or one"),
        };
        let input_left = bytes(fields[2]);
        let input_middle = bytes(fields[3]);
        let input_right = bytes(fields[4]);
        let output_left = bytes(fields[5]);
        let output_middle = bytes(fields[6]);
        let output_right = bytes(fields[7]);
        let input_begin = input_left.len();
        let input_end = input_begin + input_middle.len();
        let output_begin = output_left.len();
        let output_end = output_begin + output_middle.len();
        let input_container = [input_left, input_middle, input_right].concat();
        let input_before = input_container.clone();
        let mut output_container = [output_left, output_middle, output_right].concat();
        let output_before = output_container.clone();
        let (outcome, written) = match encode_prefixed_hex(
            &input_container[input_begin..input_end], mode,
            &mut output_container[output_begin..output_end],
        ) {
            Ok(written) => ("ok", written),
            Err(_) => ("unsupported", 0),
        };
        assert_eq!(input_container, input_before, "input container changed");
        assert_eq!(&output_container[..output_begin], &output_before[..output_begin],
                   "left output neighbor changed");
        assert_eq!(&output_container[output_end..], &output_before[output_end..],
                   "right output neighbor changed");
        println!("{} {} {} {}", fields[0], outcome, written,
                 hex(&output_container[output_begin..output_end]));
    }
}
