//! Research driver. Its sole file argument contains stimuli, never answers.
use node94_prefixed_hex::encode_prefixed_hex;

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0, "odd hex input");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex input"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_owned();
    }
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    assert_eq!(arguments.len(), 2, "one stimulus file required");
    let text = std::fs::read_to_string(&arguments[1]).expect("stimulus file");
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "id mode input_hex initial_output_hex");
        let mode = match fields[1] {
            "0" => false,
            "1" => true,
            _ => panic!("mode must be zero or one"),
        };
        let input = bytes(fields[2]);
        let mut output = bytes(fields[3]);
        match encode_prefixed_hex(&input, mode, &mut output) {
            Ok(length) => println!("{} ok {} {}", fields[0], length, hex(&output)),
            Err(_) => println!("{} unsupported 0 {}", fields[0], hex(&output)),
        }
    }
}
