//! Input-only client for the separately linked production library.
use node94_fse_weight_table::build_weight_table;
use std::fmt::Write;

fn bytes(hex: &str) -> [u8; 260] {
    assert_eq!(hex.len(), 520, "initial output must contain 260 bytes");
    let mut output = [0u8; 260];
    for (index, value) in output.iter_mut().enumerate() {
        *value = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
    }
    output
}

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one input file is required");
    let input = std::fs::read_to_string(&arguments[1]).unwrap();
    for line in input.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split(' ').collect();
        assert_eq!(fields.len(), 5, "five stimulus fields are required");
        let id = fields[0];
        assert!(!id.is_empty());
        assert!(id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        let counts: Vec<i16> = fields[3]
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect();
        let normalized: [i16; 256] = counts.try_into().unwrap();
        let mut output = bytes(fields[4]);
        let result = build_weight_table(
            fields[1].parse().unwrap(),
            fields[2].parse().unwrap(),
            &normalized,
            &mut output,
        );
        let (status, length) = match result {
            Ok(length) => ("ok", length),
            Err(_) => ("unsupported", 0),
        };
        let mut encoded = String::with_capacity(520);
        for byte in output {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        println!("{id} {status} {length} {encoded}");
    }
}
