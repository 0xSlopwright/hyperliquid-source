//! Input-only comparison driver for the separately compiled production rlib.
use node94_three_digit_ascii::parse_three_digits;

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one stimulus file is required");
    let text = std::fs::read_to_string(&arguments[1]).unwrap();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split(' ').collect();
        assert_eq!(fields.len(), 2, "expected id and hex-or-dash only");
        let id = fields[0];
        assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
        let encoded = fields[1];
        let input: Vec<u8> = if encoded == "-" {
            Vec::new()
        } else {
            assert_eq!(encoded.len() % 2, 0);
            (0..encoded.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&encoded[at..at + 2], 16).unwrap())
                .collect()
        };
        println!("{id} {}", parse_three_digits(&input));
    }
}
