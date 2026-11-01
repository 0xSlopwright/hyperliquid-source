extern crate node94_integer_digit_span;
use std::io::{self, Write};
fn lowercase_hex(raw: &str, width: usize) -> bool {
    raw.len() == width && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn main() {
    let mut arguments = std::env::args().skip(1);
    let path = arguments.next().expect("input-only stimulus file");
    assert!(arguments.next().is_none(), "only one stimulus path is accepted");
    let inputs = std::fs::read_to_string(path).expect("input stimuli");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        assert!(line.is_ascii(), "ASCII stimulus wire");
        let fields: Vec<_> = line.split(' ').collect();
        assert_eq!(fields.len(), 3);
        assert!(!fields[0].is_empty());
        assert!(lowercase_hex(fields[1], 16));
        assert!(lowercase_hex(fields[2], 40));
        let value = u64::from_str_radix(fields[1], 16).unwrap();
        let mut buffer = [0_u8; 20];
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&fields[2][2*index..2*index+2], 16).unwrap();
        }
        let start = node94_integer_digit_span::write_decimal_suffix(value, &mut buffer);
        write!(output, "{} {} ", fields[0], start).unwrap();
        // Observe all bytes: an incorrect returned index is a value difference,
        // never a harness slice panic or a source for expected output.
        for byte in buffer { write!(output, "{:02x}", byte).unwrap(); }
        writeln!(output).unwrap();
    }
}
