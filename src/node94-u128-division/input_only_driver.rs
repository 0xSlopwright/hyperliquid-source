extern crate node94_u128_division;

use core::num::NonZeroU128;
use std::io::Write;

fn word(text: &str) -> u128 {
    assert_eq!(text.len(), 32);
    assert!(text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    u128::from_str_radix(text, 16).unwrap()
}

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one stimulus path is required");
    let stimulus = std::fs::read_to_string(&arguments[1]).unwrap();
    let mut output = String::new();
    for line in stimulus.lines() {
        let fields: Vec<_> = line.split('|').collect();
        assert_eq!(fields.len(), 3);
        assert!(!fields[0].is_empty());
        assert!(fields[0].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        let dividend = word(fields[1]);
        let divisor = NonZeroU128::new(word(fields[2])).expect("nonzero input domain");
        let actual = node94_u128_division::quotient(dividend, divisor);
        output.push_str(&format!("{}|{:032x}\n", fields[0], actual));
    }
    std::io::stdout().write_all(output.as_bytes()).unwrap();
}
