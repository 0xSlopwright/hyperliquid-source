#![no_std]
#![forbid(unsafe_code)]

//! Independently authored scalar reconstruction of one node94 parser.
//! The slice API is chosen here; no original Rust name or ABI is claimed.

/// Parse exactly three ASCII digits with a nonzero leading digit.
///
/// Return zero for every other slice, otherwise the value in 100..=999.
/// The input is never modified. The contract covers safe readable slices;
/// native faults, raw invalid pointers and physical read traces are excluded.
pub fn parse_three_digits(input: &[u8]) -> u16 {
    if input.len() != 3 {
        return 0;
    }
    let first = input[0];
    let middle = input[1];
    let last = input[2];
    if first < b'0' || first > b'9'
        || middle < b'0' || middle > b'9'
        || last < b'0' || last > b'9'
    {
        return 0;
    }
    u16::from(first - b'0') * 100
        + u16::from(middle - b'0') * 10
        + u16::from(last - b'0')
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::parse_three_digits;
    use std::vec::Vec;

    fn bytes(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn frozen_native_predicates_payloads_and_lengths() {
        let mut cases = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let (stimulus, wanted) = line.split_once('\t').unwrap();
            let (id, encoded) = stimulus.split_once(' ').unwrap();
            let (wanted_id, expected) = wanted.split_once(' ').unwrap();
            assert_eq!(id, wanted_id);
            let input = bytes(encoded);
            let before = input.clone();
            assert_eq!(parse_three_digits(&input), expected.parse::<u16>().unwrap(), "{id}");
            assert_eq!(input, before, "{id}");
            cases += 1;
        }
        assert_eq!(cases, 1663);
    }
}
