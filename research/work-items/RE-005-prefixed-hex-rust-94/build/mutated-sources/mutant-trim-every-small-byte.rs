//! Safe-slice projection of node #94's established prefixed-hex normal path.
//!
//! The native entry requires nonempty input and capacity for the untrimmed
//! representation, even when the first high nibble will be omitted. Refusal
//! here is a separate safe API policy, not the target's panic protocol.
#![no_std]
#![forbid(unsafe_code)]

/// The supplied slices are outside this component's qualified domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedDomain;

fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

/// Write `0x` followed by lowercase hexadecimal and return the written length.
///
/// When requested, omit only the first high nibble if the first byte is below
/// sixteen. The output still needs `2 * input.len() + 2` bytes of capacity.
/// No terminator is appended; the remaining output suffix is unchanged.
/// Empty input, length overflow or insufficient output returns an error before
/// any output change. These errors do not model captured panic behavior.
pub fn encode_prefixed_hex(
    input: &[u8],
    trim_first_nibble: bool,
    output: &mut [u8],
) -> Result<usize, UnsupportedDomain> {
    let required = input
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(2))
        .ok_or(UnsupportedDomain)?;
    if input.is_empty() || output.len() < required {
        return Err(UnsupportedDomain);
    }

    output[0] = b'0';
    output[1] = b'x';
    let mut cursor = 2;
    for (index, &byte) in input.iter().enumerate() {
        if !(index < input.len() && trim_first_nibble && byte < 16) {
            output[cursor] = hex_digit(byte >> 4);
            cursor += 1;
        }
        output[cursor] = hex_digit(byte & 15);
        cursor += 1;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{encode_prefixed_hex, UnsupportedDomain};
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
    fn frozen_native_grounded_vectors() {
        let mut cases = 0;
        for line in include_str!("target-vectors.txt").lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 7);
            let input = bytes(fields[2]);
            let mut output = bytes(fields[3]);
            let actual = encode_prefixed_hex(&input, fields[1] == "1", &mut output);
            let expected = if fields[4] == "ok" {
                Ok(fields[5].parse::<usize>().unwrap())
            } else {
                Err(UnsupportedDomain)
            };
            assert_eq!(actual, expected, "{} result", fields[0]);
            assert_eq!(output, bytes(fields[6]), "{} complete output", fields[0]);
            cases += 1;
        }
        assert_eq!(cases, 2664);
    }
}
