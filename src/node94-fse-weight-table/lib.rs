#![no_std]
#![forbid(unsafe_code)]

//! Serialized table construction for the qualified node94 weight-table domain.
//!
//! The API and internal arrays are independently chosen. It does not expose the
//! target's private workspace, ABI, malformed-count errors, or decoder runtime.

/// Input outside the qualified log/normalized-count/876-byte caller domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedDomain;

/// Write the qualified serialized table and return its byte length.
///
/// `log` must be 5 or 6. The actual 876-byte caller additionally admits maximum
/// symbols at most 91 or 11 respectively. Counts through `max_symbol` must be
/// -1 or 0..=2^log, their absolute mass must be 2^log, the last must be nonzero,
/// and later cells must be zero. The full domain is checked before any output
/// write. Unsupported input preserves all output bytes; that is safe-API policy,
/// not a claim about the target's out-of-domain partial writes or raw errors.
///
/// Success writes exactly 132 or 260 bytes and preserves the remaining suffix.
/// Native success is RAX=0; this API instead returns the chosen byte length.
pub fn build_weight_table(
    log: u8,
    max_symbol: u8,
    normalized: &[i16; 256],
    output: &mut [u8; 260],
) -> Result<usize, UnsupportedDomain> {
    let maximum = match log {
        5 => 91,
        6 => 11,
        _ => return Err(UnsupportedDomain),
    };
    if max_symbol > maximum {
        return Err(UnsupportedDomain);
    }

    let table_size = 1usize << log;
    let last = usize::from(max_symbol);
    if normalized[last] == 0 {
        return Err(UnsupportedDomain);
    }
    let mut mass = 0u32;
    for (symbol, &coefficient) in normalized.iter().enumerate() {
        if symbol > last {
            if coefficient != 0 {
                return Err(UnsupportedDomain);
            }
        } else {
            if coefficient < -1 || i32::from(coefficient) > table_size as i32 {
                return Err(UnsupportedDomain);
            }
            mass += if coefficient == -1 {
                1
            } else {
                coefficient as u32
            };
        }
    }
    if mass != table_size as u32 {
        return Err(UnsupportedDomain);
    }

    let mut symbols = [0u8; 64];
    let mut next = [0u16; 256];
    let mut unreserved = table_size;
    let mut fast = true;
    for symbol in 0..=last {
        let coefficient = normalized[symbol];
        if coefficient == -1 {
            unreserved -= 1;
            symbols[unreserved] = symbol as u8;
            next[symbol] = 1;
        } else {
            next[symbol] = coefficient as u16;
            if coefficient as usize >= table_size / 2 {
                fast = false;
            }
        }
    }

    let stride = table_size / 2 + table_size / 8 + 3;
    let mask = table_size - 1;
    let mut position = 0usize;
    for symbol in 0..=last {
        let coefficient = normalized[symbol];
        if coefficient <= 0 {
            continue;
        }
        for _ in 0..coefficient as usize {
            symbols[position] = symbol as u8;
            loop {
                position = (position + stride) & mask;
                if position < unreserved {
                    break;
                }
            }
        }
    }

    let header = u32::from(log) | (u32::from(fast) << 16);
    output[..4].copy_from_slice(&header.to_le_bytes());
    for (row, &symbol) in symbols[..table_size].iter().enumerate() {
        let index = usize::from(symbol);
        let value = u32::from(next[index]);
        next[index] += 1;
        // Each occurring symbol has value in 1..2*T. Zero cells never occur.
        let highest_bit = 31 - value.leading_zeros();
        let bits = u32::from(log) - highest_bit;
        let base = ((value << bits) - table_size as u32) as u16;
        let offset = 4 + 4 * row;
        output[offset..offset + 2].copy_from_slice(&base.to_le_bytes());
        output[offset + 2] = symbol;
        output[offset + 3] = bits as u8;
    }
    Ok(4 + 4 * table_size)
}

#[cfg(test)]
mod tests {
    use super::build_weight_table;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        let mut result = [0u8; N];
        for (index, value) in result.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
        }
        result
    }

    #[test]
    fn independently_frozen_caller_tables_and_complete_output() {
        let mut cases = 0;
        for line in include_str!("target-vectors.tsv").lines() {
            let (stimulus, wanted) = line.split_once('\t').unwrap();
            let input: std::vec::Vec<_> = stimulus.split(' ').collect();
            let expected: std::vec::Vec<_> = wanted.split(' ').collect();
            assert_eq!(input.len(), 5);
            assert_eq!(expected.len(), 4);
            assert_eq!(input[0], expected[0]);
            assert_eq!(expected[1], "ok");
            let counts: std::vec::Vec<i16> = input[3]
                .split(',')
                .map(|word| word.parse().unwrap())
                .collect();
            let normalized: [i16; 256] = counts.try_into().unwrap();
            let mut output = bytes::<260>(input[4]);
            let length = build_weight_table(
                input[1].parse().unwrap(),
                input[2].parse().unwrap(),
                &normalized,
                &mut output,
            )
            .unwrap();
            assert_eq!(length, expected[2].parse::<usize>().unwrap(), "{}", input[0]);
            assert_eq!(output, bytes::<260>(expected[3]), "{}", input[0]);
            cases += 1;
        }
        assert_eq!(cases, 39);
    }
}

#[cfg(test)]
extern crate std;
