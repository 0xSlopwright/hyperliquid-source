#![no_std]
#![forbid(unsafe_code)]
//! Independently authored capacity20 decimal suffix, not an original ABI.

/// Write unsigned decimal `value` to the end of the actual20-byte domain.
///
/// Return the first written index; preserve every earlier buffer byte. Zero
/// writes one ASCII zero. The full u64 range needs at most20 digits, so every
/// decrement/index is in bounds. This chosen safe interface does not admit
/// native invalid pointers, arbitrary aliases or other capacities.
pub fn write_decimal_suffix(mut value: u64, buffer: &mut [u8; 20]) -> usize {
    let mut start = 20;
    loop {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    start
}

#[cfg(test)]
mod tests {
    use super::write_decimal_suffix;

    fn buffer(text: &str) -> [u8; 20] {
        assert_eq!(text.len(), 40);
        let mut out = [0; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn independent_native_contract_vectors() {
        let mut count = 0;
        for row in include_str!("target-vectors.tsv").lines() {
            let (given, expected) = row.split_once('\t').unwrap();
            let mut input = given.split(' ');
            let id = input.next().unwrap();
            let value = u64::from_str_radix(input.next().unwrap(), 16).unwrap();
            let mut bytes = buffer(input.next().unwrap());
            assert!(input.next().is_none());
            let mut answer = expected.split(' ');
            assert_eq!(answer.next().unwrap(), id);
            let wanted_start: usize = answer.next().unwrap().parse().unwrap();
            let wanted_buffer = buffer(answer.next().unwrap());
            assert!(answer.next().is_none());
            let actual_start = write_decimal_suffix(value, &mut bytes);
            assert_eq!(actual_start, wanted_start, "start for {}", id);
            assert_eq!(bytes, wanted_buffer, "complete buffer for {}", id);
            count += 1;
        }
        assert_eq!(count, 1697);
    }
}
