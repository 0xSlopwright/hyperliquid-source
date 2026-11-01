#![no_std]
#![forbid(unsafe_code)]

use core::num::NonZeroU128;

/// Unsigned quotient on the complete nonzero-divisor numeric domain.
///
/// This independently chosen bit-prefix algorithm implements the numerical
/// contract proved from node94's 198-byte leaf. It does not recover its ABI,
/// physical clobbers, zero-divisor fault behavior, or original compiler.
#[inline(never)]
pub fn quotient(dividend: u128, divisor: NonZeroU128) -> u128 {
    let divisor = divisor.get();
    let mut result = 0_u128;
    let mut remainder = 0_u128;
    let mut bit = 128_usize;
    while bit != 0 {
        bit -= 1;
        result <<= 1;
        remainder = (remainder << 1) | ((dividend >> bit) & 1);
        if remainder >= divisor {
            remainder -= divisor;
            result |= 1;
        }
    }
    result
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::quotient;
    use core::num::NonZeroU128;
    use std::vec::Vec;

    #[test]
    fn frozen_native_contract_cases() {
        let mut count = 0;
        for line in include_str!("target-vectors.tsv").lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4);
            let dividend = u128::from_str_radix(fields[1], 16).unwrap();
            let divisor = NonZeroU128::new(u128::from_str_radix(fields[2], 16).unwrap()).unwrap();
            let expected = u128::from_str_radix(fields[3], 16).unwrap();
            assert_eq!(quotient(dividend, divisor), expected, "{}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 7587);
    }
}
