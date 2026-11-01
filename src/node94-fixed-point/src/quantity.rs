use core::fmt;

/// Quantity families whose signed admission guards are established for node #94.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuantityKind {
    Notional,
    BigNotional,
    Size,
    SignedNotional,
    SignedSize,
}

/// Rejection returned by an evidence-backed signed/unsigned admission guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// A negative i64 cannot be admitted by an unsigned quantity family.
    NegativeUnsigned { kind: QuantityKind, value: i64 },
    /// A u64 above i64::MAX cannot be admitted by a signed quantity family.
    SignedOutOfRange { kind: QuantityKind, value: u64 },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeUnsigned { kind, value } => {
                write!(formatter, "negative value {value} is invalid for {kind:?}")
            }
            Self::SignedOutOfRange { kind, value } => {
                write!(
                    formatter,
                    "value {value} exceeds the signed range for {kind:?}"
                )
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

macro_rules! raw_quantity {
    ($name:ident, $raw:ty) => {
        #[doc = concat!("Raw fixed-point `", stringify!($name), "` quantity.")]
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($raw);

        impl $name {
            #[must_use]
            pub const fn from_raw(raw: $raw) -> Self {
                Self(raw)
            }

            #[must_use]
            pub const fn raw(self) -> $raw {
                self.0
            }
        }

        impl From<$name> for $raw {
            fn from(value: $name) -> Self {
                value.raw()
            }
        }
    };
}

raw_quantity!(Wei, u64);
raw_quantity!(Price, u64);
raw_quantity!(Notional, u64);
raw_quantity!(BigNotional, u128);
raw_quantity!(Size, u64);
raw_quantity!(SignedNotional, i64);
raw_quantity!(SignedSize, i64);

macro_rules! admit_unsigned_from_i64 {
    ($name:ident, $kind:expr, $raw:ty) => {
        impl TryFrom<i64> for $name {
            type Error = AdmissionError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                if value < 0 {
                    return Err(AdmissionError::NegativeUnsigned { kind: $kind, value });
                }
                Ok(Self::from_raw(value as $raw))
            }
        }
    };
}

macro_rules! admit_signed_from_u64 {
    ($name:ident, $kind:expr) => {
        impl TryFrom<u64> for $name {
            type Error = AdmissionError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                let raw = i64::try_from(value)
                    .map_err(|_| AdmissionError::SignedOutOfRange { kind: $kind, value })?;
                Ok(Self::from_raw(raw))
            }
        }
    };
}

admit_unsigned_from_i64!(Notional, QuantityKind::Notional, u64);
admit_unsigned_from_i64!(BigNotional, QuantityKind::BigNotional, u128);
admit_unsigned_from_i64!(Size, QuantityKind::Size, u64);
admit_signed_from_u64!(SignedNotional, QuantityKind::SignedNotional);
admit_signed_from_u64!(SignedSize, QuantityKind::SignedSize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_families_admit_zero_and_i64_max_without_changing_value() {
        assert_eq!(Notional::try_from(0), Ok(Notional::from_raw(0)));
        assert_eq!(
            BigNotional::try_from(i64::MAX),
            Ok(BigNotional::from_raw(i64::MAX as u128))
        );
        assert_eq!(
            Size::try_from(i64::MAX),
            Ok(Size::from_raw(i64::MAX as u64))
        );
    }

    #[test]
    fn unsigned_families_reject_negative_values() {
        assert_eq!(
            Size::try_from(-1),
            Err(AdmissionError::NegativeUnsigned {
                kind: QuantityKind::Size,
                value: -1,
            })
        );
        assert_eq!(
            Notional::try_from(i64::MIN),
            Err(AdmissionError::NegativeUnsigned {
                kind: QuantityKind::Notional,
                value: i64::MIN,
            })
        );
    }

    #[test]
    fn signed_families_admit_i64_max_and_reject_the_next_value() {
        assert_eq!(
            SignedSize::try_from(i64::MAX as u64),
            Ok(SignedSize::from_raw(i64::MAX))
        );
        assert_eq!(
            SignedNotional::try_from(i64::MAX as u64 + 1),
            Err(AdmissionError::SignedOutOfRange {
                kind: QuantityKind::SignedNotional,
                value: i64::MAX as u64 + 1,
            })
        );
    }
}
