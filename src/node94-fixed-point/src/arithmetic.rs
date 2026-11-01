use crate::{SignedSize, Size, Wei};

/// Whether a saturating operation was exact or reached a numeric boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticStatus {
    Exact,
    Overflow,
    Underflow,
}

/// The value and status produced by an evidence-backed saturating operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArithmeticOutcome<T> {
    pub value: T,
    pub status: ArithmeticStatus,
}

impl<T> ArithmeticOutcome<T> {
    #[must_use]
    pub const fn exact(value: T) -> Self {
        Self {
            value,
            status: ArithmeticStatus::Exact,
        }
    }

    #[must_use]
    pub const fn is_exact(&self) -> bool {
        matches!(self.status, ArithmeticStatus::Exact)
    }
}

macro_rules! unsigned_saturating_arithmetic {
    ($name:ident) => {
        impl $name {
            /// Adds two raw quantities, saturating at u64::MAX and reporting overflow.
            #[must_use]
            pub const fn saturating_add_status(self, rhs: Self) -> ArithmeticOutcome<Self> {
                match self.raw().checked_add(rhs.raw()) {
                    Some(value) => ArithmeticOutcome::exact(Self::from_raw(value)),
                    None => ArithmeticOutcome {
                        value: Self::from_raw(u64::MAX),
                        status: ArithmeticStatus::Overflow,
                    },
                }
            }

            /// Subtracts two raw quantities, saturating at zero and reporting underflow.
            #[must_use]
            pub const fn saturating_sub_status(self, rhs: Self) -> ArithmeticOutcome<Self> {
                match self.raw().checked_sub(rhs.raw()) {
                    Some(value) => ArithmeticOutcome::exact(Self::from_raw(value)),
                    None => ArithmeticOutcome {
                        value: Self::from_raw(0),
                        status: ArithmeticStatus::Underflow,
                    },
                }
            }
        }
    };
}

unsigned_saturating_arithmetic!(Wei);
unsigned_saturating_arithmetic!(Size);

impl SignedSize {
    /// Adds two signed sizes, saturating at the applicable i64 boundary.
    #[must_use]
    pub const fn saturating_add_status(self, rhs: Self) -> ArithmeticOutcome<Self> {
        match self.raw().checked_add(rhs.raw()) {
            Some(value) => ArithmeticOutcome::exact(Self::from_raw(value)),
            None if rhs.raw() >= 0 => ArithmeticOutcome {
                value: Self::from_raw(i64::MAX),
                status: ArithmeticStatus::Overflow,
            },
            None => ArithmeticOutcome {
                value: Self::from_raw(i64::MIN),
                status: ArithmeticStatus::Underflow,
            },
        }
    }

    /// Subtracts two signed sizes, saturating at the applicable i64 boundary.
    #[must_use]
    pub const fn saturating_sub_status(self, rhs: Self) -> ArithmeticOutcome<Self> {
        match self.raw().checked_sub(rhs.raw()) {
            Some(value) => ArithmeticOutcome::exact(Self::from_raw(value)),
            None if rhs.raw() < 0 => ArithmeticOutcome {
                value: Self::from_raw(i64::MAX),
                status: ArithmeticStatus::Overflow,
            },
            None => ArithmeticOutcome {
                value: Self::from_raw(i64::MIN),
                status: ArithmeticStatus::Underflow,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wei_addition_and_subtraction_report_boundary_saturation() {
        assert_eq!(
            Wei::from_raw(u64::MAX).saturating_add_status(Wei::from_raw(1)),
            ArithmeticOutcome {
                value: Wei::from_raw(u64::MAX),
                status: ArithmeticStatus::Overflow,
            }
        );
        assert_eq!(
            Wei::from_raw(0).saturating_sub_status(Wei::from_raw(1)),
            ArithmeticOutcome {
                value: Wei::from_raw(0),
                status: ArithmeticStatus::Underflow,
            }
        );
        assert_eq!(
            Wei::from_raw(9).saturating_sub_status(Wei::from_raw(4)),
            ArithmeticOutcome::exact(Wei::from_raw(5))
        );
    }

    #[test]
    fn unsigned_size_doubling_guard_has_observed_saturating_result() {
        let largest_exact = Size::from_raw(u64::MAX / 2);
        assert_eq!(
            largest_exact.saturating_add_status(largest_exact),
            ArithmeticOutcome::exact(Size::from_raw(u64::MAX - 1))
        );
        let first_overflow = Size::from_raw(u64::MAX / 2 + 1);
        assert_eq!(
            first_overflow.saturating_add_status(first_overflow),
            ArithmeticOutcome {
                value: Size::from_raw(u64::MAX),
                status: ArithmeticStatus::Overflow,
            }
        );
    }

    #[test]
    fn signed_size_addition_saturates_in_both_directions() {
        assert_eq!(
            SignedSize::from_raw(i64::MAX).saturating_add_status(SignedSize::from_raw(1)),
            ArithmeticOutcome {
                value: SignedSize::from_raw(i64::MAX),
                status: ArithmeticStatus::Overflow,
            }
        );
        assert_eq!(
            SignedSize::from_raw(i64::MIN).saturating_add_status(SignedSize::from_raw(-1)),
            ArithmeticOutcome {
                value: SignedSize::from_raw(i64::MIN),
                status: ArithmeticStatus::Underflow,
            }
        );
    }

    #[test]
    fn signed_size_subtraction_saturates_in_both_directions() {
        assert_eq!(
            SignedSize::from_raw(i64::MAX).saturating_sub_status(SignedSize::from_raw(-1)),
            ArithmeticOutcome {
                value: SignedSize::from_raw(i64::MAX),
                status: ArithmeticStatus::Overflow,
            }
        );
        assert_eq!(
            SignedSize::from_raw(i64::MIN).saturating_sub_status(SignedSize::from_raw(1)),
            ArithmeticOutcome {
                value: SignedSize::from_raw(i64::MIN),
                status: ArithmeticStatus::Underflow,
            }
        );
    }
}
