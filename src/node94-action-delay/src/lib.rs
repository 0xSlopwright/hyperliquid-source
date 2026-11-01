//! Qualified logical curve from node #94, entry 0x392fab0.
//!
//! The caller's raw mode/action words and f64 input are explicit values here.
//! Result/Trace are chosen observation carriers, not recovered native ABI or
//! panic payload layouts. CPU feature dispatch and soft-FMA are not recovered.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    Default20,
    Medium12,
    Eighth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    Weight,
    Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct Trace {
    pub curve: Curve,
    pub short_tail: bool,
    pub fused: f64,
    pub raw_weight: f64,
    pub weight: f64,
    pub base: f64,
    pub output: f64,
}

/// Selection follows the native low-byte mode and mixed signed/unsigned
/// 32-bit comparisons; it is not the reference's guessed enum API.
pub fn select_curve(raw_mode: u8, raw_action: i32) -> Curve {
    if raw_mode < 2 {
        return Curve::Default20;
    }
    if raw_mode == 2 {
        match raw_action {
            0 => Curve::Medium12,
            3 | 4 | 11054 | 11137 => Curve::Eighth,
            _ => Curve::Default20,
        }
    } else {
        match raw_action {
            5 => Curve::Medium12,
            0 | 1 | 10142 | 10151 => Curve::Eighth,
            _ => Curve::Default20,
        }
    }
}

/// Native SETAE and SETB operate on the raw unsigned action bits. In
/// particular, negative i32 actions satisfy the first unsigned comparison.
pub fn short_default_tail(raw_action: i32) -> bool {
    let raw = raw_action as u32;
    raw >= 100_000_000 || raw.wrapping_sub(10_000) < 100_000
}

fn finite_only_clamp(value: f64) -> f64 {
    if !value.is_finite() {
        value
    } else if value < 0.0 {
        0.0
    } else if value > 1.0 {
        1.0
    } else {
        value // Preserve -0 as the observed MAXSD source does.
    }
}

/// Qualified arithmetic semantics: one-round FMA, binary64 round-to-nearest,
/// DAZ/FTZ disabled and masked floating exceptions. No original code executes.
/// Hardware-FMA target arms ground the FMA rule; soft fallback is unqualified.
pub fn evaluate(raw_mode: u8, raw_action: i32, input: f64) -> Result<Trace, Guard> {
    let curve = select_curve(raw_mode, raw_action);
    let bias = match curve {
        Curve::Default20 => -4.0,
        Curve::Medium12 => -3.0,
        Curve::Eighth => -1.5,
    };
    let fused = input.mul_add(10_000.0, bias);
    let raw_weight = match curve {
        Curve::Default20 => fused / 20.0,
        Curve::Medium12 => fused / 12.0,
        Curve::Eighth => fused * 0.125,
    };
    let weight = finite_only_clamp(raw_weight);
    // Negating >= deliberately rejects NaN as well as negative infinity.
    if !(weight >= 0.0) {
        return Err(Guard::Weight);
    }
    let coefficient = if curve == Curve::Default20 { 1.3 } else { 1.8 };
    // Separate operations, as in the original MULSD followed by ADDSD.
    let scaled = weight * coefficient;
    let base = scaled + 0.76;
    if !(base >= 0.0) {
        return Err(Guard::Duration);
    }
    let short_tail = curve == Curve::Default20 && short_default_tail(raw_action);
    let output = base * if short_tail { 0.2 } else { 0.65 };
    Ok(Trace { curve, short_tail, fused, raw_weight, weight, base, output })
}
