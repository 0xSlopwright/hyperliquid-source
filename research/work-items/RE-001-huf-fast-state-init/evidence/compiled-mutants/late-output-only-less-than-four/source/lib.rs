//! Independently authored checked constructor for one node #94 static contract.
//!
//! Symbolic addresses describe a detached 19-word state image. This is not an
//! FFI entry point, a decoder, or permission to dereference those addresses.

pub const RAW_ERROR: u64 = (-20_i64) as u64;
pub type State = [u64; 19];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressMap {
    pub state: u64,
    pub output: u64,
    pub input: u64,
    pub table: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    OutputLengthOutsideSignedDomain,
    InputLengthOutsideU64Domain,
    AddressWrap(&'static str),
    RegionOverlap(&'static str, &'static str),
}

fn end(base: u64, length: u64, role: &'static str) -> Result<u64, DomainError> {
    base.checked_add(length).ok_or(DomainError::AddressWrap(role))
}

/// Check the symbolic normal domain before changing the detached state image.
///
/// Native code/stack/return separation, valid memory and stable code are external
/// premises. Table *payload* validity is not checked or established here.
fn domain(a: AddressMap, length: u64, n: u64) -> Result<(u64, u64), DomainError> {
    if length > i64::MAX as u64 {
        return Err(DomainError::OutputLengthOutsideSignedDomain);
    }
    let k = (length + 3) >> 2;
    let output_end = end(a.output, length, "output")?;
    end(a.output, 3 * k, "output-cursor3")?;
    let regions = [
        ("state", a.state, end(a.state, 152, "state")?),
        ("output", a.output, output_end),
        ("input", a.input, end(a.input, n, "input")?),
        ("table-header", a.table, end(a.table, 4, "table-header")?),
    ];
    for (index, &(left, lb, le)) in regions.iter().enumerate() {
        for &(right, rb, re) in &regions[index + 1..] {
            if lb < le && rb < re && lb < re && rb < le {
                return Err(DomainError::RegionOverlap(left, right));
            }
        }
    }
    Ok((k, output_end))
}

fn bit_cell(input: &[u8], end: usize) -> u64 {
    let last = input[end - 1];
    let shift = if last == 0 { 0 } else { last.leading_zeros() + 1 };
    let word = u64::from_le_bytes(input[end - 8..end].try_into().expect("proved 8-byte window"));
    (word | 1).wrapping_shl(shift)
}

/// Preserve the constructor's raw status and partial writes on the normal domain.
///
/// Raw statuses are 0 (refused), -20 as a u64 (error), or 1 (constructed).
/// Unsupported-domain errors are separate and leave every entry state word intact.
/// A success establishes initial state only, including four nonzero bit cells;
/// it establishes no table symbols/advances, later refill, CPU or decoder result.
pub fn initialize(
    state: &mut State,
    addresses: AddressMap,
    output_length: u64,
    input: &[u8],
    table_header: [u8; 4],
) -> Result<u64, DomainError> {
    let n = u64::try_from(input.len()).map_err(|_| DomainError::InputLengthOutsideU64Domain)?;
    let (k, output_end) = domain(addresses, output_length, n)?;
    // The native routine requires this DWORD before its zero-output test. The
    // checked API requires the whole immutable header value even for length 0.
    let header = u32::from_le_bytes(table_header);
    if output_length == 0 {
        return Ok(0);
    }
    if n <= 9 {
        return Ok(RAW_ERROR);
    }
    if ((header >> 16) & 255) != 11 {
        return Ok(0);
    }
    let a = u16::from_le_bytes([input[0], input[1]]) as u64;
    let b = u16::from_le_bytes([input[2], input[3]]) as u64;
    let c = u16::from_le_bytes([input[4], input[5]]) as u64;
    let starts = [
        addresses.input.wrapping_add(6),
        addresses.input.wrapping_add(6).wrapping_add(a),
        addresses.input.wrapping_add(6).wrapping_add(a).wrapping_add(b),
        addresses.input.wrapping_add(6).wrapping_add(a).wrapping_add(b).wrapping_add(c),
    ];
    state[15] = starts[0];
    state[16] = starts[1];
    state[17] = starts[2];
    state[18] = starts[3];
    if a <= 7 || b <= 7 {
        return Ok(0);
    }
    let d = n.wrapping_sub(6).wrapping_sub(a).wrapping_sub(b).wrapping_sub(c);
    if c <= 7 || d <= 7 {
        return Ok(0);
    }
    if d > n {
        return Ok(RAW_ERROR);
    }
    state[4] = addresses.output;
    state[0] = starts[1].wrapping_sub(8);
    state[1] = starts[2].wrapping_sub(8);
    state[5] = addresses.output + k;
    state[6] = addresses.output + 2 * k;
    state[2] = starts[3].wrapping_sub(8);
    state[3] = addresses.input + n - 8;
    state[7] = addresses.output + 3 * k;
    if output_length < 4 {
        return Ok(0);
    }
    // The guards give a,b,c,d >= 8 with a+b+c+d=n-6, proving all windows.
    let ends = [6 + a, 6 + a + b, 6 + a + b + c, n];
    state[8] = bit_cell(input, ends[0] as usize);
    state[9] = bit_cell(input, ends[1] as usize);
    state[10] = bit_cell(input, ends[2] as usize);
    state[13] = addresses.input;
    state[14] = output_end;
    state[12] = addresses.table + 4;
    state[11] = bit_cell(input, ends[3] as usize);
    Ok(1)
}
