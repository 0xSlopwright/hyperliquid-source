use crate::ConnectionId;

/// Keccak-256 absorb rate established by the target state initialization.
pub const KECCAK_RATE: usize = 136;
/// Keccak delimiter established by the target (`SHA3-256` uses `0x06`).
pub const KECCAK_DELIMITER: u8 = 0x01;
pub const KECCAK_OUTPUT_LENGTH: usize = 32;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const RHO_ROTATIONS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI_LANES: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Computes Keccak-256 with the target-observed rate and delimiter.
#[must_use]
pub fn keccak256(message: &[u8]) -> ConnectionId {
    let mut state = [0u64; 25];
    let mut chunks = message.chunks_exact(KECCAK_RATE);
    for block in &mut chunks {
        absorb(&mut state, block);
        keccak_f1600(&mut state);
    }

    let remainder = chunks.remainder();
    let mut final_block = [0u8; KECCAK_RATE];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] = KECCAK_DELIMITER;
    final_block[KECCAK_RATE - 1] |= 0x80;
    absorb(&mut state, &final_block);
    keccak_f1600(&mut state);

    let mut output = [0u8; KECCAK_OUTPUT_LENGTH];
    for (lane, bytes) in state[..KECCAK_OUTPUT_LENGTH / 8]
        .iter()
        .zip(output.chunks_exact_mut(8))
    {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    ConnectionId::from_bytes(output)
}

fn absorb(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), KECCAK_RATE);
    for (lane, bytes) in state
        .iter_mut()
        .zip(block.chunks_exact(8))
        .take(KECCAK_RATE / 8)
    {
        let mut word = [0u8; 8];
        word.copy_from_slice(bytes);
        *lane ^= u64::from_le_bytes(word);
    }
}

fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        let mut column = [0u64; 5];
        for x in 0..5 {
            column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let delta = column[(x + 4) % 5] ^ column[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= delta;
            }
        }

        let mut carried = state[1];
        for (&lane, &rotation) in PI_LANES.iter().zip(&RHO_ROTATIONS) {
            let next = state[lane];
            state[lane] = carried.rotate_left(rotation);
            carried = next;
        }

        for y in 0..5 {
            let offset = y * 5;
            let row = [
                state[offset],
                state[offset + 1],
                state[offset + 2],
                state[offset + 3],
                state[offset + 4],
            ];
            for x in 0..5 {
                state[offset + x] ^= (!row[(x + 1) % 5]) & row[(x + 2) % 5];
            }
        }
        state[0] ^= round_constant;
    }
}

#[cfg(test)]
mod tests {
    use super::keccak_f1600;

    #[test]
    fn zero_state_permutation_matches_the_keccak_f1600_known_answer() {
        let mut state = [0u64; 25];
        keccak_f1600(&mut state);
        assert_eq!(
            state,
            [
                0xf125_8f79_40e1_dde7,
                0x84d5_ccf9_33c0_478a,
                0xd598_261e_a65a_a9ee,
                0xbd15_4730_6f80_494d,
                0x8b28_4e05_6253_d057,
                0xff97_a42d_7f8e_6fd4,
                0x90fe_e5a0_a446_47c4,
                0x8c5b_da0c_d619_2e76,
                0xad30_a6f7_1b19_059c,
                0x3093_5ab7_d08f_fc64,
                0xeb5a_a93f_2317_d635,
                0xa9a6_e626_0d71_2103,
                0x81a5_7c16_dbcf_555f,
                0x43b8_31cd_0347_c826,
                0x01f2_2f1a_11a5_569f,
                0x05e5_635a_21d9_ae61,
                0x64be_fef2_8cc9_70f2,
                0x6136_7095_7bc4_6611,
                0xb87c_5a55_4fd0_0ecb,
                0x8c3e_e88a_1ccf_32c8,
                0x940c_7922_ae3a_2614,
                0x1841_f924_a2c5_09e4,
                0x16f5_3526_e704_65c2,
                0x75f6_44e9_7f30_a13b,
                0xeaf1_ff7b_5cec_a249,
            ]
        );
    }
}
