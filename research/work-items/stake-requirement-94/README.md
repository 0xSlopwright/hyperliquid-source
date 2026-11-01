# RE/Staking: Exchange Stake Requirement Calculation & Monomorph Dispatch (node #94)

- Component ID: RE/Staking (`l1/exchange/stake_requirement.rs`, `l1/exchange/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/exchange/stake_requirement.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of 4 FDEs totaling 1,906 bytes:
    - `0x2512770..0x2512ac8` (856 B): `collect_requirements_spot`
    - `0x26b58d0..0x26b59e0` (272 B): `RequirementIterator::next_spot`
    - `0x487ccd0..0x487ced1` (513 B): `collect_requirements_perp`
    - `0x47bcea0..0x47bcfa9` (265 B): `RequirementIterator::next_perp`
  - Observation for exact 4x4 multiplier matrix in `.rodata` (`0x3f0994`) and `.data.rel.ro` (`0x5732f60`),
    state tier byte offsets (`+0x8f2` for Spot, `+0x1372` for Perp), and source panic records at `0x56b81b0`, `0x5713008`, `0x571f590`
    mapping to `/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs:5:62`.
  - Inference for high-level Rust enum variants (`StakeRequirementAction`, `StakeRequirementScope`), trait structures (`StakeRequirementState`), and delegation lookup models.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - Four FDE extents:
      - `0x2512770..0x2512ac8` (856 B; file offset `0x2511770..0x2511ac8`).
      - `0x26b58d0..0x26b59e0` (272 B; file offset `0x26b48d0..0x26b49e0`).
      - `0x487ccd0..0x487ced1` (513 B; file offset `0x487bcd0..0x487bed1`).
      - `0x47bcea0..0x47bcfa9` (265 B; file offset `0x47bbea0..0x47bbfa9`).
    - Numeric bounds and constants:
      - `N_STAKE_REQUIREMENT_KINDS = 4`.
      - Four selected table cells per row; a tier-byte range check is not present in these iterator bodies.
      - Iterator count bounds (not a tier-byte check): index check `cmp rcx, 0x4` and kind boundary `cmp r14, 0x3`.
      - Saturating count addition: `cmovae` / `cmovb` against `0xffffffffffffffff`.
      - Multiplication and overflow detection: `mul QWORD PTR [...]` followed by `jo`.
    - Exact 4x4 multiplier values (raw staking units):
      - Kind 0: `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
      - Kind 1: `[50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000]`
      - Kind 2: `[150_000, 80_000_000_000_000, 15_000_000_000, 80_000_000_000_000]`
      - Kind 3: `[200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000]`
    - Source panic records in `.data.rel.ro`:
      - `0x56b81b0`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
      - `0x5713008`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
      - `0x571f590`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline structural verification only).
    - No live trading network, validator signing keys, or consensus execution harness.
    - Node #115 and visor targets excluded.

Original padded spans and exports are preserved in `../RE-001-nxtlvlfirm-review-20261031/original-submissions/241/`; this packet supersedes their FDE labels.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'"

# Verify packet integrity against sha256 manifest
(cd research/work-items/stake-requirement-94 && sha256sum -c MANIFEST.sha256)

# Optional human cross-check: disassemble the 4 FDE extents
objdump -d -M intel --start-address=0x2512770 --stop-address=0x2512ac8 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x26b58d0 --stop-address=0x26b59e0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x487ccd0 --stop-address=0x487ced1 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x47bcea0 --stop-address=0x47bcfa9 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `collect_requirements_spot` | `0x2512770..0x2512ac8` | `0x2511770..0x2511ac8` | 856 B | `4b198eb18d175d64eec2f5b94bb91862bae95df787a7e758b61fcef0ad94c3cb` |
| `RequirementIterator::next_spot` | `0x26b58d0..0x26b59e0` | `0x26b48d0..0x26b49e0` | 272 B | `ba2138bba3abe52183363f9f0ca5ca6fe5da70cd49f2c5e1885dd6a0a93f637f` |
| `collect_requirements_perp` | `0x487ccd0..0x487ced1` | `0x487bcd0..0x487bed1` | 513 B | `c4b3b2a81799472eac225ba61d6a822eb8f584d8ab7c6dacbef89d2708b3a933` |
| `RequirementIterator::next_perp` | `0x47bcea0..0x47bcfa9` | `0x47bbea0..0x47bbfa9` | 265 B | `c778cafb52d52b0621aec4466b0bac8dcd2457682919ec701f9f2b87f82b16c4` |

#### A. Monomorphized Iterator Dispatch
- The iterator is hard-bounded to 4 entries (`0..=3`). The loaded tier byte has no local bounds check; validity of its upstream domain remains unresolved.
- In `0x26b58d0` (Spot), the state tier byte is loaded from `[r15 + 0x8f2]`.
  The multiplier table is resolved via four signed 32-bit displacements at `0x3f0994` pointing into `.rodata` base.
- In `0x47bcea0` (Perp), the state tier byte is loaded from `[r15 + 0x1372]`.
  The multiplier table is resolved via four absolute 64-bit pointers at `0x5732f60` in `.data.rel.ro`.
- Both table representations resolve to the identical underlying 4x4 raw multiplier values:
  - Kind 0 (`0x20c2a0`): `100,000`, `10,000,000,000`, `10,000,000,000`, `50,000,000,000,000`
  - Kind 1 (`0x20c040`): `50,000`, `20,000,000,000,000`, `5,000,000,000`, `20,000,000,000,000`
  - Kind 2 (`0x20c760`): `150,000`, `80,000,000,000,000`, `15,000,000,000`, `80,000,000,000,000`
  - Kind 3 (`0x20c420`): `200,000`, `50,000,000,000,000`, `10,000,000,000`, `50,000,000,000,000`

#### B. Caller Collection & Aggregation
- `0x2512770` and `0x487ccd0` invoke their respective iterator monomorphs in a loop.
- They allocate heap storage for up to 4 elements (capacity 4, elements 0..4, initial buffer size 0x20 = 32 bytes) and collect results into a `Vec<u64>` vector.
- The caller loops use checked addition and overflow handling; opaque helper behavior and whole-caller equivalence are not established.

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following high-level role models are inferred based on search leads from `references/can1357-hl/l1/exchange/stake_requirement.rs`:
- Function signatures:
  - `per_kind_requirements<S: StakeRequirementState>(state: &S, scope: StakeRequirementScope, user: &Address, action: StakeRequirementAction) -> Result<[Stake; 4], StakeRequirementError>`
  - `total_requirement_saturating(per_kind: [Stake; 4]) -> Stake`
- Inferred enum: `StakeRequirementAction`:
  - `Kind0 = 0`, `Kind1 = 1`, `Kind2 = 2`, `Kind3 = 3`: adds 1 to prospective kind count.
  - `ExistingOnly = 4`: pure check against existing live counts.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Enforce the exact 4x4 multiplier table values matching both Spot and Perp monomorphs.
2. Establish the upstream tier-byte domain before implementing unchecked table indexing.
3. Detect `u64` multiplication overflow with fail-closed error handling.
4. Correctly aggregate requirements across the 4 kinds.
5. Be independently authored under MIT license without copying from unlicensed reference repositories.
6. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extents validated: 4/4 (1,906 B total).
  - Multiplier tables verified across both monomorphs: 16/16 cells (100% agreement).
  - Panic source records mapped: 3/3 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs:5:62`).
- Limitations & Inferences:
  - User delegation balance lookups and auxiliary validator tree checks occur in caller routines outside these 4 FDEs.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `available_delegated_stake` query the delegation map and validate active validator status?
