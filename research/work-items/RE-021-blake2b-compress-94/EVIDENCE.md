# EVIDENCE — RE-021-blake2b-compress-94

## Binary

- Path: `artifacts/node/94/hl-node`
- sha256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`

## Function extent

- VA range: `0x4e9a8a0 .. 0x4e9b02c` (length 1932)
- Ret at: `0x4e9aeaf`
- Carved sha256: `df9b7ff03af68d61cb6e574cadb5fc0081e4a38a7fd35cefd030fbebea1a8788`

## ABI (from prologue bytes)

| Reg | Role |
|-----|------|
| rdi | rounds (test+je → early finalize when 0) |
| rsi | h `*mut [u64;8]` (written back) |
| rdx | m `*[u64;16]` |
| rcx | t `*[u64;2]` (`IV[4]^=t[0]`, `IV[5]^=t[1]`) |
| r8  | f final flag (`test r8d`; `cmovne` selects `~IV[6]`) |

## IV movabs (pinned)

| VA | Imm |
|----|-----|
| 0x4e9a8c8 | 0x6a09e667f3bcc908 |
| 0x4e9a8b9 | 0xbb67ae8584caa73b |
| 0x4e9a8e1 | 0x3c6ef372fe94f82b |
| 0x4e9a9a8 | 0xa54ff53a5f1d36f1 |
| 0x4e9a8f3 | 0x510e527fade682d1 |
| 0x4e9a904 | 0x9b05688c2b3e6c1f |
| 0x4e9a923 | 0x1f83d9abfb41bd6b |
| 0x4e9a8d7 | 0x5be0cd19137e2179 |
| 0x4e9a919 | 0xe07c265404be4294 (= ~IV[6]) |

## SIGMA

- Lea at `0x4e9a99e` → `0x7c4ad0` (anchor); table base `0x7c4a90` as u64 indices.
- SIGMA[0] = 0..15; SIGMA[1] = 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3.

## G rotates

Exactly 8× each: `rol imm 0x20`, `0x28`, `0x30`, `1` (= RFC 7693 ror 32/24/16/63).

## Source pin

- VA `0x1e9dcb`, length 102:
  `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/revm-precompile-16.0.0/src/blake2.rs`

## EIP-152 behavioural proof (Unicorn on carved bytes)

| Vector | rounds | f | output sha256 (of 64-byte h) |
|--------|--------|---|------------------------------|
| 4 | 0 | 1 | (see JSON; output starts `08c9bcf3…`) |
| 5 | 12 | 1 | (output starts `ba80a53f…` = BLAKE2b-512("abc")) |
| 6 | 12 | 0 | (output starts `75ab69d3…`) |
| 7 | 1 | 1 | (output starts `b63a380c…`) |

All four: `byte_identical=true` under Unicorn emulation of the carved bytes.

## Wiring limitations

See README "What this does not claim": 0x09 dispatch, 213-byte check, f∈{0,1} reject, gas/round not statically pinned.
