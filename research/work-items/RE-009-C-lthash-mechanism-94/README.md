# RE-009-C — LtHash-style lattice accumulator mechanism (node #94)

## Component ID
RE-009-C `lthash-mechanism-94`. Related: #262 (field identities). Nothing is imported from #262.

## Target release
`hl-node` #94, 91,774,280 bytes, sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

## Source commit
This packet was built off main `1f8c67c63ca4794c9689235471c60297f8a5c985`.

## Claim status
**Mechanism: verified from instructions.** The name "LtHash" is used because it fits the evidence. The identity is not proven.

## Scope
**Included:** three leaf functions. Each one does the following:
1. Hashes an entry with blake3 and reads 0x800 bytes of XOF output.
2. Adds the result into a 0x800-byte lattice of 1024 **big-endian** u16 words. The add wraps mod 2^16.
3. Saturating-adds two u64 counters in a 0x810-byte state (at +0x800 and +0x808).
4. Merges states with the same word-wise add.

It also covers the direct call chain from the top function 0x3269ae0 to each leaf.

**Excluded:**
- The field identities (accounts, contracts, storage). These are a Location-supported inference, consistent with #262.
- Hash input serialisation.
- Any comparison with a reference LtHash implementation.
- The writer 0x32699c0, beyond its call site.

## Reproduce
```
python3 -O -B tools/lthash_mechanism.py > out.json      # sha256 9450c6225fbc78446bfd7813592ec7e9700006c1fa0bf9ad567216ddb703b12a
python3 -O -B research/work-items/RE-009-C-lthash-mechanism-94/verify.py
python3 -O -B research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py
python3 -B -m unittest tests.test_lthash_mechanism        # 12 tests
```
Tool versions: Python 3.13.5 and GNU objdump 2.44 (Debian), used only for bounded extents. The output is byte-identical under PYTHONHASHSEED 0, 7 and 99.

## Evidence
All coordinates are virtual addresses (VAs). The pinned per-leaf VAs, calls, loop bounds and block sha256s are in `lthash-mechanism.json`.
- **Byte order:** each lane is `movzx` WORD load → `rol r16,0x8` (`66 c1 cX 08`) → 32-bit add → `rol r16,0x8` → `mov` WORD store. These are big-endian words. There is no movbe or bswap.
- **Entry loop:** rax = 1..0x401 step 2, 2 lanes per iteration. That is 512 × 2 = 1024 words (0x800 bytes). 0x401 is the loop bound, not the word count. The merge loop runs 0..0x400 step 2, which is also 1024 words.
- **Counters:** add, then `mov rcx,-1` with cmovb/cmovae, which saturates at 2^64−1.
- **XOF:** blake3 new/update/xof slots 0x57700c0, 0x57700c8 and 0x57700b0, with XOF length 0x800. All links are direct rel32 calls; there is no vtable.

## Implementation and comparison
Not yet implemented.

## Results and limitations
- 3/3 leaves decoded.
- 6/6 loops (3 entry, 3 merge), all 1024 words, big-endian.
- 3/3 count blocks saturating.
- `independent_verify.py` checks 46 items, including 37 key VAs and 9 block hashes, with errors=0.
- Tamper tests cover all 37 key VAs, for both the tool and the independent verifier.

Limitations:
- No caller-completeness scan has been run yet. It is pending the full `.text` scan.
- `make` and the full suite have not been run.

Next question: does any caller outside 0x3269ae0 reach the three leaves? A full `.text` rel32 scan will answer that.

## What this does not claim
- It does not claim this is a specific published LtHash. "LtHash" is only a fitting name.
- It does not claim the accounts/contracts/storage identities. Those are inference, consistent with #262.
- It does not claim what bytes are hashed, or that this is a security property.
- It does not claim to have found every caller.
