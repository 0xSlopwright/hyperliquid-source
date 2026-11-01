# Official libcore correspondence: bounded parent/adapter intake

The existing admitted Rust1.94.1 target-library archive contains the exact
390-byte `core::fmt::builders::DebugStruct::field` symbol and a622-byte
`PadAdapter::write_str` symbol. The names are facts about that licensed
artifact, not original captured symbol/type/compiler identity.

The2,917,630-byte archive SHA256 is
ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256.
An independent AR reader binds the exact object member (2,871,296 bytes,
SHA25657ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13).
It parses actual ELF64-LE x86_64 ET_REL section/symbol/RELA records. The
selected symbols start at section offset0, have actual STT_FUNC sizes390/622
and code section indices381/883. No header/label guess substitutes for them.

The archive's actual installed file hash agrees with the already admitted
103-file toolchain identity; its existing official rust-std archive checksum,
COPYRIGHT, MIT and Apache notices are bound separately. This intake reads no
Rust implementation source and installs/downloads/builds nothing. Existing
standard-library license exceptions remain in the preserved COPYRIGHT-library
notice. Static artifact inspection does not transfer ownership of the
captured program or attribute the whole node to this archive.

## Independently admitted capture and exact denominators

One immutable91,774,280-byte node94 object was SHA256-admitted as
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
It was released after retaining only these1,012 code bytes and72 unique
referenced data/cell bytes (82 bytes counting repeated references). There is
no full-image fixture. Actual executable section/PT_LOAD mappings and exact
FDEs bind [0x1571f50,0x15720d6)390B and[0x157d000,0x157d26e)622B.
Code hashes are e6aec76f57413451c7a873712558e50e18c6f30b2001b6777c3fd29fda32388d
and d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4.

Parent390: nine actual object RELA fields occupy36 nonoverlapping bytes.
Their kinds are seven R_X86_64_PC32 and two R_X86_64_GOTPCREL, all with
addend-4 and width4. Tiny GNU decodes verify each is the final4-byte RIP
field of the corresponding actual instruction. All354 other bytes match;
exactly36 raw bytes differ, all within those actual relocation fields.
No guessed relocation mask, trimmed body or patched output was used.
This is a complete relocation-qualified **code** correspondence, not raw
whole-body byte equality or a from-source rebuild.

Adapter622: its one actual PC32 field occupies4 bytes. The other618-byte
denominator contains616 equal bytes and **two genuine raw differences**.
The four relocation-field bytes also differ, making six raw differences.
At offset0x1d0 the official code has `4d8d2437`:
`lea r12,[r15+rsi*1]`; the capture has `4e8d243e`:
`lea r12,[rsi+r15*1]`. The byte offsets0x1d0 and0x1d3 are not ELF relocation
fields. The two instructions have the same closed64-bit addition expression
and no flag/memory effect, but that static arithmetic fact does not remove
the raw discrepancy. No commutation mask, rewrite, post-build patch, different
compiler invocation or flag search was attempted.

Combined code denominator1,012B:40 actual relocation-field bytes;972
non-relocation bytes of which970 match and two differ. Raw equal bytes also
number970;42 raw bytes differ. Do not report972 matching bytes or complete
adapter reproduction.

## Narrow data and link corroboration

The parent's actual referenced2/3-byte literals all agree with the respective
artifact data: `, `, ` { `, `: `, ` {\n`, `,\n`. The `: ` reference repeats.
The adapter's actual4-byte referenced constant is four spaces in both.
These are16 unique fixed literal bytes, with18 read bytes counting the
repeated `: ` reference.

The parent references captured48B at0x5674210. The matching official data
section has three actual8-byte R_X86_64_64 fields at offsets24/32/40.
All24 fixed bytes match, including literal qwords0/24/8. Raw48-byte arrays
happen to agree because pointer fields are zero placeholders; runtime pointer
identity must instead use the actual relocation records.

Captured .rela.dyn has R_X86_64_RELATIVE addends:

- 0x5674228 (+24) ->0x157d000, corresponding to official write_str.
- 0x5674230 (+32) ->0x157cfa0, while the official symbol names write_char.
- 0x5674238 (+40) ->0x1571150, while the official section names Write::write_fmt.

The two parent GOTPCREL fields both resolve the captured slot0x576e330;
its actual RELATIVE addend is also0x157d000. Thus the linked parent references
the separately inspected adapter through both the direct GOT and data slot.
The other two captured method bodies were not admitted or compared: their
function identity, semantics and compatible instruction bytes remain unknown.
The fixed-size data agreement does not prove the original Rust private ABI,
whole vtable/runtime correctness or caller layout.

## Finite outcome and limits

GO for one coherent, scoped RE-002 artifact-correspondence outcome if the
coordinator later authorizes it: exact parent relocation-qualified code/data
facts, adapter near-correspondence with its refuting two-byte exception, and
actual limited link evidence. NO_GO for claiming raw full adapter reproduction,
original Rust version/compiler/source identity, source build, full ELF equality,
semantic closure or a completed reconstruction gate. Other compatible archives
or LLVM instruction selection could explain the commuted LEA; none was measured
here and no wider/version/config grid is proposed.

A subsequent meaningful question would separately qualify the two remaining
captured method targets or independently reconstruct/produce the exact adapter
encoding under an approved maintained-source mechanism. It must preserve these
raw exceptions, not treat them as arbitrary normalization. No broader scope,
repository edit or PR is authorized by this finite intake itself.
