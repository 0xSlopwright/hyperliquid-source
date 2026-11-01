# constants-aws-name-parse-94: does 0x164d630 reject `\`, accept `{"Variant": null}`, and where does the 0x20 fallback meet NvTestnet?

- Component ID: `constants` (`global_constants/*`). This continues the question left by `research/work-items/constants`. It does not edit that packet, `research/components.json`, or `research/progress.json`.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Node #115 and visor were not read.
- Source commit / reference commit: main `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`. Reference submodule `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a behavior lead only. No reference source is copied into this packet.
- Claim status: observations of digest-locked bytes and of one linear disassembly. Inferences and unknowns are separated below. No gate is requested. RE-015 stays open.
- Scope included: the wrapper at `0x164d630`, the object walk it calls at `0x164e930`, the value parser `0x164b3d0`, the name matcher `0x164bad0`, the quoted-string body `0x4ebf970` and its escape consumer `0x4ebef70`, the null-literal checker `0x164e800`, and the caller select in `0x164fb80` after the call at `0x164fca8`.
- Scope excluded: a Rust reconstruction, execution of the captured binary, a proof that every input matches the reference, the other 75 names, the return byte of the missing-key helper, the duplicate-key callee, and the bare non-object path.

## Answer

`0x164d630` does not itself reject a backslash, and it does not itself parse `{"Variant": null}`. It calls `0x164e930` and, when that walk returns tag 0, rewrites the tag to 1 if a non-whitespace byte remains.

A quoted backslash is not an immediate rejection. `0x4ebf970` compares the byte with `0x5c` and calls `0x4ebef70`, which decodes `"`, `/`, `\`, `b`, `f`, `n`, `r`, and `t` and returns 0 from `xor %eax, %eax` at `0x4ebf0f2`. A zero return continues the scan. The reference string reader returns no value on the first backslash, so those decoded forms are the disagreement.

The externally tagged shape is present, split across `0x164b3d0`, `0x164e6d0`, and `0x164e800`: `{`, whitespace, a quoted string, `:`, the bytes `n` `u` `l` `l`, whitespace, `}`. The quoted form and the tagged form both store the name matcher's byte. `NvTestnet` stores `0x20`.

A parsed `NvTestnet` and a failed parse are both `ebp = 0x20` after `cmove` at `0x164fda9`. They diverge earlier. Tag 0 keeps the parsed byte and skips the drop that starts at `0x164fcc2`. Any nonzero tag, including a tag the wrapper rewrote because of trailing junk, runs that drop and then keeps the `mov $0x20, %ebp`. The file-read failure at `0x164fc56` is a third store of `0x20`, and it returns before the parser call.

## Reproduce

Working directory: repository root. Platform: Linux 7.0.0-38-generic x86_64. Python 3.14.4. GNU objdump 2.46 and GNU readelf 2.46 were available. `make doctor` reported `analysis_ready: true`, `exact_rebuild_ready: false`, and `captured_binaries_executed: false`. Ghidra, Java, and llvm-objdump were not used. Rust 1.94.1 is installed; 1.95.0 is not. No captured binary, network service, chain action, or signing operation was run.

`make verify` and `make catalogue-check` both stop on the node #115 Git LFS pointer (`artifacts/node/115/hl-node`). That object was not pulled. This packet does not change literal inventories, so `make reproduce` was not run. No `tests/test_*.py` file was added, so the global `make test` suite is outside this change. The check that covers the packet is:

```sh
python3 research/work-items/constants-aws-name-parse-94/check.py
python3 research/work-items/constants-aws-name-parse-94/check.py \
  --check research/work-items/constants-aws-name-parse-94/evidence.json
```

The first command prints `ok fdes=13 escapes=8 rejected_escapes=75 quote_arms=76 fallback=32`. The second prints `ok` and the evidence path. `check.py` hashes the node #94 file, parses `.eh_frame` with `tools/fde_extents.eh_frame_records`, and reads bytes through `tools/elf_index.sections`. It does not shell out to objdump. `--check` requires the generated JSON text to be byte-identical to `evidence.json`.

Objdump was used while reading control flow. Its text is not committed, because the banner changes with the binutils build. Addresses below are ELF virtual addresses. The checker finds the single non-`SHT_NOBITS` section that contains each address and reads `file_offset + (va - section_va)`. An FDE extent is the unwind range returned by the existing parser. It is not a new proof of a function boundary. Objdump's nearest-symbol labels are stripped-binary artifacts and are not names.

## Evidence

### Wrapper, `0x164d630`–`0x164d73e`

The caller at `0x164fca8` is a direct `e8` to `0x164d630`. The wrapper copies a cursor, stores `movb $0x80` at `0x50(%rsp)` (`c6 44 24 50 80` at `0x164d66d`), and calls `0x164e930` at `0x164d677`. The depth byte the walk later reads is at cursor+`0x48`, which is that same slot.

On return, `cmpb $0, (%rbx)` at `0x164d67c` (`80 3b 00`) skips the trailing scan when the tag is already nonzero. A zero tag loads `movabs $0x100002600, %rsi` at `0x164d69b` and then, at `0x164d6b5`:

| Bytes | Instruction | Effect |
| --- | --- | --- |
| `48 83 ff 20` | `cmp $0x20, %rdi` | A byte above 32 is not skipped |
| `77 3f` | `ja` | Join the error store |
| `48 0f a3 fe` | `bt %rdi, %rsi` | Test mask bit `byte` |
| `73 39` | `jae` | A clear bit is not skipped |

The error store is `movq $0x16, 0x58(%rsp)` at `0x164d6fa`, a call to `0x164d740`, and `mov $1, %al` at `0x164d716`, which is written back as the tag. A tag-0 parse with trailing non-whitespace becomes tag 1. The same mask immediate also appears at `0x164e964`, `0x164b3f4`, `0x164e6f8`, and `0x164e820`. Its set bits are 9, 10, 13, and 32.

### Quoted backslash

`0x4ebf970` loads the class table through the GOT slot `0x57770a8`. `.rela.dyn` reloc `R_X86_64_RELATIVE` (type 8) has addend `0x7caac8`. That 256-byte table has 34 nonzero flags, each equal to 1: bytes `0x00`–`0x1f`, `0x22`, and `0x5c`.

`cmpb $0, (%rbp,%rcx,1)` at `0x4ebf9c5` (`80 7c 0d 00 00 75 24`) leaves the plain-copy loop when the flag is set. The `jne` targets `0x4ebf9f0`, and the next compare is `cmp $0x5c, %ecx` at `0x4ebf9f4`. Equality calls `0x4ebef70` at `0x4ebfa44`. `test %rax, %rax` at `0x4ebfa49` takes the failure path when `rax` is nonzero; that path stores status 2 with `movq $2, (%rbx)` at `0x4ebfb5b`.

The escape jump table at `0x7ca728` has `0x54` signed-rel32 slots, index = byte − `0x22`. Eight arms store `movb $imm, (%rax,%r14,1)` (`42 c6 04 30`) and jump to `0x4ebf0eb`, which increments the output length and executes `xor %eax, %eax` at `0x4ebf0f2`:

| Byte | Decoded | Arm |
| --- | --- | --- |
| `"` `0x22` | `0x22` | `0x4ebeffc` |
| `/` `0x2f` | `0x2f` | `0x4ebf05c` |
| `\` `0x5c` | `0x5c` | `0x4ebf01c` |
| `b` `0x62` | `0x08` | `0x4ebf0b3` |
| `f` `0x66` | `0x0c` | `0x4ebf0d0` |
| `n` `0x6e` | `0x0a` | `0x4ebf03c` |
| `r` `0x72` | `0x0d` | `0x4ebf079` |
| `t` `0x74` | `0x09` | `0x4ebf096` |

`u` (`0x75`) is a separate arm at `0x4ebf103`. The other 75 in-range bytes target `0x4ebf149`, whose first instruction is `movq $0xc, (%rsp)`. That arm calls `0x4ebf5b0` and jumps to `0x4ebf0f4`, which is the epilogue after `xor %eax, %eax`, so the cleared-eax return is not taken. A byte that is flagged but is neither `0x5c` nor `0x22` stores code `0x10` at `0x4ebfb45` and calls `0x4ebf4e0`. A finished input stores code `0x4` at `0x4ebfaae` and calls the same writer. The writer's normal return stores status 2 with `movq $2, (%r14)` (`49 c7 06 02 00 00 00` at `0x4ebf51a`). A closing quote stores status 1 (`48 c7 03 01 00 00 00` at `0x4ebfb29`).

`0x164e6d0` compares that status with `cmpl $2, (%rsp)` at `0x164e776`. Status 2 stores tag 1 and returns without calling the name matcher. Any other status calls `0x164bad0`.

The pinned reference's string reader returns no value on `\` and on bytes `0..=0x1f`, before any name lookup. The bytes above do not do that for a backslash. A successful simple escape continues the scan.

### Tagged form and `NvTestnet`

The walk at `0x164e930` tests the first non-skipped byte with `cmp $0x7b, %edi` at `0x164e9b7` and branches to `0x164f48b` when it is not `{`. On `{` it stores `movb $0x4c, 0xf(%rsp)` at `0x164e9f2`. The eight-byte key compare at `0x164eaf3` reads `aws_name` from `0x20a458`, after `cmpq $8, 0x20(%rsp)` at `0x164eae7`. A match calls the value parser `0x164b3d0` only while that slot is still `0x4c`.

`0x164b3d0` skips with the same mask, but its first compare is `cmp $0x22, %rdi` at `0x164b403`, so `"` is inside the tested range. A quote calls `0x164e6d0`. Tag 1 returns tag 1. Any other tag indexes the 76-slot table at `0x264a88`. Each arm is `movb $index, 0x1(%rbx); xor %eax, %eax`, and every arm stays inside `0x164b3d0`–`0x164b97a`. Index 32 is `movb $0x20, 0x1(%rbx)` at `0x164b820`.

A `{` in the value parser calls `0x164e6d0` again, then requires `:` (`cmp $0x3a, %rsi` at `0x164b513`) and calls `0x164e800`. That checker skips with the mask and compares, in order, `n` at `0x164e86d` (`41 83 f9 6e`), `u` at `0x164e897` (`40 80 fe 75`), `l` at `0x164e8af` (`41 80 f8 6c`), and `l` at `0x164e8c7` (`80 f9 6c`). Success is `xor %eax, %eax` at `0x164e8cc` and a return. A zero return stores the lookup byte and tag 0 (`40 88 6b 01 c6 03 00` at `0x164b54a`). Whitespace is skipped again, and `cmp $0x7d, %esi` at `0x164b5b8` must fall through. The fall-through stores the lookup byte once more and returns tag 0 (`40 88 6b 01 31 c0` at `0x164b5ce`). The `jne` at `0x164b5b8` targets `0x164b939`.

The name matcher reaches `NvTestnet` from slot 7 of the 12-slot table at `0x264bb8` (target `0x164bf97`). At `0x164bfd4` the bytes are `movabs $0x656e74736554764e` (`NvTestne`), `xor (%rsi), %rcx`, `movzbl 8(%rsi), %edi`, `xor $0x74, %rdi`, `or %rcx, %rdi`, and `je`. The `je` targets `0x164c3a4`, which is `movb $0x20, 0x1(%rax); xor %ecx, %ecx`. The rodata spelling `NvTestnet` is the nine bytes at `0x2180ff`. The quoted path does not translate the byte: index 32 of the identity table is the same `0x20`.

### Caller fallback

`0x164fc56` is `mov $0x20, %bpl` (`40 b5 20`) on the file-read failure path. That path returns without calling `0x164d630`.

After the call, `0x164fcad` loads the tag into `%bpl` and the next byte into `%r13d`, compares the tag with 1, and `jne`s to `0x164fd8a` when the tag is not 1 (`0f 85 c8 00 00 00`). Tag 1 falls into the drop block at `0x164fcc2`. At `0x164fd9d` the bytes are `movzbl %r13b, %eax; test %bpl, %bpl; mov $0x20, %ebp; cmove %eax, %ebp` (`41 0f b6 c5 40 84 ed bd 20 00 00 00 0f 44 e8`). `cmove` replaces `0x20` only when the tag byte is zero.

A parsed `NvTestnet` is tag 0 and byte `0x20`, so `ebp` stays `0x20` because the kept byte is `0x20`. A nonzero tag also leaves `ebp` as `0x20`, after the drop. The two results are the same register value and different control flow.

### Missing key, and the unquoted backslash

A closing object compares the slot with `0x4c` at `0x164f192` (`80 7c 24 0f 4c`). If the slot is still `0x4c`, the walk calls the GOT slot `0x5770b20`. The `R_X86_64_RELATIVE` addend is `0x164b980`. That helper compares `%al` with `0x4c` (`3c 4c` at `0x164b9e9`) and executes `ud2` at `0x164ba5f` when it is equal. The byte it returns otherwise was not resolved.

Inside the walk, an unquoted token whose index is `byte + 0xffffffa5` uses the table at `0x265044`. Index 1, which is byte `0x5c`, targets `0x164edde`. That address is `lea -0x30(%r12), %eax; cmp $0xa, %al; jae 0x164f52c`, and `0x164f52c` stores code `0x0a` (`48 c7 44 24 10 0a 00 00 00`). This is a digit test in the value skipper. It is not the quoted-string escape decoder.

## Implementation and comparison

No Rust is implemented or measured. There is no Cargo manifest, build, raw/normalized comparison, or helper-closure count. The reference was not copied.

| Behavior named by the constants question | Node #94 | Basis |
| --- | --- | --- |
| Quoted `\` returns no value immediately | Disagree | `0x4ebf9f4` calls `0x4ebef70`; eight simple escapes return 0 and the scan continues |
| Bytes `0x00`–`0x1f` leave the plain string | Agree on the class flags | 34 flags, value 1, at `0x7caac8`; a flagged byte other than `\` or `"` stores code `0x10` and reaches the status-2 writer |
| Externally tagged `{`, string, `:`, `null`, `}` | Agree on those bytes | `0x164b474`, `0x164e6d0`, `0x164b513`, `0x164e86d`–`0x164e8cc`, `0x164b5b8` |
| Quoted and tagged forms use the same name byte | Agree for the locked stores | Identity arm `0x164b820` and tagged store `0x164b5ce` both write the matcher byte; `NvTestnet` is `0x20` |
| Failed parse and parsed `NvTestnet` are different results | They differ before `0x164fda9` and match in `ebp` after it | Tag 0 skips `0x164fcc2` and `cmove` keeps the byte; a nonzero tag keeps `mov $0x20, %ebp` |
| Trailing non-whitespace after a successful value | The wrapper forces tag 1 | `0x164d67c` through `0x164d716`. The reference returns when the value has been parsed |

## Inferences

- Tag 0 means the following byte is a parsed discriminant. Tag 1 means the caller should drop the returned object and substitute 32. That reading is the control flow of `0x164fd9d`, not a source-level type.
- `0x4c` means `aws_name` has not been stored yet. The walk writes it before the key loop and later replaces it with the matcher byte on a tag-0 value.
- A simple escape that decodes to the bytes of a known name still reaches `0x164bad0`, because that call is the path taken when the string status is not 2. This was not executed.
- The mask `0x100002600` skips tab, line feed, carriage return, and space, because `bt` uses the byte as a bit index and only those four bits are set.

## Unknowns

- The top-level non-`{` path at `0x164f48b` calls `0x164e1c0`. Whether it accepts a bare quoted name was not decoded.
- The byte returned by `0x164b980` when the object ends with the slot still `0x4c` was not identified. The helper `ud2`s if that byte is `0x4c`, so the returned value is some other byte, or it does not return. It is not shown to be "no value" or `NvTestnet`.
- A second `aws_name` while the slot is no longer `0x4c` goes to `0x164f57d` and calls `0x16504a0`. That callee was not decoded.
- The `\u` arm at `0x4ebf103` was not followed to a decoded scalar.
- `0x4ebf5b0` preloads `eax = 1` and tail-calls through a GOT slot. The success `xor %eax, %eax` is not on that arm. Whether every invalid escape returns nonzero was not proved past that preload. The string body treats a nonzero return as status 2.
- No input was executed, so this packet does not claim the two parsers accept the same strings. Node #115 was not compared. No component gate is requested.

## Negative controls

- The checker rejects a node #94 file whose size or SHA-256 differs.
- The quote-path table must have 76 distinct arms, and arm `i` must store `i`. A renamed or shifted arm fails.
- The `NvTestnet` immediate is the eight bytes `NvTestne` plus a compare with `t`, and its `je` must land on the `movb $0x20` at `0x164c3a4`. The following name in that matcher is not claimed.
- The class table must be exactly those 34 flags. An extra special byte fails.
- The unquoted-token slot for `0x5c` must target `0x164edde`, and `0x164f52c` must store code `0x0a`. That path is not accepted as the quoted-string rule.
- Parent-packet text that calls `0x164d630` the whole state machine is left unchanged. The correction is this packet: `0x164d630` is the wrapper.

## Results and limitations

Checks that passed: `check.py` and `check.py --check` against `evidence.json`; `make doctor` with `analysis_ready: true`. Checks that failed for a reason outside this packet: `make verify` and `make catalogue-check`, both on the node #115 LFS pointer. `make test` was not run. No hosted CI result was observed.

Nothing here completes RE-001 or RE-015. The 13 FDE rows in `evidence.json` are unwind extents, 270 through 3,455 bytes, not a function census. Indirect GOT slots are zero on disk and were resolved only through `.rela.dyn` addends.

Next question: what byte does `0x164b980` return when an object closes with the slot still `0x4c`, and does `0x164f48b` parse a bare quoted name or reject it?
