# foundation-length-prefix-encode-94: what does the length-prefix encode window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-length-prefix-encode-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the big-band calls category's gate-singleton slice after the small-band queue was exhausted.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 148-byte FDE window, its twelve int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the memcpy@plt call edge, and the exact length-prefix encode rule over capacity, length, and the header.
- Excluded: the memcpy implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose length-prefix encode rule reads directly from its own bytes: choose a 1-, 2-, or 3-byte header from the length class, check the capacity against the total, write the header plus the data, and return the total — or return -70 without writing anything when the capacity is short. It is the first packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5571600`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.132 against the divide-by-million window, 0.143 against the scaled-count window, 0.071 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.195 against the cached-pointer-refresh window, 0.103 against the min-cap gap-check window, 0.120 against the offset-equality window, 0.059 against the two-mode limit-check window, 0.157 against the global-bounds-gated equality window, 0.083 against the struct-init flag-pack window, 0.121 against the all-records flag-scan window, 0.143 against the helper low-byte equality window, 0.105 against the byte-gate counter window, 0.067 against the triple-min inequality window, 0.098 against the u32 second-field equality window, 0.133 against the cache-refresh zero-test window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, mov, push, mov, cmp, ja, lea, cmp, jb, lea, mov, mov, add, mov, call, mov, pop, ret, nop, xor, cmp, seta, add, movsxd, add, cmp, jb, cmp, jne, mov, shl, add, mov, mov, jmp, mov, shl, add, mov, mov, jmp, nop, mov, mov, pop, ret`) is a singleton among 28,811 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_length_prefix_encode.py --check research/work-items/foundation-length-prefix-encode-94/evidence.json
python3 -m unittest tests.test_foundation_length_prefix_encode -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5571600 --stop-address=0x55716a0 artifacts/node/94/hl-node
objdump -d --start-address=0x55739f0 --stop-address=0x5573f89 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002d14a4` (this window), `0x002d14c4` (the next FDE, bounding the padding), and `0x002d1784` (the first caller) — all three use CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002d14a4` describes `[0x5571600, 0x5571694)`, 148 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5571693`).
- The unwind index stride to the next entry is 160 bytes, ending at `0x55716a0`, only because twelve `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "160-byte FDE-bounded" would overstate the frame by those twelve padding bytes, and the checker locks the 148-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x5573b9c`, verified as an instruction start by disassembly from its containing FDE start (`0x55739f0`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one capacity-checked, length-prefixed copy

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5571600` | `endbr64` | Entry |
| `0x5571604` | `mov r8, rdx` | Save the data pointer |
| `0x5571607` | `push rbx` | Save callee-saved register |
| `0x5571608` | `mov rdx, rcx` | Length becomes the memcpy length argument |
| `0x557160b` | `cmp rcx, 0x1f` | Small-class test |
| `0x557160f` | `ja 0x5571640` | Longer lengths take the big path |
| `0x5571611` | `lea rbx, [rcx + 1]` | Small total: length + 1 |
| `0x5571615` | `cmp rsi, rbx` | Capacity vs total |
| `0x5571618` | `jb 0x5571688` | Short capacity fails |
| `0x557161a` | `lea eax, [rcx * 8]` | Small header value |
| `0x5571621` | `mov byte [rdi], al` | Store the 1-byte header |
| `0x5571623` | `mov eax, 1` | Small header size |
| `0x5571628` | `add rdi, rax` | Advance output past the header |
| `0x557162b` | `mov rsi, r8` | Data pointer becomes the memcpy source |
| `0x557162e` | `call 0x5660100` | memcpy@plt; its body is excluded |
| `0x5571633` | `mov rax, rbx` | Return the total |
| `0x5571636` | `pop rbx` | Epilogue |
| `0x5571637` | `ret` | Return |
| `0x5571638` | `nop` (8 bytes) | Alignment padding between paths |
| `0x5571640` | `xor eax, eax` | Clear the header-size register |
| `0x5571642` | `cmp rcx, 0xfff` | Medium-class test |
| `0x5571649` | `seta al` | 1 iff length > 0xfff |
| `0x557164c` | `add eax, 2` | Header size: 2 or 3 |
| `0x557164f` | `movsxd rbx, eax` | Header size, sign-extended |
| `0x5571652` | `add rbx, rcx` | Total: length + header size |
| `0x5571655` | `cmp rsi, rbx` | Capacity vs total |
| `0x5571658` | `jb 0x5571688` | Short capacity fails |
| `0x557165a` | `cmp eax, 3` | Large-class test |
| `0x557165d` | `jne 0x5571670` | Header size 2 takes the medium path |
| `0x557165f` | `mov eax, ecx` | Large header value, low 32 bits of length |
| `0x5571661` | `shl eax, 4` | |
| `0x5571664` | `add eax, 0xc` | Large header: length * 16 + 12 |
| `0x5571667` | `mov dword [rdi], eax` | Store the 4-byte header |
| `0x5571669` | `mov eax, 3` | Large header size |
| `0x557166e` | `jmp 0x5571628` | Join the copy path |
| `0x5571670` | `mov eax, ecx` | Medium header value, low 32 bits of length |
| `0x5571672` | `shl eax, 4` | |
| `0x5571675` | `add eax, 4` | Medium header: length * 16 + 4 |
| `0x5571678` | `mov word [rdi], ax` | Store the 2-byte header |
| `0x557167b` | `mov eax, 2` | Medium header size |
| `0x5571680` | `jmp 0x5571628` | Join the copy path |
| `0x5571682` | `nop` (6 bytes) | Alignment padding before the failure path |
| `0x5571688` | `mov rbx, -70` | Failure value |
| `0x557168f` | `mov rax, rbx` | Return -70 |
| `0x5571692` | `pop rbx` | Epilogue |
| `0x5571693` | `ret` | Return |

- The rule, over capacity (`rsi`), length (`rcx`), data (`rdx`), and output (`rdi`), is: let `h = 1` if `length <= 0x1f`, `2` if `length <= 0xfff`, else `3`; the header is `length * 8` as one byte if `h == 1`, `length * 16 + 4` as two bytes if `h == 2`, `(length & 0xffffffff) * 16 + 12` as four bytes if `h == 3`; the total is `length + h`; if `capacity < total`, write nothing and return `-70` (`0xffffffffffffffba`); else write the header followed by `length` bytes copied from data via memcpy and return `total`.
- The class boundaries are exact and verified on both sides: `0x1f` is the last small length and `0x20` is the first medium length; `0xfff` is the last medium length and `0x1000` is the first large length. The small header is exact because `length * 8 <= 248` for `length <= 31`; the medium header is exact because `length * 16 + 4 <= 65524` for `length <= 0xfff`.
- The header formulas for the medium and large classes use `ecx`, so a length above 32 bits truncates the header to its low 32 bits while the total and the memcpy length stay full 64-bit. That edge is recorded in evidence with only the header, total, and result checked, because materializing a 4 GiB copy is out of scope; the truncation itself follows directly from the `mov eax, ecx` bytes.
- Both capacity checks precede their stores, so the failure path writes nothing: no header byte, no word, no dword, and no copy. The failure value is exactly -70, not a generic error code.
- The memcpy call passes `rdi = output + h`, `rsi = data` (the saved entry `rdx`), and `rdx = length` (entry `rcx`, never reassigned after the initial move). The callee at `0x5660100` is the memcpy@plt stub (`jmp *GOT`, `push 1`, `jmp PLT0`), not an FDE start, so no body size is claimed for it — the same exclusion pattern as the memcmp@plt callees of the triple-min inequality and u32 second-field equality windows. The memcpy implementation behind the stub is excluded.
- The single caller at `0x5573b9c` sits in a 1,433-byte FDE (`0x55739f0..0x5573f89`, `.eh_frame+0x002d1784`, CIE `0x00000000`, the same CIE as the window). The caller's own role is not established beyond the call site.

## Inferences

- Inferred label: length-prefix encode helper. The rule is observed and proven above; only the label is inferred.
- The header values read as a length tag: the small header stores `length * 8` (a byte-granular length shifted into the high bits of the byte), the medium header stores `length * 16 + 4`, and the large header stores `length * 16 + 12`, so the low bits of the stored header distinguish the header width. That reading is an inference only; the packet claims the arithmetic, not the format's meaning.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the call site.

## Unknowns

- The source-level name and types of this window, its output buffer, its capacity, and its data.
- What format the length-prefixed encoding belongs to, and what the header's low bits mean to its reader.
- Why the failure value is -70, and whether any caller distinguishes it from other failures.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The memcpy implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
