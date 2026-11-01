# RE-002: the complete fixed callee behind the write_fmt edge

The accepted formatter correspondence left the fixed rendering dependency
behind a 19-byte `Write::write_fmt` edge unqualified. This result identifies
that used callee's complete code body, rather than adding another address or
symbol census. It does not close the callee's dynamic callbacks or inputs.

Node #94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The admitted source base is `4179e174f58ea877cb803abece4a3842c614daf3`.
The independently established initial observations and rights are retained
unchanged in `fixtures/FINAL-READONLY-INTAKE.json` and its supporting records.
The maintained collector is `tools/libcore_write_fmt_leaf.py`; shared ELF/ar
and indexed FDE readers remain unchanged.

## The concrete dependency

The caller at `0x1571150` contains a GOTPCREL field at byte 15 of its complete
19 bytes. Its linked-coordinate destination is GOT slot `0x576e008`.
The actual unique, symbol-zero `R_X86_64_RELATIVE` record has addend
`0x1571d90`. A normal loader adds the unknown image load bias; this does not
claim an observed live process address.

The selected indexed FDE is 52 bytes and declares exactly
`0x1571d90..0x1571f50`: **448 code bytes**. The complete CIE and selected FDE
footprint, local index neighborhood, allocated executable section and PT_LOAD
coordinates are bound. There is no new global FDE census or source/target
unwind-behavior equivalence claim.

The admitted official libcore archive has SHA-256
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`;
its selected object member has SHA-256
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.
The unique published global/default `STT_FUNC`
`_ZN4core3fmt5write17h469843d235cc4241E` covers its entire 448-byte executable
section at section-relative value zero. The actual source code has **zero
RELA fields**. All 448 bytes match the target, SHA-256
`1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561`.
No byte is masked, normalized, trimmed or replaced.

The same complete named body exists in the independently retained default
linked ELF, Thin linked ELF and saved Thin ET_REL object. Those are pinned
inputs from the earlier recorded build, not new compiler runs. Linked ELF
comparisons remain raw only; the ET_REL object also has zero selected code
RELA fields. This compatibility does not identify the original compiler,
version, fork, flags or whole node build uniquely.

## What remains dynamic

The real tiny native view contains 138 rows and 26 local direct branches.
There are no fixed direct external calls or observed RIP-relative data operands
inside this 448-byte body. Three indirect calls remain at `0x1571e05`,
`0x1571e54` and `0x1571ef6`, plus an indirect tail jump at `0x1571f39`.
They are explicit unresolved transfers, not fixed helpers silently counted as
closed. Input-referenced tables, method targets, private types/ABI, rendering,
failure and unwind behavior remain unqualified. Other references inside the
revisited 19-byte caller are not promoted to new data-closure claims.

Keep the denominators separate: new primary code **448**, revisited caller
context **19**, accepted primary correspondence **1,456**, and the prior
supporting context **114**. The old two genuine adapter differences and all
old comparison qualifications are unchanged. No project gate advances here.

## Reproduction and controls

Use the exact already authenticated official archive; no installation,
compiler or captured executable is launched by this command:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/libcore_write_fmt_leaf.py \
  --libcore /path/to/libcore-e60dd2ab51fbc7de.rlib \
  --output /tmp/new-owned-write-fmt448
```

Optional `--default-linked`, `--thin-linked` and `--thin-object` paths select
the three full-hash-pinned retained inputs. The collector admits immutable
complete input bytes and gives GNU only a private, nonexecutable 448-byte file.
It refuses previous output paths, including broken symlinks, before input
reads. Source/provider file digests are checked before and after; trusted host
loading is assumed, not an atomic-execution or filesystem-sandbox guarantee.

Portable tests use actual tiny admitted excerpts and the actual 19-byte edge.
Actual object tests mutate serialized function/section and real relocation
metadata below archive identity. Actual capture tests mutate the selected
GOT/FDE/section/PT_LOAD fields below full-image identity. Every non-RELA byte,
including the terminal byte, remains visible to the raw comparator. No source
relocation can create a mask. Missing optional local artifacts may skip their
corresponding actual tests; a skip does not qualify an absent artifact.

```sh
HL_LIBCORE_ARCHIVE=/path/to/libcore-e60dd2ab51fbc7de.rlib \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_libcore_write_fmt_leaf.py -v
```

The maintained positive collector completed against the full-digest-admitted
capture, official archive and all three retained inputs. It reports the complete
448-byte raw match and zero source RELA fields. Ten source/portable methods pass
in normal and optimized Python. All five actual capture methods pass in fresh
normal processes, with no skips; eleven actual serialized counterfactuals also
ran in individual processes. The terminal code change remains exactly one raw
difference, while malformed used mappings are rejected below identity. Exact
commands, raw streams, source bindings and negative snapshot identities are in
`controls/`. These executions do not claim a single literal 15-method module,
original-object execution or a full current repository suite.

## Rights and scope

New Python/tests/docs are MIT. The tiny official compiled libcore excerpt
retains The Rust Project Contributors' rights under the MIT option in
`fixtures/LICENSE-MIT` and its notice; Hyperliquid capture bytes retain their
separate ownership. No Rust source or unlicensed inferred implementation was
read or copied, no compiled code was transplanted into a new Rust crate, and
no original/compiler/object/emulator execution is part of this result.

This closes one specific binary-backed source-identity prerequisite behind
the accepted formatter work. Existing generic readers could locate bytes but
did not bind this used edge to the complete licensed body and its genuine
zero-relocation status. The narrow producer and controls support that finding;
there is no standalone tooling, infrastructure or workflow change.

The independent peer caught one prototype-only linked-candidate gap: clearing
PF_X in a real retained linked ELF still left a section-only extraction accepted.
The producer now binds its actual executable PT_LOAD/section/file coordinates
through the existing reader. Real serialized PF_X and coordinate controls pass.
Selected unsupported REL/RELR metadata is refused rather than mistaken for
absence of source relocation fields. The original prototype observation is
preserved; whole-input admission already rejected changed full artifacts.
