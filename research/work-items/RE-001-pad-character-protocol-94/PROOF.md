# Character request protocol, node #94

The complete selected function is `0x157cfa0..0x157cfff`, 95 bytes and
37 decoded rows. Its exact indexed FDE encloses this extent. The following
`write_str` body starts at `0x157d000`; its 622 bytes and the intervening byte
are outside this proof. The node SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

The prior artifact packet already observed this 95-byte correspondence as an
opaque supporting edge. The new result is the conditional request/state
contract and independently authored Rust. The old 1,456-byte primary artifact
denominator and other opaque edges receive no additional identity credit.

## Complete raw roles and data binding

`pad_character_protocol_static.py` accounts for every byte with 37 finite
operand/control witnesses. These are static checks of one supported body,
not a PC/register/memory evaluator. The retained GNU listing is explanatory;
the certificate uses raw bytes, widths and relative displacements.

The official research archive is the licensed Rust 1.94.1 libcore with SHA-256
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`.
Its exact member hash is
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.
The selected complete `PadAdapter as Write::write_char` FUNC occupies all
95 bytes of its executable section. This is compatible artifact attribution,
not unique original compiler, source, nominal type or ABI identity.

Exactly one source code relocation is present: the four-byte PC32 field at
offset 31, addend -4, to a defined four-byte OBJECT. Its raw data is four
spaces. The captured signed RIP displacement reaches `0x20a058`, whose
four file-backed bytes equal that object. Only those actual four relocation
bytes are excluded from the code comparison: all 91 other bytes agree.

The selected 48-byte source layout has a typed absolute relocation at +32
to this complete FUNC. The captured layout at `0x5674210` is raw-equal;
its +32 cell is file-backed for eight bytes and has one symbol-free
RELATIVE relocation to `0x157cfa0`. These are static loader inputs, not
observed runtime pointers. No behavior is inferred for the other cells.

## Native request and state relation

Use D for receiver+0, V for receiver+8 and N for the pointer at receiver+16.
These are role names, not recovered Rust fields or types.

1. Offsets 11, 15 and 18 cache N, D and V before any callback. Offset 22
   samples the flag byte. A zero sample branches directly to offset 71.
2. A nonzero sample requests exactly four spaces through the method read
   from cached V+24. D is the cached destination. The complete low 32-bit
   character argument is saved in R12D and restored to ESI across this call.
3. Offset 56 tests AL, not EAX or the whole return register. A nonzero AL
   takes the normal error epilogue, writes low AL=1 and returns. This path
   has no controller write through N and no character request. Callback
   edits to N therefore remain visible under the separated-role premises.
4. Both successful routes meet at offset 71, where **full ESI** is compared
   with scalar 10. SETE writes exactly one byte through cached N. Thus
   U+010A and U+1000A do not set the flag merely because their low byte is LF.
5. Only after that store does offset 78 load the current character method
   from cached V+32. Offset 82 restores cached D. The common epilogue
   restores the saved registers and tail-jumps to that method. There is no
   successor in this body that canonicalizes its returned AL.

Consequently, indent failure returns low8 one without an owned flag store;
otherwise the owned LF-predicate store precedes the character request and
that callback's low8 result and flag changes survive. An indent-success
callback's flag change is overwritten by the owned predicate store. An
indent callback can change subsequent method selection: cached V does not
mean a cached method entry. A NUL character still causes a character request.

## Closed safe implementation domain

The existing byte operation remains `write_indented_chunks`; its callbacks'
nonzero status becomes one. The new operation has a shared proxy with two
real request methods, `write_bytes` and `write_character`, and accepts a
valid Rust `char` and `&Cell<u8>`. It neither converts the character to UTF8
nor supplies a renderer.

The proxy bridge must correspond to entry-cached D/V and fixed N while
performing each operation with current method behavior. The proxy may change
its later character behavior and any flag byte during the indent request.
The tests model this with a scripted mode change. Safe reference validity,
whole-call role separation and normal callback returns are stronger premises
than arbitrary raw native pointers. In particular, N/receiver/table/own-frame
aliasing, concurrency, unwinding and a modified return frame are excluded.

The five saved registers occupy 40 bytes and are restored on both native
exits. Normal callbacks must honor the actual callee-saved and frame
obligations. We do not treat a passing proxy as proof those obligations hold
for every real callee.

The status result is a chosen **low8 projection**. Script statuses 2, 128 and
255 distinguish pass-through from normalization; they do not establish valid
discriminants of an original `fmt::Result`. Upper RAX and high32 RSI remain
unqualified: the indent route restores ESI and zero-extends it, while the
no-indent route need not establish identical high RSI bits. These distinctions
are not hidden in an ABI-equivalence claim.

## Independent expectations and controls

`ORACLE-FREEZE.json` binds a reference frozen before any new character Rust.
Its 320 input-only stimuli and separate expected transcripts cover all three
normal routes, arbitrary nonzero flag bytes, low8 callback statuses, callback
flag edits, and a byte callback changing the subsequent character method.
The reference is the finite three-case logical relation above; it reads no
production Rust and evaluates no captured instructions.

The Rust library's complete previous byte source is retained as a byte-for-byte
prefix. Its original driver and all 3,023 byte fixtures remain unchanged.
Character tests link the real library externally, so the old byte runner and
its original cfg(test) program remain independently usable. The input-only
character client receives the 11 stimulus fields and prints actual status,
final flag/mode and actual requests; it does not receive expected traces.

Native below-identity controls change actual operand widths, method slots,
branch destinations, saved character arguments, indentation bytes and typed
relocation/FDE relationships. A source/target pair with the same wrong
low-byte predicate must still fail the supported full32 certificate. Build
controls independently change Rust status, predicate and store ordering and
require normal-row mismatches plus real assertion failures. Results are
reported only after actual execution of our authored code.

No complete formatter, parent controller, original ABI, full node behavior,
captured execution, whole-ELF equality or acceptance gate is claimed.
