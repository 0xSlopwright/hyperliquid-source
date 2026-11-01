# Chosen higher-order field request controller

This `no_std` library, with no registry dependencies, implements a qualified logical projection
of node #94's 390-byte parent field helper at `0x1571f50..0x15720d6`.
It requires **real supplied writer and value callbacks**. It does not implement
the opaque original value formatter, an original fmt type/vtable/ABI, physical
rendering, or the complete node. The existing adapter library is an actual
compiled dependency, not a placeholder or transplanted machine code.

`WriterWords` exposes three opaque `Cell<u64>` values: destination, table and
raw flags. `FieldCells` holds a formatter reference and raw error/present bytes.
These are chosen safe logical roles, not recovered layouts or dereferenceable
native addresses. `PRETTY_FLAG` is bit23 of the raw flags word: the observed
byte(F+18)&0x80 lies in the little-endian word loaded from F+16.

## Timing, callbacks and result projection

- Nonzero entry error skips formatter/name/callback access, overwrites error1
  then present1 and returns the same chosen state reference. Arbitrary initial
  present bytes are supported on this route. Valid Rust arguments are still
  required even when unused, stronger than native unused raw-pointer states.
- On entry error0, cache the original formatter reference F and sample mode
  and H once. H0/1 is the qualified domain; another H returns `None` solely
  as a newly chosen refusal policy, not an original native result. Callback
  changes to error, H, mode or state.formatter never reroute this invocation.
- Flat H0/H1 requests `" { "`/`", "`, the name, then `": "`. Each direct writer
  call freshly reads the **old cached F's current** D/V words, including for
  an empty name. Nonzero writer bytes canonicalize to1. The supplied G gets
  saved data/descriptor words and a live old-F context; G's returned byte is
  stored raw, including2/128/255.
- Pretty H0 first directly requests `" {\n"` without local N; H1 skips it.
  Only after a successful opening, or directly for H1, initialize N1 and copy
  the old cached F's current D/V/full flags. H0 opening may replace S.formatter
  and clear old-F bit23: the parent stays pretty, but its copied flags may be0.
- Pretty name and colon use the existing adapter with captured D/V/shared N.
  An empty name makes no underlying writer requests. G gets the copied flags
  and a real adapter request capability. G may change N, emit arbitrary bytes,
  ignore a failed inner request, emit again and return0 or any byte. There is
  no hidden sticky-error accumulator. A nonzero G result canonicalizes to1;
  zero requests suffix `",\n"` through the known adapter with N left by G.
- Finish stores the local result to error, then present1, and returns `Some`
  of the same chosen state reference. This is source/logical order, not a
  claim about physical stores or the native RAX ABI. Native RAX returns S,
  not a status. The known preserved adapter suffix returns0/1; the primitive
  native raw-suffix relation outside that specialization is not implemented.

Writer W receives `(D, V, bytes, optional shared N)` and a raw-byte response
is consumed. A bridge must supply fresh method-entry selection from passed V;
a stable Rust closure is not evidence of stable native writer identity.
Value G receives saved data/descriptor identity and `ValueContext`, not a fake
formatted value. Descriptor contents/method selection may change before G and
must be represented by that proxy; the controller does not freeze a native
function or deep-copy the underlying value state.

`ValueContext::request` really calls W in flat mode or the existing adapter in
pretty mode. Flat getters read current old-F words/flags and expose that same
F reference. Pretty getters return private immutable copied metadata and the
shared N Cell. There is no default G or guessed original value formatting.

## Strong chosen domain

All Rust references/lifetimes are valid, and the name bytes are immutable for
the whole call. Native code preserves the name pointer/length, not necessarily
all pointee bytes across earlier callbacks; raw pre-name mutation is excluded.
Callbacks return finitely and normally; panic/unwind, faults, concurrent
mutation and unsafe corruption are outside this contract.

S/F/A/L/N/frame/return roles must be separated, or own setup/stores must not
corrupt later-read metadata. For example raw F=A permits A+16=&N to change the
later F+16 load even for H1; this is excluded, not a target defect. H1 mode/
copied-flags consistency follows only under this separation. Pretty A/L
metadata is preserved except N. Arbitrary metadata edits or changed suffix
dispatch remain unimplemented. Existing native callee-save/frame/return/input
conditions remain external bridge assumptions, not consequences of these
chosen Cell types. Source code and final Cell values do not establish a
physical memory-access trace, original compiler/byte identity, runtime or gate.

## Real standalone build

Compile the **unchanged actual adapter source** and then this actual parent
library with explicit `--extern`. Use the authenticated repository research
rustc1.94.1; it is not a recovered original node compiler. All outputs belong
in fresh physical `/tmp` paths. No Cargo workspace, registry dependency,
lockfile, original callback stub or build script is invented.

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_newline_writer_protocol \
  --crate-type=rlib -D warnings src/node94-newline-writer-protocol/lib.rs \
  -o /tmp/libnode94_newline_writer_protocol.rlib
/path/to/verified/rustc --edition=2021 --crate-name node94_field_request_protocol \
  --crate-type=rlib -D warnings src/node94-field-request-protocol/lib.rs \
  --extern node94_newline_writer_protocol=/tmp/libnode94_newline_writer_protocol.rlib \
  -L dependency=/tmp -o /tmp/libnode94_field_request_protocol.rlib
/path/to/verified/rustc --edition=2021 --test -D warnings \
  src/node94-field-request-protocol/independent_tests.rs \
  --extern node94_field_request_protocol=/tmp/libnode94_field_request_protocol.rlib \
  -L dependency=/tmp -o /tmp/field-independent-tests
/tmp/field-independent-tests --nocapture
```

The separate tests use only the actual public production API and real W/G
callbacks, with hand-derived native assertions rather than a private model.
The independent reference oracle, input-only production driver and final real
build/mutant/rebuild evidence are documented in the sibling packet. They
corroborate this conditional higher-order projection, not unknown original
value formatting. All39 files at published5976, their manifests, native
exports and earlier failures remain unchanged. Captured node/visor code and
compatible original objects are never executed or emulated.
