# Chosen public Rust API for the parent protocol

Crate `node94_field_request_protocol`, component
`src/node94-field-request-protocol`. These are new safe logical views, not
original Rust types, layout, vtable, ABI or a value-formatter implementation.
All 39 files at public5976 remain untouched. Independent tests compile as a
separate external `--test` crate against the actual production rlib.

```
pub const PRETTY_FLAG: u64 = 1 << 23;

pub struct WriterWords {
    pub destination: core::cell::Cell<u64>,
    pub table: core::cell::Cell<u64>,
    pub flags: core::cell::Cell<u64>,
}
impl WriterWords {
    pub fn new(destination: u64, table: u64, flags: u64) -> Self;
}

pub struct FieldCells<'f> {
    pub formatter: core::cell::Cell<&'f WriterWords>,
    pub error: core::cell::Cell<u8>,
    pub present: core::cell::Cell<u8>,
}
impl<'f> FieldCells<'f> {
    pub fn new(formatter: &'f WriterWords, error: u8, present: u8) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKind { Flat, Pretty }

// Fields private; no way to mutate Pretty D/V/copied flags/local metadata.
pub struct ValueContext<'a, W: ?Sized> { /* private */ }
impl<'a, W: ?Sized> ValueContext<'a, W>
where W: FnMut(u64, u64, &[u8], Option<&core::cell::Cell<u8>>) -> u8 {
    pub fn kind(&self) -> ContextKind;
    pub fn writer_words(&self) -> (u64, u64);
    pub fn raw_flags_word(&self) -> u64;
    pub fn newline_flag(&self) -> Option<&core::cell::Cell<u8>>;
    pub fn flat_writer(&self) -> Option<&WriterWords>;
    pub fn request(&mut self, bytes: &[u8]) -> u8;
}

pub fn try_field_protocol<'s, 'f, W, G>(
    state: &'s FieldCells<'f>, name: &[u8],
    saved_data: u64, saved_descriptor: u64,
    writer: &mut W, value: &mut G,
) -> Option<&'s FieldCells<'f>>
where W: FnMut(u64, u64, &[u8], Option<&core::cell::Cell<u8>>) -> u8 + ?Sized,
      G: for<'a> FnMut(u64, u64, &mut ValueContext<'a, W>) -> u8 + ?Sized;
```

u64 words are opaque supplied identity/value projections, never dereferenced by
the controller as native pointers. The W proxy receives D/V values and must
represent fresh method selection for passed V if asserting a native bridge.
G receives the saved input data/descriptor words; the descriptor method/pointee
may change before G and is resolved by the supplied proxy at actual invocation.
No default fake G/value-format implementation is provided.

## Scope and exact logical behavior

- Entry error is read once. If nonzero, set error1 then present1 and return
  Some(sameState), with no formatter/name/W/G access. Initial H may be anybyte.
- Otherwise cache the initial state.formatter reference F ONCE; sample its
  flags bit23 and initial H ONCE. Initial H outside0/1 returns None as a chosen
  API-domain refusal, not original behavior. No callback edit reroutes E/H/mode.
- Flat H0/H1 prefix is207b20/2c20. Prefix, name and colon3a20 directly invoke W,
  each with current D/V from OLD cached F and None for N. Empty name still
  requests an empty raw slice. Any nonzero W AL canonicalizes error1.
- Flat G receives savedData/savedDescriptor and Flat context referring to OLD
  cached LIVE F. Context getters/request see current old-F words, not the old
  parent mode sample. G returnedAL propagates RAW to final error (02/80/ff).
- Pretty H0 first invokes direct W with207b0a/currentOLD-FD/V/NoneN. Error
  canonicalizes1 and skips N/snapshot/G. H1 skips opening. Afterwards initialize
  N1, capture current OLD-F D/V/fullflags AFTER opening/setup phase. Keep the
  earlier mode/H. Own-role separation below excludes setup corrupting F.
- Pretty name and colon use the unchanged actual adapter with capturedD/V/N.
  Empty name makes no underlying W; under this domain N remains1 for colon.
- Pretty G gets Pretty context with capturedD/V/flags and shared N. Its
  request(bytes) really calls the existing adapter with those words and N.
  G may ignore request() failure, issue more requests and return0/arbitraryAL;
  there is NO hidden sticky-error accumulator. Nonzero G AL normalizes1 and
  skips suffix. Zero G AL invokes suffix2c0a through the known adapter using
  N left by G, including255. Capture the adapter's returnedAL (0/1 here).
- Every qualified finish sets error(localStatus), then present1 and returns
  Some(sameState). Ambient callback E/H edits are overwritten only there.
  Source order is not a physical compiled store trace or original RAX ABI.

Context getters:
- Flat writer_words() reads current destination/table from cachedF; flags getter
  reads current full rawflags; flat_writer() returns that SAME F reference;
  newline_flag() is None; request directly calls W with fresh currentD/V/NoneN.
- Pretty writer_words/raw_flags_word return immutable post-opening copies;
  flat_writer() is None; newline_flag() returns shared localN; request invokes
  the existing adapter, W receiving capturedD/V/Some(N) on actual requests.

## Strong domain and exclusions

All chosen Rust references/lifetimes remain valid even in prior-error/empty
states; this narrows native unused/invalid raw-pointer states. The name slice
is immutable for the WHOLE call: native preserves its pointer/length, not all
pointee bytes across preceding callbacks. All callbacks return finitely and
normally; no panic/unwind/fault/concurrent mutation or unsafe corruption.

Logical S/F/A/L/N/frame/return roles are separate, or own setup/stores must not
corrupt later-read metadata. In raw F=A, A+16=&N can replace F+16 before its
load; that raw alias case is excluded, not a target bug. H1 mode/copy-flags
consistency is conditional on this separation, not a universal native theorem.
H0 opening may clear OLD-F bit23 before its copied flags snapshot while parent
stays Pretty; flat prefix may set it while parent stays Flat and G sees it live.

Pretty metadata is private/preserved exceptN. Arbitrary A/L changes or changed
suffix dispatch and primitive raw suffixAL02/80/ff are outside this known-
adapter specialization. Existing native frame/callee-save/return/argument and
memory conditions stay explicit external bridge assumptions. No original fmt,
private type/vtable/layout/ABI, physical renderer/memory trace, original compiler
or byte identity/runtime equivalence or component gate is claimed.

## Ownership

- S5: lib.rs, README.md, actual test_driver.rs, transcript fixture, runner
  tools/bincode_diagnostic_parent_rust.py, Python admission tests, sibling packet
  research/work-items/RE-005-field-parent-rust-94/, sole Git/PR integration.
- Completion: ONLY src/node94-field-request-protocol/independent_tests.rs,
  independently authored external Rust test crate using public API/real W/G;
  private/tmp native/test proof receipts. No compiler until coordination.
- Tail: independently freeze reference/stimulus protocol privately, then ONLY
  tools/bincode_diagnostic_parent_reference.py after agreeing import/wire API;
  no reading new controller branches before reference freeze, no compiler.
- Current912: read-only native/source/semantic review and later one independent
  actual-rlib client after compiler/headroom coordination; no author edits.

Real build: compile unchanged adapter rlib from5976 with explicit crate identity,
then parent rlib with --extern and external driver/test clients. No Cargo,
workspace, guessed dependencies or fake callbacks. All outputs physical/tmp.
