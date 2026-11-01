# RE-005: higher-order field request controller

- Component: codec/diagnostic request protocol; no component gate requested.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Native parent: VA `0x1571f50..0x15720d6`, 390 bytes, 109 retained rows,
  SHA-256 `e6aec76f57413451c7a873712558e50e18c6f30b2001b6777c3fd29fda32388d`.
- Used adapter: VA `0x157d000..0x157d26e`, 622 bytes, SHA-256
  `d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4`.
- Preserved source: published #1030 head
  `5976ec53938ade09bdbb906e738b1abaab942d05`, tree
  `a84c04f12161a1b2279ff43dafc0c2ff6d14b9ea`; all39 original files, blobs,
  Git modes, manifests, byte exports, negative results and flat inventories
  remain unchanged. This is a sibling packet.
- Claim: independently authored Rust implementation of the qualified logical
  parent contract with **real supplied W/G callbacks and request capability**.
  Unknown original value formatting is not implemented.

## Concrete behavior and native bridge

The parent now composes the actual separately compiled newline-adapter rlib.
Its supplied value callback receives saved opaque data/descriptor identities
and a real context: flat requests sample live words from the cached old F;
pretty requests use post-opening copied words and the same mutable newline N.
G can emit arbitrary bytes, observe/mutate N, ignore an inner request failure,
emit again and choose its own returned byte. There is no fabricated formatter
or hidden sticky error. The library has no registry dependencies or Cargo
scaffold.

The existing native proof and independently extracted [witness table](NATIVE-WITNESSES.md)
establish five flat and nine pretty paths. The [Rust API documentation](../../../src/node94-field-request-protocol/README.md)
describes the complete chosen domain and timing. In particular, entry E is
checked before the chosen H qualification; nonzero E yields E1/H1 for any H.
Mode bit23, H and old F are sampled once. Flat prefix/name/colon read current
old-F D/V each time, including an empty name request. Flat G's raw AL2/128/255
survives, whereas earlier writer and pretty G errors become1. Pretty opening
is direct; successful opening can change old-F words before their snapshot.
Name, colon, real G requests and suffix share N through the actual adapter.
The final source writes E then H1 and returns the same safe state reference.

These are chosen valid Rust references and separate logical roles, not native
types/layout/vtables/ABI. The name is immutable across the whole call, stronger
than merely retaining its native pointer/length. Calls return finitely and
normally; panic/unwind, faults, concurrency and unsafe alias corruption are
excluded. Original callee-save/frame/input/return conditions remain external.
S/F/A/L/N/frame roles are separated or own setup must not corrupt later-read
metadata: raw F=A can let A+16=&N overwrite a later F+16 sample. Pretty A/L
metadata stays preserved except N. A bridge supplies actual fresh writer and
value-method selection at each call; closure identity does not establish a
stable native function. Known-adapter suffix AL0/1 is the specialization used
here; arbitrary raw suffix dispatch/metadata mutation is not implemented.

`None` only refuses the newly chosen E0/H outside0..1 domain; it is not a native
return or formatter failure. Rust final Cell values/source order do not prove
physical generated store/access order or native RAX (which returns S). No
rendering, original compiler, runtime, full-helper ABI, byte-identity or gate
claim is made.

## Independent expectations and real execution

An independent author froze `tools/bincode_diagnostic_parent_reference.py`
before reading the new controller/driver. It admits one immutable full-size
node94 `bytes` object by SHA-256 and derives original parser, literal and
certificate facts from that exact object. GNU receives only390/622-byte raw
snapshots. No full-image provider file is created, and no captured code is run
or emulated. The reference interprets the five-plus-nine abstract callback
certificate paths and the proved adapter contract; it is not a CPU runner.

The925 stimuli cover every certificate path and six explicit chosen-domain
refusals, arbitrary bytes, all-space/empty names, raw AL, changing writer/value
method maps, cached-F versus replaced S.formatter, old live flags versus copied
pretty words, post-opening snapshots, real nested requests, ignored inner
errors, mutable N and sequential calls. Fresh expectations match the checked
fixture byte-for-byte before compilation. Input files contain only stimuli;
the production driver reads no expected transcript and receives no expected
prefix/name/colon/suffix role tags. Actual W/G/Q events and context words are
observed through the public production API. This is data-flow separation,
not a filesystem sandbox or physical native trace.

The independent `independent_tests.rs` is a separate external Rust test crate
using only the actual public rlib and real W/G closures. Its12 hand-derived
tests bind the literal native mode bit and timing/status distinctions without
importing the transcript oracle. The other external test checks all925 frozen
transcripts. The production library includes neither test driver nor fixture.

## Reproduce and observed results

Use the checksum-verified research rustc1.94.1 described in [TOOLCHAIN.json](TOOLCHAIN.json),
full commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM21.1.8 and the
recorded explicit C linker driver. This is the repository research toolchain,
not a recovered original node compiler. Build/install hooks were inspected;
the verified private prefix uses manifest-listed package payloads without
executing installer hooks or writing global configuration.

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/owned-short-dir python3 -B \
  tools/bincode_diagnostic_parent_rust.py \
  --rustc /path/to/verified/prefix/bin/rustc \
  --output /tmp/new-owned-parent-result --controls
python3 -B -m unittest discover -s tests -p test_bincode_diagnostic_parent_rust.py -v
```

The actual bounded run is retained in [RESULT.json](RESULT.json), with exact
argv, tool identities, file digests and [170 raw streams](RAW-LOGS.json):

- 85 actual subprocess records, including compiler/linker probes.
- Debug and optimized actual adapter+parent rlibs:12 external tests and one
 925-case external fixture test pass per profile. Each input-only production
 client matches925 transcripts,4061 actual W calls and510 actual G calls.
- Nine independently selected semantic source mutations all compile; each
 production client exits normally with925 same-identity rows. Differences are
 44/12/5/20/517/156/72/8/506, respectively, and include its independently
 selected witness. Each also produces real exit101 assertion failures in
 both the12-test API client and the fixture client. Raw output is preserved.
- Two complete own dependency-chain rebuilds are raw-equal without masks:
 parent38230 bytes and adapter9440 bytes. These are own-build comparisons;
 they make no original node machine-code comparison claim.
- Four fresh Python admission controls pass normally and under `-O`, including
 wrong target, changed fixture and existing output refusal before compilation.
- Before/after audits match all39 original files/Git blobs/modes,10 new source
 entries, the target digest, all103 compiler payloads and seven genuine pins.

The exact compact records are [ORACLE.json](ORACLE.json),
[BUILD-AUDIT.json](BUILD-AUDIT.json), [FOCUSED-VALIDATION.json](FOCUSED-VALIDATION.json),
[REFERENCE-FREEZE.json](REFERENCE-FREEZE.json) and
[SEMANTIC-MUTANTS.json](SEMANTIC-MUTANTS.json). [FOCUSED-VALIDATION.json](FOCUSED-VALIDATION.json) also preserves the initial
test-regex failure; [PREPARATION.json](PREPARATION.json) records the private
audit-schema and independent mode-auditor setup history. None was a production
failure or relabeled as final evidence. Earlier5976
evidence remains intact. Final exact-head repository checks and independent
frozen reviews are reported separately with the amended PR.

The remaining question is a native bridge that establishes original caller,
object/metadata/alias domains and actual value-formatter behavior. This packet
implements the proved higher-order protocol; it does not close those gaps.
