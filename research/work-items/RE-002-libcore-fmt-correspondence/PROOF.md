# Static comparison contract

This is a file-format/artifact correspondence argument, not a theorem of
machine execution, original source provenance or behavioral equivalence.

1. `admit_file` reads each artifact once into immutable Python `bytes`, then
   requires its full SHA-256. `analyze` requires those identities again. The
   archive parser resolves the actual GNU long-name table and unique code
   member in those same bytes; the member's full SHA-256 is also mandatory.
   All sections, symbols, RELA records and excerpts derive from those objects.
   Later pathname replacement cannot change the already admitted contents.
   Concurrent reads are not an atomic filesystem snapshot guarantee. Analysis
   source-file hashes are separate observational bindings under a stable,
   trusted host assumption.
2. Source ELF type/machine/encoding are ET_REL/x86-64/ELF64 little endian.
   Section contents, linked symbol/string tables and selected RELA records are
   bounded. The three selected actual STT_FUNC symbols cover their complete
   source sections from value zero. Neither source padding nor code suffixes
   are trimmed. Capture excerpts require one file-backed allocated section
   and one PT_LOAD with identical file coordinates. Code also requires both
   executable flags. Each primary extent and the separate supporting 61-byte
   extent has exactly one matching actual FDE.
3. Only actual selected-code RELA kinds 2 (PC32) and 9 (GOTPCREL), addend -4,
   derive four-byte field positions. The selected sets must be in bounds and
   disjoint. Source ELF metadata supplies the record kind and symbol; there
   is no arbitrary input-width or manual-mask parameter. Comparing every raw
   code byte first retains all 78 differing positions. Removing only the 76
   positions in actual source fields from the *comparison denominator* leaves
   1,378 equal and two unequal positions out of 1,380. No byte is rewritten.
4. For field address P, encoded signed value d and actual addend A, the linked
   reference is P+d-A. PC32 identifies the direct data address; GOTPCREL here
   identifies the slot address, not its callee. Each selected captured slot
   must map to source bytes and have one type-8, symbol-zero RELATIVE record;
   its selected non-null addend must map to retained bytes. These linked ELF
   coordinates are not a claim about a running process's loader base.
5. All referenced raw data slices are compared without a data mask. The
   source symbol's size (or remaining section size for an actual zero-size
   section symbol) bounds each selected slice. The source Location's distinct
   ABS64 record and captured RELATIVE record bind the 75-byte path separately.
   Data and pointer records do not enter the 76-byte code-field denominator.
6. The 48-byte layout has 24 fixed bytes and three actual eight-byte ABS64
   fields at offsets 24/32/40. The first official symbol must equal the actual
   compared adapter function symbol, including its source table identity,
   section, value and size. The parent's two source GOT symbols must bind the
   same symbol. Only then are their separately checked captured RELATIVE
   addends associated with the partially compared adapter. Other methods
   remain unqualified. The decimal's three official GOT symbols similarly
   bind the selected 61-byte source function, whose target has its own exact
   FDE. Its three field records and 49 equal complement bytes remain separate
   supporting evidence, with transitive data/calls open.
7. The adapter's two unequal bytes are outside its one actual field. Complete
   encodings `4d8d2437` and `4e8d243e` remain in the raw exports. A native
   commuted-address explanation never converts them to equal bytes. The
   producer explicitly requires the observed gap offsets [464,467] and the
   complete observed denominator; a fabricated claim of exact reproduction
   does not follow from this packet.

The independent expectation source parses the official archive/object before
reading this producer and freezes full official/capture byte vectors plus
typed fields. Corruption controls exercise the real parsing/comparison seams
below full-image admission, so a digest rejection is not mislabeled a data,
symbol, relocation or FDE proof. Those controls and their actual results are
retained separately from this argument.

The output's small official excerpts retain the exact upstream MIT license
and attribution. They are not a Rust implementation, a transplanted build or
permission to relicense the captured node. This result narrows a provenance
question while leaving all component completion gates false.
