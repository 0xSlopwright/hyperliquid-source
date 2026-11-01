# RE-001: review of the advanced PR #998 helper correction

Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original advanced head: `ca401da99e2409714914d206d89ae469bc21be19`.
Previously reviewed head: `01cd25da6f53c1b269f1ff4e016810657612b57c`.

This incremental review accepts the bounded selected-helper correction. All eight
changed original Git blobs are preserved byte-for-byte in `originals/`; their
SHA-256 values, exact file scope and validation commands are in `review.json`.
The only subsequent edits are a duplicated word in the packet README and test
descriptions that now say seven bodies. Source semantics are unchanged.

GNU readelf and the repository FDE parser independently agree on 135,313 actual
FDE ranges. All seven claimed bodies reproduce their retained native exports
exactly: 9,917 bytes, 2,057 instructions, 124 direct calls and 84 RIP bindings.
The original six bodies and six relocation bindings are unchanged. The added
helper is `0x2308120..0x23082ff`, 479 bytes and 135 native instructions, with
SHA-256 `ca07d60df5a750ca7938d7a0a929163c4ab6b2cf08ebead3354e6841e91e3f7b`.

The u16 load zero-extends 0x158 to 344. The first signed comparison (239) takes
JG to `0x230815c`; the second (351) does not take JG. Adding -240 gives u32 index
104. Unsigned JA after comparing 25 transfers to `0x2308274`, where the stack
is restored and the helper returns. This path has no internal call and no
jump-table dispatch. Therefore the earlier diagnostic label lacked evidence;
the new limit-exit label is appropriately bounded. Operand/destination bytes
and the epilogue were authenticated independently. Exhaustive static algebra
over all 65,536 u16 inputs confirms only the stated selected predicate; it is
not target execution or an instruction emulator. The actual immediate mutation
25 to 104 makes the selected input leave this proved route, as the tests require.

The exact original seven-test suite passes in normal and optimized actual
Python 3.10. The integrated seven-test suite also passes in both modes, including
full byte-exact native regeneration and corruption controls. Doctor, verify,
catalogue-check and reproduce pass; both changed Python files compile under
actual Python 3.10 before and after integration. Full combined repository tests
are a separate parent-integration gate, not claimed by this focused review.

Other helper tags, jump tables, cleanup callees and exceptional paths remain
unclosed. Public request/error types, whole API behavior, source recovery and
runtime equivalence are not established. No imported evidence, progress gate,
submodule pin or captured artifact was changed; no target/emulator ran.
