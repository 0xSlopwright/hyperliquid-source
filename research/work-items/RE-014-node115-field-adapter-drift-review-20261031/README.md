# RE-014 node115 field/adapter review

PR #1149 exact head `0d08a3323b8e61d4bcff608e0d655b3d223338ad` is valid bounded static research. All60 changed original blobs are archived unchanged. All59 original manifest entries authenticate. No production correction was needed.

Target115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Independently parsed full FDEs establish parent `0x167d950..0x167dad6` (390 bytes) and adapter `0x1686bd0..0x1686e46` (630 bytes); complete native disassembly bytes authenticate against this target.

The official Rust1.94.1 library was acquired with signed manifest/archive authentication, SHA-256 `ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`. GNU ar independently selects the unique original object, SHA-256 `57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`. Native object symbols, instructions and typed RELAs corroborate the390-byte source parent. Exactly nine actual4-byte RELA fields account for36 excluded bytes;354 non-RELA bytes equal the target. Six literal references and the48-byte table are raw compared. Three table and one GOT RELATIVE records retain their exact types, symbols, mapped slot footprints and static addends. The selected table/GOT edges converge at the630-byte adapter.

The source adapter is622 bytes and target630: no mask or behavior is transferred, zero adapter bytes receive a normalized correspondence claim. The two other table callees remain opaque. Static RELATIVE addends are not runtime pointer observations. Historical short-FDE and unmapped-slot failures/corrections remain intact. Corruption tests cover both issues and actual source/target relocation fields, literals, table header, typed pointer records, selected edges and admission identities.

Before the provider arrived, discovery passed two admission tests and skipped the provider class; those original receipts remain. With the authenticated provider, all10 tests pass in actual Python3.10 normal and optimized modes, with no skips. Fresh CLI generation equals the full original retained records byte-for-byte. Actual3.10 compile and `make verify catalogue-check reproduce` pass. No captured execution, emulation, compiler execution or source build is needed for this packet.

Reproduce from the repository root with the authenticated library path:

```sh
export HL_RE014_LIBCORE=/path/to/libcore-e60dd2ab51fbc7de.rlib
python3 -B -m unittest discover -s tests -p test_node115_field_adapter_drift.py -v
python3 -O -B -m unittest discover -s tests -p test_node115_field_adapter_drift.py -v
python3 -B tools/node115_field_adapter_drift.py --libcore "$HL_RE014_LIBCORE" --output work/new-field-adapter-records
make verify catalogue-check reproduce
```

`static-audit.json` records exact head/files/native hashes and commands. New review receipts replace local checkout/cache/output/home path text with documented tokens; raw and published hashes are in `path-redactions.json`, raw records remain in ignored work. Original PR records are not rewritten. Source artifact license/copyright files remain in the original packet. No original compiler identity, ABI interchangeability, whole-ELF equivalence or recovery gate is established.
