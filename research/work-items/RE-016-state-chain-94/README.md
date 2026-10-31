# RE-016 state chain (hl-node #94)

This is a standalone packet. `tools/state_chain.py` builds `state-chain.json` from the binary. It needs only a bounded .rela.dyn parse and three bounded function extents. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/. It checks 43 key VAs byte by byte, re-derives 10 call/slot targets and re-parses both relocations, then reports PASS, FAIL or INCONCLUSIVE. `tests/test_state_chain.py` holds the pins, the seed checks and the tamper tests. See EVIDENCE.md.

File hashes (also in MANIFEST.sha256):

- EVIDENCE.md 86274de110037bb7e444c5a154dd343f9c2d01f23d0ec78d339db4dd03044f81
- state-chain.json f525820a128fa88738389d19b9ee70446a6fb436e5294be652e8d241ebcbaf0e
- verify.py 8b534da3b2a3e0aa1838663e64b7b318c7c35dfac6fe35e880c5d3a59f0e5db3
- independent_verify.py 79ec9789842d6f58f6d48035165ab9c350097ed820436464a83e90e119f7a5c5
- tools/state_chain.py 82271b9927fd83be7ee71ef4625bafc420cdcac6c9d549999918f7229af51ccc
- tests/test_state_chain.py bdfe1a2b5bd2c9d62ce7a4d68990721ff23825c99436e922ac5f8eacab65fb4c

## What this does not claim

- It does not prove that 0x3751e80 builds a snapshot or an export. "State materializer / exporter" is inferred. No string literal is referenced in the three extents, and no named caller exists.
- It does not identify which caller reaches 0x3751e80. Six indirect call sites load slot 0x5773aa8. The packet does not rescan the text segment, so the no-rel32-caller facts come from an earlier scan.
- It does not describe 0x3269ae0 beyond "the top LtHash fn, documented in #262/#316". It does not describe 0x37d08a0, 0x332d440 or 0x37d4e30 at all.
- It does not say what any copied block or field means. It records only lengths and destinations.
- It does not repeat #316's writer analysis, #262's LtHash analysis or #271's exchange +0x3a00 lead, and makes no claim over them.
- It makes no claim about other releases, source code or consensus behaviour, and it does not reimplement or compare anything.
