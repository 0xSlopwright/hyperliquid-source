# Independent review corrections

Original PR #892 head `cf84b5763d383a165f6bd04fe279d202a7e63e79`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The growth helper passes r8d=8 (alignment) and r9d=0x18 (element size), not8-byte elements. The callee fragment0x4f04fcb..0x4f04fe7 rounds r9 to r8 alignment and multiplies by rcx capacity. Corrected labels and record fields; the element is24 bytes (three qwords). Removed the false8-byte sibling label; the other helper passes r9d=0x168. The collector reports63 matching sites, not64.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
