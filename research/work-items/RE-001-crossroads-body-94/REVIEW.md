# Independent review corrections

Original PR #664 head `be3d75a61bdb5572c20ff6dce626060951cb90aa`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The original13-site inventory omitted four imported calls. GNU decoding found17: added GLOB_DAT bindings for memcmp at0x44aa731/0x44aad11/0x44aae13 and memcpy at0x44ab436, plus a table-omission negative control. The two Location structures and FDE range reproduce against node94; the packet makes no end-to-end computation claim. Corrected cross-packet names and bounded the census interpretation.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
