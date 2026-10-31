# Independent review corrections

Original PR #639 head `889fd54d31593429152f40088c49c8f6926e2687`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The multiply overflow branch is JO at 0x1450a87; the addition uses SETO/TEST/JNE at 0x1450ab1..0x1450ab9. Corrected the claim of two SETO/JNE pairs. The admitted giant-body scope is its FDE and one six-byte call only.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
