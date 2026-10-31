# Independent review corrections

Original PR #694 head `1d2a7184ebc6ddf0c34b2503d3e19731e60ed619`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

Removed the inherited ship-complete inference: the getter at0x14385c6 uses TEST/JNE to enter Once for nonzero state. There are four Location structures and a separate assertion string among five LEA targets. Bounded reachability and sampled word-predicate claims explicitly.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
