# Independent review corrections

Original PR #636 head `e6f976294271787f2cbd1f41786669b8c1c65ca0`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The zeroing glue writes [rdi,rdi+0x10) and [rdi+0x18,rdi+0x20); the intervening qword is untouched (0x35ab623 and 0x35ab62e). The accessor writes fields through +0x5b, not a 48-byte result (0x3790ffa..0x3791037). Reachability wording now reports only observed cell references and the bounded encoding census.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
