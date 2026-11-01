# Independent review corrections

Original PR #624 head `b1958fa1f423657d5e93c9678d7d56fbd0453aac`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The original collector returned a hardcoded zero for LEA references without scanning them. Added the advertised 48-8d scan and an outside-body reference mutation control; the authenticated result remains zero. Also checks absence of a RELATIVE relocation to this body.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
