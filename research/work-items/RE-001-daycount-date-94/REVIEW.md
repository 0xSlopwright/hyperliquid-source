# Independent review corrections

Original PR #648 head `5bb1fd91426841da55369a2f0573c0ad5401e355`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

Removed the incorrect ranking claim (324 sites is below 952) and corrected cross-packet names. The exhaustive 146097-day model, authenticated table bytes and epoch result reproduce independently; no full constructor equivalence is asserted.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
