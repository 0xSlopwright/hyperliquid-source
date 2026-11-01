# Independent review corrections

Original PR #459 head `1de44c0d7eabb72ed289959460ec41c56b211668`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

The helper writes a 16-byte result: seconds-within-day at +0, nanoseconds at +4 and i64 carry in whole-day seconds at +8 (0x15207d3..0x15207dd). Corrected the earlier 12-byte claim and the historical statistics extent to actual FDE end 0x489a544.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
