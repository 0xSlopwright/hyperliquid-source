# Independent review corrections

Original PR #659 head `1725e42c55f8c690740d8f2deb8525aa1d5cc966`.

Target node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured executable was run.

There are four CMPXCHG sites (0x4ee3b63,0x4ee3b98,0x4ee3c5a,0x4ee3c83), one completion XCHG at0x4ee3c1a and one unwind XCHG at0x4ee3d14. Slots0x576ea40 and0x576e8d8 have GLOB_DAT relocations for syscall and __errno_location, respectively; they merely lack RELATIVE relocations. Corrected counts and relocation wording.

Static readback used `objdump -d -M intel --start-address=<start>
--stop-address=<end> artifacts/node/94/hl-node` at the packet bounds or
the small corrective windows named above. ELF import bindings were checked
with `readelf -rW artifacts/node/94/hl-node`. Python 3.10 regenerators and
focused corruption controls were rerun after these corrections. Original
logs are historical author runs, not the independent review result.
