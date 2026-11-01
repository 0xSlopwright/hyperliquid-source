# Review correction record

Original PR: #1143, `cbfb19f8f6b8bf107774f4b51088b043b1877e89`.
Review base: `a4e4302fb0743238cfd7ac21bc0823ee2f91345a`.
Target node94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No captured instructions have been executed in this review.

Original source defaults would call Unicorn from `analyse()`, the CLI and
packet verifier, and automatically execute ten tests if the module is
installed. Original `emu_start` had time/instruction limits but no execution
closure or guest-write restriction; the allocator callback accepted arbitrary
sizes/call returns and the output reader accepted unbounded pointer choices.
These are harness defects, not native scalar-multiplication counterexamples.
The preserved originals and original passing 22-test static log precede all
changes. The historical claimed 2137-test/46-error logs remain verbatim in the
archived README and are not review receipts.

The correction makes static behavior the default, adds explicit execution
opt-in, uses the separately reviewed shared execution guard, and constrains
the exact allocator contract and result header. Fixed inputs, byte pins,
mathematical expected values and the original output JSON are unchanged.
No immutable imported evidence or imported provenance manifest is repinned.
The original checksum manifest is archived; the current manifest records
current files and preservation metadata.

The native call review found two helpers absent from the original selected
callee list. The decoder curve check, projective add and projective double
reach field-add `0x4f1f8e0` via slot `0x5777658`. Add/double also reach
field-subtract `0x4f20020` via slot `0x5777668`. The arithmetic indirect
register calls resolve through saved/reloaded values of these slots and
Montgomery multiply slot `0x5776ef8`, while affine conversion reaches inverse
through `0x5777640`. The new execution range list includes both helper FDEs.
Raw native listings under `review-evidence/` retain the complete reviewed
functions for examining register propagation, not only call-byte matches.
Panic and allocation-error call targets remain outside the allowed closure.

The original full static record remains reproducible; additions to the
execution allowlist are documented separately instead of silently changing
the historical JSON's selected `callees` list. That list must not be used as
a transitive-closure denominator. The phrase “behavioural proof” and broad
“no SIMD” claims were narrowed in current documentation: baseline SSE is
present, current emulation has not run, and finite stubbed vectors cannot
establish whole-node or all-domain equivalence.

Acceptance still requiring authorization: reproduce the nine author records
using the corrected bounded harness, then run the explicitly opted-in runtime
controls if their scope is authorized. Static checks and fake engines establish
only source/guard behavior. No current native-runtime or hosted-CI result is
claimed. `review-evidence/validation.json` records the completed static gates.
