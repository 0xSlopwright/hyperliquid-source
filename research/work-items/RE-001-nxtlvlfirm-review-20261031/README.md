# Selected NxtLvlFirm static-evidence review

Node #94 only: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

PRs #198, #241 and #615 are retained with bounded corrections. The exact original
packet and source blobs, including their original manifests, are preserved under
`original-submissions/`; `review.json` pins every archived blob. Original negative
results remain in the local review ledger, with their raw log hashes recorded here.

For #198, independent GNU disassembly confirms all 27 reported direct calls and
12 diagnostic LEAs at instruction boundaries. Actual `.eh_frame` records confirm
all 9 caller and 12 constructor extents. The six 1,733-byte callers return accepted
values in RDX with EAX zero; the three 896-byte callers instead store the value at
output+8 and tag9 at output. The shared sign/zero predicates are established for
integer values. Text decoder ownership, complete helper behavior, indirect refs
and Rust result-type names remain inferred. The raw scanner is a candidate finder,
and self-derived sample vectors are not independent semantic proof.

For #241, actual FDE endpoints remove 30 bytes of inter-function padding from
three of four recorded spans (1,906 actual bytes). Matrix values and the two table
encodings are retained. A tier byte is loaded without a local bounds check; the
iterator count bound does not prove the upstream tier domain. The verifier now
checks real FDE records and relocated panic locations, and explicit checks remain
active under optimized Python. Opaque count helpers and full caller behavior are
outside this acceptance.

For #615, actual FDE endpoints remove 89 padding bytes from ten of eleven spans
(6,903 actual bytes). Capacity arithmetic is bounded to unsigned64 inputs and
verified against the observed high-half multiplication/shift sequence over 1,125
boundary and deterministic-random inputs. The name predicate counts UTF-8 bytes:
1 through16 pass this local length check. Full creation eligibility, duplicate
address/name checks, and reference-only error names remain separate.

Normal and optimized focused suites each pass34 tests with zero skips. Additional
controls reject forged FDE endpoints, corrupted relocated panic locations and
multiplier values, ambiguous artifact manifests, changed artifact identities,
and invalid unsigned domains. Original source and corrected Python compile under
actual Python3.10.18. Repository artifact verification, catalogue consistency and
inventory reproduction are separately recorded in the final local ledger.

All native inspection uses GNU objdump/readelf2.47.20260726. No captured program
was executed and no progress gate or whole-function equivalence is asserted.
