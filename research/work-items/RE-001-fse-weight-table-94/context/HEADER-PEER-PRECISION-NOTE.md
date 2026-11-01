# Header/composition wording precision after independent review

The independent reviewer derived the actual selected header contract from
the895/908-byte listings and separately authenticated them. Its current
proof is `/tmp/hl-fse-header-peer-20261101/INDEPENDENT-CONTRACT.md`.
This note preserves all earlier byte observations, proof documents and
receipt hashes; it does not relabel a historical run or modify source.

Two qualifications should accompany the earlier header/composition records:

1. The zero-run terminal bit offset is bounded by31 before a fast reload
   only when its base is eligible (base<=end-7). Near the end, a terminal
   offset can be33/34 before the explicit final-window cap/masked-shift
   route. The earlier general bound55 and final accepted-offset<=32 checks
   remain valid. No statement should universalize the fast-path31 bound to
   the near-end route. The actual clamp proves physical read bounds there.
2. Raw-48 is an observed defensive assignment behind the symbol-capacity
   finish guard. The earlier lists of numerical error codes are conservative
   return-set descriptions; they do not establish a reachable input for
   every listed member. In particular no -48 reachability is claimed under
   the stated max255/remaining-mass invariant. The proof can overapproximate
   its return set without using that assignment as an accepted test outcome.
   Likewise the composition's phrase 'can receive' must be read only as that
   conservative site classification, not a witness of -48 reachability.

No normalized-count, h<=V, initialization, region, table-coverage or state/bit
bound changes. The constructor uses only the same proved successful-input
invariant. Before any public source/evidence outcome, its final documents
must incorporate these precise distinctions directly rather than depending
on a reader to infer them from a conservative error list.
