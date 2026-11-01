# Caller qualification is separate from the771-byte constructor

The implementation domain follows one actual used caller with a876-byte
secondary workspace. That number, its outer allocation formula and the
log5/6 limit are not all present in the primary771-byte body. The fresh
immutable-input record binds208 **separate revisited context bytes**:

| Context | Exact linked window | Bytes | Observed role |
| --- | --- | ---: | --- |
| HUF caller setup | `55e8f97..55e8fce` |55 | Workspace+0x3e0/+0x4e0 roles, stack size0x36c and call556f970 |
| Compressed statistics call | `556ef30..556ef5a` |42 | Source/capacity adjustment, selector1, limit6 and call5570990 |
| Selected decoder setup | `556feeb..556ff5a` |111 | Returned-log guard, actual workspace formula and call556fb60 |

`metadata.caller_context` checks the exact208 raw bytes against the same
full-digest-admitted source. This is raw witness binding plus the accompanying
manual contextual proof, not an interprocedural instruction evaluator, whole
caller implementation, new function denominator or extra constructor coverage.

The preserved historical proof chain is:

- Initial builder/helper obligation receipt3d94078a: actual bit0 branch at
  556f997/556f99c and tail556fada->556ee40, with later coverage still open.
- Selected statistics receipt2fff6363: call556ef55 passes capacity255,
  source length V<=127, limit6, workspace and size, selector1.
- Entry narrowing receiptf4156aa0: selector1 at55709c1/55709cc bypasses
  the generic body and restores/tails to556fe70.
- Selected2,835-byte memory/count proof4e1bb1f4: local output guards and
  partial-error states, with helper premises explicit.
- Header receipt51c5631c and independent review3dca5a0d: actual21-byte
  dispatch,895-byte selected reader and908-byte short fallback establish
  h<=V and normalized initialized count cells in their normal domain.
- Constructor proofb0e18f23 and independent23e665c0: complete table
  coverage/state/bit/workspace result from those normalized cells.

These are separately retained proof contexts, not claimed original source
identities. The contextual header proof restricts signed-WORD interpretation
to the outer admitted logs5/6: generic log15 can store physical0x8000.
Near-end zero-run offsets may exceed31 before the explicit cap/masked path;
only the eligible fast refill has the smaller bound. Raw-48 is a defensive
observed error assignment, not a reproduced reachable case in the max255
normalized domain. No stronger claim is smuggled into the constructor API.

Let B=m+1 and T=2^log. The constructor alone requires scratch
`T+2*B+8`, at Q=A+4*T+0x204. The outer caller requires

`4*(T+floor((T+2*B+11)/4)+0x83) <= 876`.

This gives m<=91 at log5 and m<=11 at log6. With the same passed residual,
the constructor's own check alone would permit95/15; those are different
questions. The outer guard exceeds the exact count/output/scratch total by
8 or10 bytes. Independent WORKSPACE-UNITS.json preserves the actual boundary
and next rejected cases. Those units are checked separately from the native
row-mutation controls and are explicitly a caller qualification premise in
the provider record.
