# Node #94 consensus block admission

This crate reconstructs the bounded block-admission contract retained in
`research/work-items/RE-008-block-admission-94/` for node #94.  It is a safe,
in-memory Rust component, not a networked consensus node.

The recovered scope includes historical stake-set selection, strict weighted
quorum, QC and TC admission, ordered block gates, and the registration side
effects that follow successful admission.  Proposer scheduling (`0x4b31e70`),
digest construction (`0x454c050`), and signature recovery (`0x14c6f50`) remain
unresolved.  They are isolated by `AdmissionAuthenticator`; no API accepts an
untrusted boolean as proof of authentication.

The captured executable is never run by this crate.
