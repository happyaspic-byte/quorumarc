# Research baseline

QuorumArc combines established safety mechanisms with a product-level proof and
enforcement boundary. It does not claim to invent quorum, leases, WAL, fencing,
VM checkpointing, or connection migration.

## Primary references

- LeaseGuard: progress-coupled leader leases and formal modelling (SIGMOD 2026).
- FoundationDB and TigerBeetle VOPR: deterministic simulation and reproducible
  fault injection using production state-machine logic.
- Pacemaker fencing guidance: quorum alone cannot stop an isolated node from
  continuing to control a resource.
- Remus and QEMU COLO: checkpoint/output buffering and primary-secondary VM
  replication precedents.
- QUIC RFC 9000 and HA/TCP (NSDI 2025): connection identity and explicit
  connection-state migration boundaries.
- Firecracker snapshot and CRIU documentation: restore speed does not by itself
  guarantee disk or network continuity.
- LINBIT DRBD Reactor: Rust and event-driven HA already exist; the language alone
  is not a differentiator.

## Proposed differentiation

The product contribution is to bind quorum, fence, state, health, policy, and
lease evidence into one machine-verifiable `PromotionProof`, enforce it at every
external-effect boundary, and emit a replayable `ContinuityReceipt`. This is a
design thesis to validate, not yet a patentability or market-uniqueness claim.

Formal trademark and prior-art searches are required before public commercial
claims. The preliminary name scan found no exact `QuorumArc` repository or web
company match at the time of review.
