# R8 integration boundary

The existing `happyaspic-byte/r8-protocol` project is preserved unchanged.

## Suitable future uses

- dual-path transport with independent path security state;
- delivery-ID deduplication and divergent-payload detection;
- fast path rebinding in closed networks;
- protected replication or health traffic after durable framing is designed.

## Explicit non-uses

R8 does not replace:

- quorum, leader election, membership, or consensus;
- hardware/storage fencing or EffectGate enforcement;
- durable WAL, snapshot consistency, or RPO acknowledgement rules;
- workload lifecycle, VM migration, VIP publication, or session recovery;
- proof signing, policy authority, or audit persistence.

The currently reviewed R8 prototype keeps important session state in memory,
uses a small datagram-oriented frame, and has lab path-switch results rather
than full server failover results. Those limitations are not defects in its
research scope, but they prevent treating it as the QuorumArc safety kernel.

## Integration rule

A future `quorumarc-transport-r8` crate must be optional, pinned to an exact
reviewed R8 revision, license-cleared, fuzzed at its boundary, and replaceable by
a standard transport without changing safety decisions. Transport loss may
reduce availability; it must never grant authority.
