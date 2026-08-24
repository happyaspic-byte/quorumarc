# Engineering targets

These are validation gates, not achieved production claims.

| Target | Gate | Acceptance condition |
|---|---:|---|
| Split-brain safety | 0 | 0 violations in at least 1,000,000 deterministic fault histories |
| Proof enforcement | 0 | 0 EffectGate activations without a valid PromotionProof |
| Replayability | 0 | Every simulator failure reproducible by source revision + seed/history |
| Proof validation | 0 | p99 below 1 ms on reference host, after benchmark harness exists |
| Planned service switch | 1 | p95 ≤250 ms, p99 ≤500 ms on declared reference topology |
| Unplanned service switch | 1 | p95 ≤1 s, p99 ≤2 s only with validated EffectGate fencing |
| Stateful RPO-0 switch | 2 | p95 ≤2 s, p99 ≤5 s and zero acknowledged-write loss |
| Generic KVM recovery | 3 | p95 ≤15 s on the declared VM/storage profile |
| Warm KVM recovery | 4 | p95 ≤3 s research target on supported profiles |
| Soak reliability | 1+ | 7 days and 10,000 injected power/link faults without invariant violation |

The lower bound for an unplanned recovery is:

\[
RTO \ge T_{detect} + T_{lease/fence} + T_{catchup} + T_{activate} + T_{endpoint}
\]

A BMC power fence can take seconds or tens of seconds, so sub-second recovery is
not advertised for that topology. Results must always include workload,
hardware, storage, network, fence mechanism, percentile, and sample count.

## Continuity levels

| Level | Promise |
|---|---|
| L1 | Restart service on a prepared peer; existing connections may reconnect |
| L2 | Replay application/WAL state with an explicit RPO policy |
| L3 | Restore a supported Linux process/container checkpoint |
| L4 | Restore a disk-consistent microVM/VM memory and device checkpoint |
| L5 | Rebind cooperative logical sessions and deduplicated operation IDs |

Unsupported black-box applications are never labelled L5 merely because a VIP
moved or a memory snapshot restored.
