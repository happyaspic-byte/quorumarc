# PromotionProof v0.1 — design draft

## Purpose

Authorize one candidate to open one workload's EffectGate for a bounded epoch
and lease interval. A missing, stale, ambiguous, or internally inconsistent
field invalidates the complete proof.

## Logical fields

```text
PromotionProof {
  workload_id
  candidate_node_id
  candidate_incarnation
  epoch
  policy_hash
  quorum_certificate {
    epoch, workload, candidate, candidate_incarnation, policy_hash,
    required_commit, state_root, lease_not_before, lease_expires_at,
    distinct_voters[]
  }
  fence_receipt { epoch, target, verifier, mechanism, observed_at }
  state_evidence { required_commit, durable_commit, state_root, observed_at }
  health_attestation {
    workload, node, candidate_incarnation, epoch, healthy, checks, observed_at
  }
  lease_grant {
    workload, holder, candidate_incarnation, epoch, not_before, expires_at
  }
}
```

## Validation order

1. Match workload and pinned policy hash.
2. Require an epoch greater than the current accepted epoch.
3. Verify a majority/intersecting configured quorum and required witness.
   The independent witness is never an eligible workload candidate.
4. Verify that fencing covers the prior authority and the new epoch.
5. Verify candidate durable state at or beyond the required commit index.
6. Verify a non-zero state root and fresh matching health evidence.
7. Verify a bounded candidate lease that is active at evaluation time.
8. Produce a non-cloneable in-process `ValidatedPromotion` capability.
9. Stage the capability, durably persist epoch/incarnation anti-replay state,
   confirm the exact record, then activate. No persistence confirmation means
   the gate remains closed.

Gate 0 uses strongly typed in-memory values. A later wire revision must define
canonical encoding, domain-separated signatures, algorithm agility, certificate
chains, revocation, key rotation, clock uncertainty, and rollback resistance.
No ad-hoc cryptography will be added to the safety kernel.

The Gate 0 clock and persistence interfaces are trusted abstractions. The draft
does not yet specify their distributed time bounds or durable storage protocol.
