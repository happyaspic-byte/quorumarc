# QuorumArc

[![CI](https://github.com/happyaspic-byte/quorumarc/actions/workflows/ci.yml/badge.svg)](https://github.com/happyaspic-byte/quorumarc/actions/workflows/ci.yml)

QuorumArc is a **proof-carrying continuity fabric** research project for safe,
low-downtime failover. A node cannot become externally active merely because
it believes its peer is dead. It must present verifiable authority evidence for
quorum, fencing or safe lease expiry, durable state, health, time, and policy.

> Status: **Gate 1A foundation under development.** The repository contains
> tested protocol, storage, runtime, RPO-0 demonstration, and process-lab
> components, but it does not yet implement automatic Node A/Node B failover or
> a production EffectGate. Production readiness, zero downtime, and completed
> physical validation are not claimed.

## Core ideas

- **PromotionProof** — promotion is an evidence bundle, not a Boolean decision.
- **EffectGate** — stale or uncertified generations cannot emit external effects.
- **Continuity Capsule** — each workload declares state, effects, recovery, and
  its promised continuity level.
- **Continuity Receipt** — activation records the evidence that made it safe.
- **Progress lease** — renewal must depend on durable application progress, not
  heartbeat traffic alone.

The target authority flow below is architectural intent; the arrows are **not**
a claim that the complete flow is currently connected.

```mermaid
flowchart TD
    A["Node A Agent"] --> Q["2-of-3 quorum"]
    B["Node B Agent"] --> Q
    W["Independent Witness"] --> Q
    Q --> P["Certified PromotionProof"]
    P --> G["Generation-scoped EffectGate"]
    G --> X["Workload effects"]
```

## Safety invariants

1. At most one node may hold externally effective authority for a workload.
2. Every acknowledged demonstration RPO-0 write must survive one data-node loss.
3. Lower-epoch commands and side effects must be rejected at every boundary.
4. No promotion may occur before verified fencing or conservative gate expiry.
5. Missing or ambiguous evidence closes the gate; it never fails open.

These invariants are currently checked within the scopes of individual
components and the compact model. They have not yet been demonstrated by one
end-to-end Node A/Node B/Witness activation and failover campaign. See the
[safety model](docs/SAFETY.md), [Gate 1A scope](docs/GATE1A.md), and
[failure matrix](docs/FAILURE_MATRIX.md).

## Workspace

| Package | Implemented purpose | Current claim boundary |
|---|---|---|
| `quorumarc-core` | Promotion-proof validation and logical fail-closed EffectGate | In-memory safety kernel |
| `quorumarc-sim` | Deterministic compact-model schedule explorer | One serial metadata view and trusted logical clock |
| `quorumarc-wire` | Strict canonical envelope and domain-separated Ed25519 verification | Component protocol; not a complete authority transaction |
| `quorumarc-store` | Checksummed atomic authority journal with fault injection | File-store model; not proof for every disk/filesystem |
| `quorumarc-runtime` | Bounded frames, durable Witness actor, and test EffectGate sink | Component runtime only |
| `quorumarc-rpo0` | Two-replica WAL-backed monotonic-counter demonstration | Demonstration workload, not a general database |
| `quorumarc-lab` | Real localhost TCP Witness process and deterministic fault cases | No complete Node A/Node B active-writer lifecycle |
| `quorumarc-agent` | Safe-default inspection/refusal CLI | Automatic promotion deliberately disabled |
| `quorumarc-witness` | Safe-default Witness inspection/refusal CLI | No production network voting service |

## Implementation and validation status

| Classification | Current status |
|---|---|
| Implemented in source | Canonical signed wire format, durable authority store, Witness actor/process lab, RPO-0 demo, logical/test EffectGate, safe-default CLIs |
| Verified by compact model | Extended Safety run #6 on `0424290` explored depth 12: 143,439 unique states, 836,424 transitions, and 0 model invariant violations |
| Partially verified on GitHub-hosted Ubuntu | Component tests, a Witness child process over localhost TCP, bounded/malformed input handling, idempotent voting, and declared store crash points |
| Not yet end-to-end verified | Node A and Node B election, activation, real failover/failback, one integrated RPO-0 authority path, and all 25 scenarios as global PASS results |
| Requires physical equipment | Independent failure domains, real NIC/switch faults, BMC/PDU or storage fencing, VIP movement, hardware clock behavior, and client-observed outage |

Extended Safety run #6 on commit `0424290` executed **153 tests: 153 passed, 0
failed, 0 ignored**. It also completed 16 real-process Witness-lab repetitions,
16 durable-store crash-recovery repetitions, and all seven named malformed
parser checks. This is component/process evidence, not a global PASS for the 25
integrated failover scenarios.

That run measured **76.05% workspace line coverage**.
The 80% workspace target is therefore **not met**. No threshold is weakened or
silently treated as passing. The linked run's model counts apply only
to its exact compact-model revision and do not prove physical or end-to-end HA.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo run --locked -p quorumarc-sim -- --depth 12 --require-safe
```

Do not infer a completed Gate 1A result from a local run or from the CI badge.
An exit claim requires the exact commit, successful workflow URL, artifact, test
inventory, model report, coverage report, and scenario-by-scenario evidence.

## Primary unresolved blocker

The source now separates the canonical pre-certificate proposal digest from the
final signed-envelope digest, persists both in authority journal format v2, and
checks both during agent material inspection. That removes the earlier digest
dependency cycle without opening effects. Automatic activation remains blocked
because no trusted-time, fencing, lease-activation, and enforced EffectGate
control plane connects Node A, Node B, and the Witness. The agent reports
`ACTIVATION_CONTROL_PLANE_UNAVAILABLE` and remains closed. See
[known limitations](docs/KNOWN_LIMITATIONS.md).

## R8 boundary

The existing R8 Protocol repository remains unchanged. R8 may later be pinned
to an exact reviewed commit as an optional data-transport adapter. It is **not**
quorum, consensus, fencing, durable replication, or authority. See the
[R8 boundary](docs/R8_BOUNDARY.md).

## Delivery gates

- **Gate 0:** compact safety model and proof validator.
- **Gate 1A:** GitHub-hosted authority lab; current foundation is incomplete.
- **Gate 1 physical:** two Linux data hosts, an independent Witness, and real
  endpoint/fence adapters.
- **Later gates:** supported workload profiles, KVM adapters, and hot shadows.

The repository is public for review and reproducible research, but the code
remains proprietary under `LICENSE`; public visibility does not grant
production-use or redistribution rights. Formal trademark clearance is also
required before commercial release.
