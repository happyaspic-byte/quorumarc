# Architecture

## Product thesis

Most failover systems focus on deciding that a primary is unavailable. QuorumArc
focuses on proving that a replacement can safely create external effects. The
proof is checked by a small Rust safety kernel before network, storage, serial,
USB, PLC, or other outputs are enabled.

## Planes

| Plane | Responsibility | Initial mechanism |
|---|---|---|
| Safety | Epochs, votes, policies, promotion proofs | A/B/Witness 2-of-3 metadata quorum |
| Data | Recoverable workload state | Synchronous WAL or validated native adapter |
| Effect | Enforce single externally effective writer | Lease-bound fail-closed EffectGate |
| Recovery | Restore and prewarm workload | systemd/container first; KVM later |
| Endpoint | Publish the active generation | VIP/proxy/eBPF generation adapter |
| Transport | Carry redundant data paths | Standard transport; optional pinned R8 adapter |
| Simulation | Explore clocks, partitions, crashes, disks | Same pure state rules as production |

## Core objects

### Continuity Capsule

A versioned declaration for one protected workload:

- workload identity and policy hash;
- state source and required durable commit index;
- all external effects that must be fenced;
- recovery and health-check adapters;
- continuity level and RTO/RPO target;
- failure domains and required voters.

An undeclared external effect makes the capsule ineligible for automatic
promotion. This prevents a healthy network service from being labelled safe
while both copies can still write to a serial controller or shared device.

### PromotionProof

An immutable evidence bundle binding one candidate, workload, epoch, policy,
lease, quorum, fence, durable state, and health attestation. Gate 0 validates the
structure in memory. Later gates add durable consensus records, signatures,
anti-rollback storage, and a canonical wire format.

The quorum certificate binds the candidate boot incarnation, required commit,
state root, and exact lease bounds. A candidate cannot lower the required commit
or lengthen a lease after votes were issued. The signed wire revision must bind
the complete fence and health evidence through one canonical promotion digest.

### EffectGate

The last enforcement boundary before a side effect. It only opens for a
validated proof and closes automatically at lease expiry. An implementation may
use tc/eBPF for host networking, storage reservations for shared disks, BMC/PDU
for power, or device-specific fencing. A userspace flag alone is not sufficient
for a production safety claim.

Gate 0's Rust `check_effect` method is a logical model check, not a kernel I/O
barrier: time can pass after it returns. Production claims require enforcement
at packet/storage/device execution time, not a userspace check-then-act sequence.

### Continuity Receipt

The activation result records epoch, holder, workload, policy, durable commit,
state root, fence class, and lease interval. The wire revision must also include
the signed complete proof digest. Receipts are intended to be append-only and
directly replayable by the simulator.

## Failover transaction

1. **Prepare:** restore, catch up, validate state, prewarm caches, and prepare
   endpoint changes while external effects remain closed.
2. **Fence:** close the old EffectGate or obtain an independently verified
   hardware/storage fence receipt.
3. **Certify:** bind quorum, fence, state, health, lease, and policy into a proof.
4. **Commit:** persist the new epoch and activation decision.
5. **Publish:** open the new gate and publish the new endpoint generation.
6. **Receipt:** append the evidence and measured timing for audit/replay.

Every step is idempotent and crash-recoverable in the intended production
design. Gate 0 implements validation and local gate transitions only.

## Deployment topology

- Node A and Node B host identical Rust agents and protected workloads.
- The witness must occupy an independent power, switch, and administrative
  failure domain whenever automatic failover is expected.
- The management UI is not in the safety path. A UI outage cannot create or
  prolong authority.
- Windows and Linux guests can be protected later on Linux KVM hosts; guest
  cooperation through VSS/fsfreeze is a capability, not an assumption.
