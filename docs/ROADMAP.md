# Roadmap

## Gate 0 — proof before automation

- Pure Rust `PromotionProof` validator and fail-closed EffectGate.
- Typed refusal reasons and activation receipt.
- Deterministic exhaustive simulator and invariant tests.
- Continuity Capsule and canonical proof schema design.
- TLA+ model before real automatic promotion.

Exit rule: no live automatic failover capability is shipped.

## Gate 1 — Linux service continuity

- Two Linux data nodes and an independently placed witness.
- Durable metadata consensus and signed votes/receipts.
- systemd/container workload adapter.
- Real Redfish/PDU/storage fencing and a kernel-enforced network EffectGate.
- Planned switchover and failover drills with measured RTO.

## Gate 2 — explicit RPO-0 profiles

- Durable WAL protocol, snapshots, checksums, repair, and corruption alarms.
- Application-native profiles before generic block-level claims.
- Backpressure when the RPO contract cannot be maintained.

## Gate 3 — KVM warm standby

- libvirt/QEMU lifecycle and dirty-state transfer adapters.
- Linux fsfreeze and Windows VSS cooperation where available.
- Disk, memory, device, network, and external-effect consistency matrix.

## Gate 4 — selective hot shadow

- Request mirroring and output comparison only for supported workloads.
- Cooperative logical-session rebinding and stable operation IDs.
- Optional R8 dual-path adapter after separate protocol review.

Each gate requires a threat model, deterministic and hardware fault tests,
upgrade/rollback tests, closed-network installation material, and independently
reviewed claims before the next gate is advertised.
