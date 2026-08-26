# Product-completeness program

## Objective

QuorumArc is intended to exceed established VM-level fault-tolerance and
application-level HA products in **safe authority, explainability, industrial
effect control, offline operability, and repeatable evidence**. That objective
is a roadmap and acceptance bar, not a statement about the current build.

The project must not obtain a favourable comparison by narrowing a competitor's
scope, counting source files, or labelling unverified adapters as implemented.
The current product remains below a commercial HA system until every P0 item is
implemented and physically validated.

## Competitive exit bar

| Product dimension | Required QuorumArc outcome | Current evidence |
|---|---|---|
| Safe authority | Signed proof binds quorum, fence/expiry, lease, policy, health, commit and root | Component and bounded one-shot lab |
| Automatic lifecycle | Long-running identical A/B agents perform election, failover and safe failback | Not implemented |
| External uniqueness | At least one real enforced endpoint/effect adapter plus verified fence read-back | Not implemented |
| Data continuity | Named synchronous workload profiles with a durable client-ack boundary and recovery proof | Counter component demonstration only |
| Setup | Validated package, configuration wizard, one-command preflight and rollback-safe upgrade | One-command bounded self-test implemented; installer not implemented |
| Operations | Local Web/API status, topology, alarms, reason codes, receipts and guided repair | CLI diagnostics only |
| Workload coverage | systemd and container profiles first; KVM and supported databases later | Not implemented |
| Security lifecycle | Provisioning, least privilege, rotation, revocation, SBOM, provenance and independent review | Partial cryptographic interfaces and CI dependency checks |
| Availability evidence | 25 integrated scenarios, latency percentiles, zero single-writer violations and zero acknowledged loss | Component/model evidence; 0/25 global PASS |
| Physical evidence | Two data hosts, independent Witness, NIC/switch/power/storage/fence/VIP campaigns | Not performed |
| Serviceability | Backup, restore, node replacement, upgrade, rollback, support bundle and runbooks | Documentation sketches only |
| FT continuity | Supported memory/device/session continuity profiles | Later research gate |

## Priority classes

### P0 — safe usable HA

1. Identity-bound, rollback-aware durable authority stores.
2. Long-running identical Node A and Node B services plus an independent
   Witness service.
3. Authenticated health, durable-progress leases, election, planned switch,
   Active failure, promotion, and safe failback.
4. One real fence adapter and one I/O-bound EffectGate adapter.
5. Integrated synchronous workload acknowledgement and recovery.
6. All 25 failure scenarios with retained traces and exact CI evidence.
7. Physical three-host validation before any production claim.

### P1 — deployability and operations

1. Versioned TOML schema, offline validation and configuration generation.
2. Signed `.deb` and offline bundle, service users, systemd units and
   uninstall/upgrade procedures.
3. Local management API and Korean/English Web console outside the safety path.
4. Topology, reason-code explanation, proof/store inspection, alarms and
   support-bundle export.
5. Safe backup/restore, key rotation, node replacement and repair workflows.

### P2 — workload breadth

1. systemd TCP service profile.
2. Docker/Podman container profile.
3. PostgreSQL or another explicitly contracted database profile.
4. VIP/nftables, proxy, serial, USB-over-network and PLC effect boundaries.
5. KVM restart and warm-standby profiles only after the Linux service path is
   physically qualified.

### P3 — service and assurance

1. Supported hardware/OS/firmware matrix and compatibility tests.
2. Seven-day soak and at least 10,000 seeded fault cycles on a declared lab.
3. Independent distributed-systems, cryptographic and penetration review.
4. Release provenance, SBOM, vulnerability response, long-term support policy,
   diagnostics and operator training.

## Usability targets

These targets are not achieved until measured on the declared release:

- fresh lab installation and validated configuration in at most 15 minutes;
- one command for non-destructive pre-installation diagnostics;
- no secret copied through a dashboard, command line, Git repository or trace;
- a failed configuration names an actionable reason code and the unsafe effect
  that remains closed;
- planned switch from the management interface with an exported receipt;
- every upgrade has a preflight, compatibility decision and closed-gate abort;
- automatic promotion remains disabled until an operator explicitly approves a
  complete eligible workload capsule.

## Claim discipline

“More complete” is accepted only when the exact release has stronger evidence
for its declared workload and topology. VM memory continuity cannot be inferred
from fast application restart. Application compatibility cannot be inferred
from a generic process adapter. RPO 0 cannot be inferred from two files without
a durable external acknowledgement boundary. A userspace flag is not fencing.

The [failure matrix](FAILURE_MATRIX.md), [engineering targets](TARGETS.md),
[known limitations](KNOWN_LIMITATIONS.md), and successful exact-head workflow
artifacts are the authoritative scorecard.
