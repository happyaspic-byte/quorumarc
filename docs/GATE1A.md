# Gate 1A: GitHub-first authority lab

## Status and claim boundary

QuorumArc starts from **Gate 0**: an in-memory promotion-proof validator, a
logical fail-closed EffectGate, and a deterministic compact-state simulator.
The Gate 1A feature branch now also contains canonical signed-envelope,
durable-store, witness-runtime, RPO-0 demonstration, and real-process lab
building blocks. These components do not yet form an automatic two-node
failover service. Nothing in this document changes that claim.

Gate 1A is an incremental engineering program for exercising the authority path
with real processes on a GitHub-hosted Ubuntu runner. A substage is complete only
after its code, tests, and successful GitHub Actions run are linked from the
change that claims completion. A design document, compiling module, or isolated
unit test is not completion evidence.

The GitHub lab is deliberately not called production HA. Its participants share
one virtual machine, kernel, clock, power source, and underlying storage. It can
test protocol behavior and crash recovery, but it cannot establish independence
of physical failure domains or the correctness of real fencing hardware.

### Implemented and verified boundary

- A GitHub-hosted runner has executed a Witness as a child process and exchanged
  authenticated, bounded protocol frames over a real localhost TCP socket. The
  lab covers durable retry after `SIGKILL`, same-epoch conflicting-candidate
  refusal, stale-epoch replay refusal, malformed and oversized frames,
  unauthenticated requests, and disconnect-before-request. This evidence is in
  [workflow run 32706670597](https://github.com/happyaspic-byte/quorumarc/actions/runs/32706670597).
- The `quorumarc-agent` and `quorumarc-witness` command-line programs are
  safe-default inspection and refusal shells. They can report health/status,
  inspect snapshots or proofs without becoming an active writer, and exercise
  selected failure paths. They deliberately refuse activation, automatic
  promotion, and network voting because the complete authority transaction is
  not connected.
- Canonical wire, durable-store, witness-runtime, and demonstration RPO-0
  modules have focused tests. Their presence does not mean that the complete
  Node A/Node B/Witness lifecycle or workload failover path has been integrated.

Not yet complete are automatic promotion, a physical fence adapter, the full
25-scenario failure campaign, coverage exit thresholds, and p50/p95/p99
failover or write-latency measurements. No production-readiness, zero-downtime,
or physical-fencing claim follows from the current GitHub evidence.

## Goal

Run Node A, Node B, and a non-workload Witness as independently addressable
processes. Promotion remains fail-closed unless one canonical, signed envelope
binds all of the following evidence:

- workload, candidate node, and candidate boot incarnation;
- epoch, protocol version, message ID, and policy hash;
- quorum votes and their voter identities;
- fence receipt or a conservatively expired authority lease;
- required and candidate durable commit indexes plus state root;
- health attestation and exact lease bounds.

The authority decision must be durable before the test EffectGate can open. A
missing key, unknown version, ambiguous durable record, replay, state mismatch,
or unavailable witness must result in a typed refusal and a closed gate.

## Incremental delivery

### Gate 1A.0 — signed durable-authority smoke

The component pieces below are implemented and tested in isolation or in the
limited Witness process lab. The end-to-end authority transaction is not a
completed capability claim.

1. Define a length-bounded, deterministic canonical promotion envelope.
2. Sign a domain-separated digest with a reviewed standard signature library.
3. Verify signer identity, key status, complete-envelope binding, and version.
4. Persist highest epoch, incarnation, vote, proof digest, lease, durable state,
   and activation receipt using an atomic crash-recoverable store.
5. Refuse same-epoch double voting and rolled-back or corrupt state.
6. Exercise `stage -> durable confirmation -> activate -> effect` with a test
   sink; inject failure before and after every persistence boundary.

Gate 1A.0 exits only when restart tests show that an acknowledged vote or
authority record cannot be forgotten, malformed inputs fail closed, and the
existing Gate 0 invariants remain green.

One integration blocker remains: a durable `VoteRecord` binds a
`proposal_digest` before the quorum certificate exists, while the final signed
promotion-envelope digest includes the resulting certificate. Treating those
two digests as the same value creates a dependency cycle: votes would need to
sign a final digest that itself depends on those votes. The current Witness
runtime therefore uses a distinct proposal-binding digest and the agent keeps
promotion closed. Before activation can be enabled, the wire protocol and
durable schema must explicitly define and persist both the pre-certificate
proposal binding and final certified-envelope digest, with verification across
restart.

### Gate 1A.1 — three-process control plane

- **Partial only:** the current real-process TCP lab exercises a Witness child
  process and a client harness; it is not yet a complete Node A/Node B/Witness
  control plane.
- Run identical agent binaries for Node A and Node B, plus a Witness that can
  vote but cannot host or activate a workload.
- Authenticate peers, bound messages, use explicit versions and request IDs,
  and make retries idempotent.
- Add process lifecycle, delay, duplication, reordering, partition, pause, and
  restart controls to a deterministic user-space fault proxy or equivalent.
- Record every safety decision with stable reason codes and a replayable seed.

### Gate 1A.2 — RPO-0 demonstration workload

- **Component implemented, authority integration incomplete:** the WAL-backed
  demonstration enforces two distinct durable replicas before acknowledgement,
  but its commit index and state root are not yet carried through an automatic
  failover transaction.
- Add a small counter or key/value workload with a checksummed write-ahead log.
- Acknowledge a write only after both data nodes have made it durable.
- Bind the committed index and state root into promotion authority.
- Deduplicate retries with a stable operation ID.
- Stop acknowledging writes when the two-copy durability contract cannot be
  maintained; do not silently weaken the policy for availability.

This workload is evidence for the QuorumArc protocol. It is not a general-purpose
database or a claim that arbitrary applications automatically achieve RPO 0.

### Gate 1A.3 — repeatable safety campaign

- **Not complete:** focused process-lab cases are automated, but the required
  25-scenario matrix, coverage thresholds, and timing distributions are not.
- Automate the 25 scenarios in [the failure matrix](FAILURE_MATRIX.md).
- Retain seeds and traces for failures and upload bounded artifacts from CI.
- Add malformed-input, crash-recovery, multi-seed, and bounded fuzz campaigns.
- Measure logical failover and write latency without weakening lease or fencing
  requirements to meet a latency target.

## Validation classes

| Class | What it can establish | What it cannot establish |
|---|---|---|
| Gate 0 model | Safety of the compact explored state machine at the reported depth | Concurrent independent views, real storage, real networking, physical fencing |
| GitHub-hosted 1A | Wire compatibility, authenticated process interaction, idempotency, file-store crash recovery, controlled fault schedules | Independent machines, power/NIC/switch faults, BMC/PDU behavior, hardware clock bounds |
| Future physical lab | Two-host behavior, real NIC/switch paths, actual endpoint movement, measured outage, selected fence adapters | Production readiness without longer campaigns, supported hardware matrix, and independent review |

Results must always name their class. A user-space simulated partition must not
be reported as a switch failure, and killing a process must not be reported as
power fencing.

## Authority transaction

1. **Recover:** load durable authority state; any ambiguity enters a blocked
   state that requires repair or operator intervention.
2. **Catch up:** candidate reaches the proof's required commit and state root.
3. **Fence or wait:** obtain authoritative fencing evidence or wait through the
   old authority lease plus its safety guard.
4. **Vote:** every voter durably records its vote before replying.
5. **Certify:** form and verify the complete signed promotion envelope.
6. **Commit:** durably record the new epoch, proof digest, and lease.
7. **Activate:** open only the generation-scoped test EffectGate.
8. **Receipt:** append an activation receipt that can be inspected and replayed.

No direct `closed -> open` transition is valid. A crash at any point must recover
to a state that either finishes the same idempotent transaction or stays closed.

## CI evidence required for an exit claim

- exact commit SHA and successful workflow URL;
- Rust format, Clippy with warnings denied, and all workspace tests;
- Gate 0 regression report with explored depth, states, transitions, and
  single-writer violations;
- scenario-by-scenario Gate 1A result with seed and validation class;
- crash-recovery and malformed-envelope summaries;
- measured coverage and latency only when produced by the linked run;
- dependency/security scan result and any accepted exceptions;
- explicit residual limitations.

Until those artifacts exist, status remains **planned or under development**.

## Explicitly outside Gate 1A

- production-grade Redfish, IPMI, PDU, storage-reservation, nftables, eBPF, or
  device fencing;
- protection of arbitrary virtual machines or block devices;
- Byzantine-fault-tolerant consensus;
- proof of clock bounds across independent hosts;
- an availability or downtime service-level agreement;
- production deployment on a public-repository self-hosted runner;
- any modification of `r8-protocol` or use of R8 as authority, quorum, or
  fencing.

The physical continuation is described in [the lab setup](LAB_SETUP.md), and
known gaps are maintained in [known limitations](KNOWN_LIMITATIONS.md).
