# Gate 1A: GitHub-first authority lab

## Status and claim boundary

Gate 1A is an **incomplete foundation**, not an automatic HA product. The branch
contains a canonical signed envelope, durable authority store, Witness actor,
bounded framing, test EffectGate, RPO-0 demonstration workload, safe-default
CLIs, and focused process/fault tests. A bounded integration also connects one
candidate, one peer, and one Witness in an explicitly enabled
`LAB_GENESIS_ONE_SHOT` transaction. A separate command-driven lifecycle lab
runs long-lived Node A, Node B, and Witness processes through multiple signed
authority epochs. It is not an automatic HA controller.

The one-shot test starts three processes, attempts one two-copy demo write,
obtains a durable Witness decision, persists candidate authority, and emits one
logical test effect. It neither kills an Active nor promotes the other node.
Exact-head GitHub results are recorded in the Draft PR; even a green run is
only bounded one-host process evidence. The project does not claim completed
failover, failback, zero downtime, global
single-writer enforcement, or production RPO 0. The lifecycle test adds actual
Active kill/pause and safe logical transfer against the test sink, while its
controller-supplied time and explicit promote command remain lab boundaries.

The GitHub-hosted lab also shares one virtual machine, kernel, clock, power
source, and storage stack. It can validate software components and controlled
process faults; it cannot establish physical failure-domain independence or
the correctness of real fence hardware.

## Evidence snapshot

The following facts must not be conflated:

| Evidence class | Current evidence | Claim limit |
|---|---|---|
| Implemented in source | Wire, store, runtime, demo workload, refusal CLIs, bounded genesis, and command-driven long-running lifecycle lab | Presence or compilation is not a successful exact-head run |
| Exact-head compact model | The [Draft PR](https://github.com/happyaspic-byte/quorumarc/pull/2) links the depth-12 report and artifact for its current head | Applies only to that model revision and its assumptions |
| Exact-head coverage | The Draft PR links the generated workspace and per-file coverage report | A workspace percentage does not establish aggregate critical-path compliance |
| Exact-head workspace tests | The Draft PR links the exact commit, run, test inventory, and artifact digest | Component/process success is not an integrated failover PASS |
| GitHub-hosted process scope | The PR exact-head evidence covers the process suites associated with that commit | Shared host, logical clock, test sink, and explicit control commands remain |
| Required scenario campaign | Lifecycle source covers 21 scenario IDs and emits bounded trace fields, including bounded Node/Witness fault proxies | Exact-head workflow evidence is required; rows 6, 19, 20, 23 and physical classes remain |
| Physical validation | No physical campaign has run | Desktop/server, NIC, switch, fence, VIP, and hardware-clock claims are absent |

Run numbers without an exact commit and artifact are historical diagnostics,
not current exit evidence. Static source documentation therefore avoids
retaining an older run as a current measurement. The final candidate must record its own successful
workflow URL, commit SHA, test inventory, model report, coverage report, and
scenario artifacts.

## Implementation classification

### Implemented components

- A deterministic, length-bounded promotion envelope and domain-separated
  Ed25519 signature verification with strict version and trailing-byte checks.
- A checksummed authority journal with atomic replacement, durable generation,
  restart recovery, single-vote enforcement, and declared storage fault points.
- A durable Witness actor, bounded frames, idempotent request IDs, and a
  generation-scoped test EffectGate sink.
- A WAL-backed monotonic-counter demonstration that requires two distinct
  durable replicas before acknowledging an operation and deduplicates stable
  operation IDs.
- A localhost TCP Witness process harness with deterministic cases for kill,
  restart, conflict, stale epoch, malformed/authentication failures, bounded
  clean exit, concurrency, and pause/resume behavior.
- A same-binary three-mode bounded lab for one peer fsync, one durable
  Witness vote/fixture fence, candidate proof/store ordering, and one logical
  test-sink effect after explicit lab-genesis opt-in.
- A one-command release self-test that creates isolated deterministic fixtures,
  launches the three roles, recovers both WALs and authority stores, verifies
  exact generations and lock release, and removes successful state by default.
- Safe-default `quorumarc-agent` and `quorumarc-witness` command shells for
  status, health, inspection, and bounded failure simulation.

### Verified only within a limited class

- The compact model checks its stated invariants under one serial metadata view
  and one trusted logical clock, at the exact explored depth.
- Unit and integration tests check component contracts and selected process
  behavior on a shared runner.
- Local owner locks and path checks scope the one-shot test to one declared
  filesystem instance. They do not prevent an independently cloned credential
  and store set from authorizing a separate sink.
- Crash campaigns check the declared file-store API fault points, not arbitrary
  controller, filesystem, firmware, or total trusted-copy rollback behavior.
- The test EffectGate records logical effects; it is not nftables, eBPF,
  storage-reservation, VIP, BMC, PDU, or device enforcement.

### Not implemented or not integrated

- One restart-safe authority transaction joining the now-separated proposal and
  final-envelope digests to trusted time, fencing, durable activation, and
  EffectGate opening.
- Identical long-running Node A and Node B services with consensus-derived roles.
- Automatic first election, Active failure detection, safe promotion, failback,
  and externally observable workload recovery.
- Real fencing and real effect adapters.
- A global PASS for all 25 required failure scenarios.
- Coverage gates at 80% workspace and 90% critical safety paths.
- p50/p95/p99 failover and RPO-0 write latency from an integrated flow.

### Requires future physical validation

- Independent power, NIC, switch, storage, and clock failure domains.
- BMC/Redfish, PDU, storage-reservation, or equivalent fencing with read-back.
- VIP/endpoint movement, client-observed outage, ARP/ND convergence, and load.
- Ordinary Ubuntu data hosts plus a genuinely independent Witness host/device.

## Goal

Run Node A, Node B, and a non-workload Witness as independently addressable
processes. Promotion must remain fail-closed unless one canonical, signed
envelope binds all of the following evidence:

- workload, candidate node, and candidate boot incarnation;
- epoch, protocol version, message ID, and policy hash;
- quorum votes and voter identities;
- fence receipt or a conservatively expired authority lease;
- required and candidate durable commit indexes plus state root;
- health attestation and exact lease bounds.

The authority decision must be durable before the EffectGate can open. A
missing key, unknown version, ambiguous durable record, replay, state mismatch,
or unavailable Witness must result in a typed refusal and a closed gate.

## Current promotion-integration blocker

The earlier proposal/final-digest dependency cycle is resolved in source. A
domain-separated digest covers the complete canonical quorum binding before
votes exist. The Witness persists that proposal digest; a promotion record in
authority journal format v3 persists both that value and the digest of the
complete signed envelope, together with cluster/workload/node/role/store
identity. Promotion recovery matches vote to proposal, while activation matches
its receipt to the final signed-envelope digest. Format v1 and v2 are
deliberately rejected rather than ambiguously migrated.

The explicit lab-genesis candidate threads these materials through three
processes and a test sink. Its evidence is synthetic: fixed logical time, a
fixture bootstrap fence, deterministic test membership, and one operation. It
is not the normal agent control plane and does not implement election, failure
detection, lease renewal, failover, or failback. The agent therefore continues
to refuse `run` with `ACTIVATION_CONTROL_PLANE_UNAVAILABLE`.

No local protocol can detect a perfect clone of every trusted store, its v3
expected identity/configuration, and the Witness credential. Production safety
additionally needs protected Witness ownership, independently enforced
anti-rollback identity, independently verified replication progress, and real
fencing or safe expiry.

## Incremental delivery

### Gate 1A.0 — signed durable-authority components

**Status: component foundation implemented; integrated activation incomplete.**

1. Define a length-bounded deterministic promotion envelope.
2. Sign a domain-separated digest with a reviewed standard signature library.
3. Verify signer identity, key status, complete-envelope binding, and version.
4. Persist epoch, incarnation, vote, proof digest, lease, durable state, and
   activation receipt using an atomic crash-recoverable store.
5. Refuse same-epoch double voting and rolled-back or corrupt state.
6. Keep every failure path closed until a complete authority transaction is
   durably verified.

The component source supports these pieces, but Gate 1A.0 cannot claim an exit
until the exact head has a linked green run and the durable material is
joined to the missing activation control plane without weakening fail-closed
behavior.

### Gate 1A.1 — three-process control plane

**Status: bounded one-shot lab plus long-running lifecycle and deterministic
automatic-decision state machine; autonomous controller incomplete.**

- Run identical agent binaries for Node A and Node B, plus a Witness that can
  vote but cannot host or activate a workload.
- Authenticate peers, bound messages, use explicit versions and request IDs,
  and make retries idempotent.
- Add process lifecycle, delay, duplication, reordering, partition, pause, and
  restart controls to a deterministic fault proxy or equivalent.
- Record every safety decision with stable reason codes and replayable seeds.

The [lifecycle laboratory](LIFECYCLE_LAB.md) now runs identical long-lived data
node services and a distinct durable Witness. It performs signed, durable,
lease-guarded authority transfers and real process kill/pause tests. Promotion
is still initiated by a deterministic test command. The command is signed by
one pinned lab controller key and bound to its target node. A deterministic
state machine requires repeated failed probes plus lease/guard expiry before a
promotion attempt, but the harness supplies observations and execution. RBAC,
durable cross-restart command replay protection, an autonomous trusted failure
detector, explicit message reordering and A/B data-path faults, production
time/fence adapters, and all-scenario completion remain open. Bounded
Node/Witness fault proxies now cover drop, delay, duplicate, reply-loss,
corruption, and stale-request injection. The one-shot
self-test remains the packaged installation diagnostic and is not election or
failover evidence.

### Gate 1A.2 — RPO-0 demonstration workload

**Status: component implemented; authority/failover integration incomplete.**

- Acknowledge an operation only after both data replicas durably record it.
- Bind commit index and state root into promotion authority.
- Deduplicate retries with a stable operation ID.
- Stop acknowledging writes when the two-copy contract cannot be maintained.
- Recover every acknowledged operation after a single data-node loss.

The small monotonic-counter workload is protocol evidence, not a general
database and not proof that arbitrary applications achieve RPO 0.

### Gate 1A.3 — repeatable safety campaign

**Status: partial component/model/process cases; no global scenario PASS.**

- Automate the 25 rows in [the failure matrix](FAILURE_MATRIX.md) against the
  integrated three-role lifecycle.
- Retain seeds and traces and upload bounded artifacts.
- Run malformed-input, crash-recovery, multi-seed, and bounded fuzz campaigns.
- Measure logical failover and write latency without weakening lease or fencing.
- Raise measured coverage through meaningful safety-path tests; do not lower
  the 80% workspace or 90% critical-path targets to declare success.

## Authority transaction required for activation

1. **Recover:** load durable state; ambiguity enters a blocked repair state.
2. **Catch up:** candidate reaches the required commit and exact state root.
3. **Fence or wait:** prove fencing or wait through the old lease and guard.
4. **Vote:** each voter durably records its proposal-bound vote before reply.
5. **Certify:** assemble and verify the complete signed promotion envelope.
6. **Commit:** durably record the epoch, final digest, and lease.
7. **Activate:** open only the matching generation-scoped EffectGate.
8. **Receipt:** durably record an inspectable activation receipt.

No direct `closed -> open` transition is valid. A crash at any point must
recover by completing the same idempotent transaction or remaining closed.

## CI evidence required for an exit claim

- exact commit SHA and successful workflow URL;
- format, Clippy with warnings denied, and locked workspace tests;
- model depth, states, transitions, and violation count;
- scenario-by-scenario result with seed and validation class;
- crash-recovery and malformed-envelope summaries;
- actual coverage and latency produced by the linked run;
- dependency/security scan result and accepted exceptions;
- explicit residual limitations.

A source test count is not a successful test count. A historical workflow is
not evidence for a later tree. Until all items are linked, Gate 1A remains under
development.

## Explicitly outside Gate 1A

- production-grade Redfish, IPMI, PDU, storage-reservation, nftables, eBPF, or
  device fencing;
- protection of arbitrary virtual machines or block devices;
- Byzantine-fault-tolerant consensus;
- proof of clock bounds across independent hosts;
- an availability or downtime service-level agreement;
- a public-repository self-hosted runner;
- modification of `r8-protocol` or use of R8 as authority, quorum, or fencing.

The physical continuation is described in [the lab setup](LAB_SETUP.md), and
residual gaps are maintained in [known limitations](KNOWN_LIMITATIONS.md).
