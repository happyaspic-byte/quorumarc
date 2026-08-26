# RPO-0 demonstration workload

## Current status

`quorumarc-rpo0` is an **IMPLEMENTED** library for a deliberately small
monotonic-counter workload. It provides:

- a fixed-schema, checksummed write-ahead log (WAL) and strict recovery;
- a coordinator that returns an acknowledgement only after two distinctly
  identified `ReplicaSink` instances return matching durable receipts;
- an on-disk `FileReplica` that validates the existing WAL, appends the exact
  canonical record, calls `sync_all` on the file, and syncs its parent
  directory before returning;
- exact-tail retry after a lost response: if the canonical record is already
  the validated durable tail, the replica re-syncs and returns the same receipt
  instead of appending it twice; changed reuse remains fail-closed;
- stable 16-byte operation IDs, exact-retry deduplication, conflicting-reuse
  refusal, and recovery of the deduplication table from the WAL;
- deterministic commit indexes and SHA-256 state roots exposed as
  `WorkloadProgress`; and
- in-memory fault injection plus automated tests for acknowledgement,
  recovery, corruption, truncation, stale/out-of-order requests, invalid
  receipts, missing replicas, identity collision, and duplicate operations.

This is not yet an end-to-end replicated service. A client protocol, data-node
network transport, concurrent-writer exclusion, checkpointing, a recovery CLI,
and a multi-host workload daemon are **NOT-IMPLEMENTED**. The two replica sinks
are ordinary library arguments and may be two files or in-memory fixtures in
one process. A distinct replica ID does not prove a distinct disk, machine, or
failure domain. `FileReplica` deliberately provides no cross-process fencing or
file lock.

The counter can report the commit index and state root that a promotion proof
would need to bind, but no current service durably couples that progress to the
authority store, canonical promotion envelope, witness decision, or
EffectGate. Consequently the repository does not claim end-to-end RPO 0,
automatic recovery, or workload failover. No exact CI run is linked from this
document, so the implementation and its tests are not labelled
**CI-VERIFIED** here.

Physical power, storage-cache, controller, independent-host, and network
behavior is **PHYSICAL-REQUIRED**. Hosted-runner process tests remain
software-only evidence on one runner.

## Narrow meaning of the target claim

For this named demo only, `RPO 0` is intended to mean:

> Every operation for which the demo client receives a success acknowledgement
> is recoverable from either surviving data node after any one fault inside the
> explicitly tested crash/storage model.

The implemented library establishes a narrower building block: when
`ReplicatedCounter::apply` returns success, two distinct sinks have returned
receipts for the same canonical WAL record, commit index, and checksum, and the
unit tests recover the acknowledged state from either sink. It does not yet
establish that the sinks are independent nodes or that a network client
received the acknowledgement.

The eventual claim will not mean that every submitted or in-flight request
succeeded. It will not cover arbitrary databases, filesystems, virtual
machines, queues, devices, client sessions, or malicious/Byzantine faults.
Loss of a data node must stop success acknowledgements rather than silently
weaken the two-copy policy.

## Implemented library semantics

The current counter path behaves as follows:

1. A caller supplies a stable 16-byte operation ID, its observed commit index,
   and a non-zero increment.
2. Exact reuse of an already applied ID returns the stored acknowledgement
   without another append. Reuse with different input is refused.
3. Stale or future commit expectations are refused before replica I/O.
4. The counter creates one canonical WAL record containing the next commit
   index, operation ID, previous value, increment, resulting value, version,
   lengths, and CRC.
5. The left and right sinks must have different replica IDs. Each validates its
   existing WAL before appending.
6. An exact retry whose canonical bytes are already the validated WAL tail
   returns the same receipt. This resolves a local response-loss ambiguity
   without a duplicate append; it is not a distributed commit marker.
7. Success is returned only after both receipts bind the expected replica ID,
   commit index, and record checksum. Any append uncertainty or invalid receipt
   poisons that in-memory writer so later writes remain refused until explicit
   recovery.
8. Recovery accepts only a complete, checksum-valid, contiguous WAL with
   consistent value transitions and unique operation IDs. Two recovered copies
   must be exactly equal before `ReplicatedCounter::from_recovered` reopens the
   logical writer.

The current writes to the two sinks are serial, not an atomic distributed
transaction. If the first append succeeds and the second fails, the writer
returns no acknowledgement and enters the uncertain state. An operator or
future service must reconcile the replica prefixes safely; the library does
not truncate, roll back, or guess.

## Missing service and promotion integration

The complete Gate 1A demonstration still needs to:

1. expose a bounded authenticated client/data-node protocol with stable
   request IDs and an acknowledgement trace;
2. run each durable sink on an independently controlled data-node process;
3. prevent concurrent or stale processes from writing either WAL;
4. reconcile an unacknowledged one-sided append without losing a possibly
   committed operation;
5. durably couple the jointly acknowledged commit/root to the authority store;
6. bind that exact progress into the final signed promotion envelope and refuse
   a lagging or divergent candidate;
7. open the EffectGate only after the complete durable authority decision; and
8. define checkpoint, backup, node replacement, and key/policy transitions.

The witness stores no recoverable workload data, so its vote cannot replace
the second durable data copy.

## Acknowledgement and recovery oracle

The future client trace must distinguish `submitted`, `acknowledged`,
`refused`, and `unknown because the connection failed`. After every injected
fault, recovery must replay each WAL to a valid prefix and report its highest
commit/root and operation-ID result table. The acceptance oracle compares only
acknowledged operations:

- every acknowledged operation appears exactly once in recovered logical
  state;
- no two different results exist for one operation ID;
- the recovered root at each compared commit is identical on both valid
  copies;
- a promoted candidate is at or above the authority-required commit and
  matches its root; and
- when two-copy durability is unavailable, no new success acknowledgement is
  observed.

An operation whose response was lost may have committed. The client must retry
the same operation ID to resolve that ambiguity; the exact-tail behavior makes
the local replica retry idempotent. It must not issue a replacement ID and then
call a duplicate result data loss.

Recovered WAL state exposes an exact-operation confirmation API. It returns the
durable commit, value, and state root only when operation ID, expected prior
commit, and increment all match. The lifecycle lab uses this after an Active
loss to answer a signed duplicate request from the successor without appending
another record. This is recovered-dedup evidence for the fixed pre-seeded
operation, not a continuous network client-write service.

A single surviving WAL cannot by itself distinguish "both replicas durable and
the client acknowledged" from "only this replica durable and the operation
returned unknown/failure." A future service therefore needs an authenticated
two-copy commit decision and acknowledgement trace. The current bytes must not
be described as proving that boundary.

## Remaining software campaign

The existing unit tests exercise the library contract and its local fault
fixtures. Before a GitHub-hosted end-to-end RPO demonstration is reported, an
automated process campaign must additionally cover:

- fresh start and clean restart of two independent data-node processes;
- crash before append, during a partial append, after append but before sync,
  after each local sync, and before/after the client response;
- duplicate requests before and after process restart;
- operation-ID reuse with different content;
- truncated, corrupt, reordered, and unexpected-version WAL frames;
- one data node unavailable, slow, or returning a durability error;
- candidate lag and same-index state-root mismatch;
- safe reconciliation of a one-sided unacknowledged WAL append;
- promotion/restart from the last jointly durable acknowledged index; and
- repeated failover/failback with a replayable seed and exact acknowledged set.

Every result must identify the exact commit, validation class, platform,
filesystem, fault point, seed, acknowledgement trace, recovered commits/roots,
and pass/fail oracle. A green unit test alone is not a physical RPO claim.

## Exit boundaries

- **IMPLEMENTED now:** counter state machine, WAL codec/recovery, file and
  in-memory replica sinks, dual-receipt acknowledgement, recovered dedupe, and
  promotion-progress output.
- **IMPLEMENTED service exit:** authenticated client/data-node service,
  independently hosted sinks, safe prefix reconciliation, and durable
  promotion/EffectGate integration are present and reviewed.
- **CI-VERIFIED exit:** the exact commit has a linked successful run of the full
  software campaign with retained summaries/traces.
- **SIMULATED label:** user-space crashes, partial writes, delays, and partitions
  on a hosted runner keep this label.
- **PHYSICAL-REQUIRED exit:** independent A/B hosts are tested with real power,
  storage, NIC/switch, clock/pause, and selected fence/effect adapters.

Even after these exits, the result is evidence for this named demonstration
workload only and is not a production availability or arbitrary-application
RPO guarantee.
