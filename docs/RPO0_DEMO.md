# RPO-0 demonstration plan

## Current status

The RPO-0 demonstration workload is **NOT-IMPLEMENTED**. There is no replicated
counter/key-value service, workload WAL, dual-node durable acknowledgement path,
client protocol, recovery command, or three-process campaign in this repository.
Accordingly there is no **CI-VERIFIED** RPO-0 result.

The core proof types and canonical envelope bind required commit, candidate
durable commit, and state root (**IMPLEMENTED**). The authority store can retain
one commit/root, and the lab-only in-memory effect actor deduplicates operation
IDs during one process lifetime (**IMPLEMENTED**, but **SIMULATED** as an
external effect). Neither capability makes acknowledged workload data durable.
The in-memory actor loses its records on restart and is not the demo WAL.

Physical power, storage-cache, controller, and independent-host behavior is
**PHYSICAL-REQUIRED**. A GitHub-hosted process test, once built, would still be
software-only evidence on one runner.

## Narrow meaning of the future claim

For this demo only, `RPO 0` will mean:

> Every operation for which the demo client receives a success acknowledgement
> is recoverable from either surviving data node after any one fault inside the
> explicitly tested crash/storage model.

It will not mean that every submitted or in-flight request succeeded. It will
not cover arbitrary databases, filesystems, virtual machines, queues, devices,
client sessions, or malicious/Byzantine faults. Loss of a data node must stop
success acknowledgements rather than silently weaken the two-copy policy.

## Required demo design

The Gate 1A.2 target is a deliberately small counter or key/value state machine:

1. A client supplies a stable, non-zero 128-bit operation ID and an operation.
2. The active data node rejects conflicting reuse of an operation ID.
3. Both data nodes append a framed record containing operation ID, sequence,
   previous state/root, operation, and checksum to their local WAL.
4. Each data node makes the record durable according to the documented local
   store contract before reporting durable success.
5. The active acknowledges success only after both data-node durable results
   bind the same index and resulting state root.
6. Retries with the same ID and identical operation return the original result;
   reuse with different content is refused and self-fences the authority path.
7. Checkpointing never removes WAL needed to recover the latest acknowledged
   index on either node.
8. Promotion authority binds at least the last acknowledged commit and its
   state root. A candidate behind that commit or holding a different root is
   refused.

The witness does not store recoverable workload data in this design, so its
vote cannot replace the second durable data copy.

## Acknowledgement and recovery oracle

The client trace must distinguish `submitted`, `acknowledged`, `refused`, and
`unknown because the connection failed`. After every injected fault, recovery
must replay each WAL to a valid prefix and report its highest commit/root and
operation-ID result table. The acceptance oracle compares only acknowledged
operations:

- every acknowledged operation appears exactly once in recovered logical state;
- no two different results exist for one operation ID;
- the recovered root at each compared commit is identical on both valid copies;
- a promoted candidate is at or above the authority-required commit and matches
  its root; and
- when two-copy durability is unavailable, no new success acknowledgement is
  observed.

An operation whose response was lost may have committed. The client must retry
the same operation ID to resolve that ambiguity; it must not issue a replacement
ID and then call a duplicate result data loss.

## Required software campaign

Before any GitHub-hosted demonstration is reported, automated tests must cover:

- fresh start and clean restart on each data node;
- crash before append, during a partial append, after append but before sync,
  after local sync, after peer sync, and before/after client response;
- duplicate requests before and after restart;
- operation-ID reuse with different content;
- truncated, corrupt, reordered, and unexpected-version WAL frames;
- one data node unavailable, slow, or returning a durability error;
- candidate lag and same-index state-root mismatch;
- promotion/restart from the last jointly durable acknowledged index; and
- repeated failover/failback with a replayable seed and exact acknowledged set.

Every result must identify the exact commit, validation class, platform,
filesystem, fault point, seed, acknowledgement trace, recovered commits/roots,
and pass/fail oracle. A green unit test alone is not a physical RPO claim.

## Exit boundaries

- **IMPLEMENTED exit:** demo service, WAL/recovery, stable client protocol,
  dual-durable ACK coordinator, and promotion binding are present and reviewed.
- **CI-VERIFIED exit:** the exact commit has a linked successful run of the full
  software campaign with retained summaries/traces.
- **SIMULATED label:** all user-space crashes, partial writes, delays, and
  partitions on a hosted runner keep this label.
- **PHYSICAL-REQUIRED exit:** independent A/B hosts are tested with real power,
  storage, NIC/switch, clock/pause, and selected fence/effect adapters.

Even after these exits, the result is evidence for this named demonstration
workload only and is not a production availability or arbitrary-application
RPO guarantee.

