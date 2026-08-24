# Gate 1A durability model

## Status and claim boundary

The labels **IMPLEMENTED**, **CI-VERIFIED**, **SIMULATED**,
**PHYSICAL-REQUIRED**, and **NOT-IMPLEMENTED** have the meanings defined in
[the wire protocol](WIRE_PROTOCOL.md). No successful CI run is linked from this
document.

`quorumarc-store` is an **IMPLEMENTED** local authority snapshot store. Its
fault-injecting backend and test fixtures are **SIMULATED** crash-boundary
evidence when executed. The store is not consensus, replicated storage,
rollback-proof storage, a workload WAL, a hardware fence, or a production
database. Those capabilities are **NOT-IMPLEMENTED** here. Claims about disks,
controllers, firmware, power loss, or independent hosts are
**PHYSICAL-REQUIRED**.

## Stored authority state

One committed snapshot contains:

- the highest accepted or voted epoch;
- the durable process incarnation;
- the last vote (epoch, candidate, proposal digest);
- the last promotion (epoch, proposal digest, final signed-envelope digest,
  lease, commit, state root);
- current durable workload commit and state root; and
- the last activation receipt (epoch, holder, incarnation, promotion digest,
  activation time, expiry).

Transitions reject stale incarnations and epochs, same-epoch double votes,
promotions without a matching durable vote/proposal digest, commit regression,
a changed root at the same commit, and activation that does not exactly match
the current vote, promotion, incarnation, final signed-envelope digest, and
lease. Exact retries are idempotent and return the existing durable generation.

This is bounded anti-replay state, not a history. Despite the filename
`authority.journal`, the implementation replaces one complete snapshot; it
does not append a sequence of records.

## Files and commit sequence

For a store directory `D`, the authoritative path is
`D/authority.journal`; `D/authority.journal.tmp` is staging only. A transition:

1. validates a complete next state and increments the frame generation;
2. removes a stale staging file;
3. writes the complete new frame to the staging path;
4. calls file `sync_all` on the staging file;
5. atomically renames staging over the committed path; and
6. calls `sync_all` on the parent directory on Unix.

Only after that sequence returns success does the store issue a
`DurabilityReceipt`. If directory synchronization reports `Unsupported`, the
generic store continues; other directory-sync failures are treated as unknown
durability and poison the open store. An Ubuntu deployment must validate the
selected filesystem and mount stack rather than assuming that every storage
layer honors these calls.

Any write-path error poisons that in-process store instance. It will refuse
further writes until reopened. A failure before rename should leave the prior
committed snapshot authoritative. A failure after rename but before confirmed
directory synchronization is deliberately ambiguous to the caller: no receipt
is issued, and reopening accepts the complete snapshot currently visible.
Therefore a caller must retry the same logical operation after recovery and
must not infer failure from the absence of an acknowledgement.

## Frame and recovery rules

The internal store frame is version 2, little-endian, and limited to 1 MiB. It
contains magic `QARCJNL1`, format version, zero reserved header field,
generation, payload length, payload, IEEE CRC-32, and trailer `QARCEND1`.
CRC-32 detects accidental damage; it is not authentication and does not resist
malicious replacement.

Format v2 adds separate proposal and final signed-envelope digests to promotion
state. A v1 frame or any other unsupported version is rejected fail-closed;
there is no automatic migration. Operators must not edit a v1 frame or change
its version field. A future migration tool needs a separately reviewed,
closed-gate procedure and coherent proof/workload evidence.

Open reads only `authority.journal`, validates the whole frame and state
invariants, then removes any staging file. Bad magic/version/reserved fields,
truncation, oversized or mismatched length, checksum/trailer damage,
non-canonical fields, invalid identifiers, generation zero, or inconsistent
state refuses recovery. A staging file can never grant authority.

A missing committed file creates a fresh empty state. Consequently an operator
must never point an existing identity at an accidentally empty directory: doing
so is not recovery; it discards anti-replay knowledge.

## Crash model and trust assumptions

The implementation assumes:

- one serialized writer owns a store directory; there is no inter-process file
  lock, compare-and-swap, or protection against opening the same directory
  twice;
- rename is atomic on the selected local filesystem;
- successful file and directory synchronization reports the real durability
  boundary of the complete storage stack;
- the committed directory is not silently rolled back, cloned, restored from
  an old backup, or replaced by an attacker; and
- the filesystem returns bytes or errors rather than fabricating successful
  persistence.

The deterministic backend can inject create/read/write/sync/rename/directory
sync/remove errors and partial writes. Test source covers restart recovery,
idempotent voting, double-vote/stale-epoch refusal, corrupt and truncated
frames, partial writes, write/sync/rename failures, directory-sync ambiguity,
promotion/vote binding, and progress regression. These are not
**CI-VERIFIED** until a successful run for the exact commit is linked.

The model cannot establish behavior for volatile device caches, RAID or SAN
controllers, hypervisor snapshots, filesystem bugs, torn sectors outside the
declared fault points, hostile rollback, bit rot after validation, concurrent
writers, or physical power loss. Those require both additional design and, for
literal hardware claims, **PHYSICAL-REQUIRED** tests.

## Safe handling rules

- Give each role and workload its own directory on one local filesystem; never
  share it through NFS or copy a live directory to another node identity.
- Restrict the directory and signing keys to the service account. The authority
  frame is sensitive integrity state even though it contains no private key.
- Stop the owning process and close/fence effects before copying or restoring.
- Back up `authority.journal`, configuration/policy, membership, public-key
  metadata, and the matching workload state as one labelled recovery set.
- Never restore authority state alone or workload state alone. Verify that the
  workload commit/root agrees with the authority snapshot before any activation.
- Preserve a damaged frame and logs for diagnosis. Do not edit bytes, delete the
  frame, or manufacture a higher epoch to make recovery succeed.
- Treat any older valid backup as rollback. Current code has no trusted remote
  generation ledger or hardware monotonic counter to prove it safe.

Detailed operator procedures and their current limitations are in
[operations](OPERATIONS.md).
