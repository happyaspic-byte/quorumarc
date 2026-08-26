# Command-driven lifecycle laboratory

## Evidence boundary

The lifecycle laboratory runs Node A, Node B, and an independent Witness as
three long-lived `quorumarc-cluster` processes on one Ubuntu host. Node A and
Node B use the same binary and differ only by identity, keys, paths, and
configuration. It is a safety integration test, not an automatic failover
controller or a production deployment profile.

The following claims are implemented in this laboratory:

- both data nodes recover an identical acknowledged monotonic-counter WAL;
- every process start durably allocates a newer node incarnation;
- the candidate durably records its vote before contacting the Witness;
- the Witness authenticates either candidate and durably prevents a different
  same-epoch vote;
- candidate and Witness signatures bind the complete canonical promotion
  envelope, policy, commit, state root, incarnation, epoch, and lease;
- epoch 1 uses bootstrap authority; later epochs require the old EffectGate
  lease plus an explicit guard interval to have expired;
- the candidate persists promotion and activation before confirming and
  opening its generation-scoped `EffectGate`;
- every node response is signed and bound to the request ID and node identity;
- expired leases, clock rollback, store poison, proof failure, and effect
  conflict close or keep closed the test effect sink;
- an early promotion attempt is rejected before it can consume a Witness
  epoch; and
- exact proof replay cannot create a second activation.

The integration suite launches real child processes and covers required
scenario IDs 1, 2, 3, 4, 5, 11, 12, 14, 15, 16, 17, 18, 21, 22, 24, and 25.
Each passing test emits a deterministic evidence line containing its scenario,
seed, validation class, single-writer violation count, and acknowledged-write
loss count. A successful exact-head workflow is still required before a source
result is reported as GitHub-verified evidence.

## Fixed safety timing

The test uses a deterministic logical time domain:

| Value | Bound |
|---|---:|
| Epoch 1 start | 1000 ms |
| Lease duration | 200 ms |
| Post-lease guard | 50 ms |
| Next epoch stride | 250 ms |

Epoch 2 therefore cannot activate before 1250 ms. This logical schedule makes
the test reproducible and checks proof/gate ordering. It does not establish
clock bounds across hosts and it is not a measured 250 ms failover claim.

Lease renewal is deliberately absent. Heartbeats cannot extend authority. A
new authority epoch requires another durable Witness vote and the exact
replication progress expected by the capsule.

## Service modes

Both modes require explicit `--allow-lifecycle-lab`; they bind only to a
loopback address and use bounded frames, connections, and I/O deadlines.

```text
quorumarc-cluster lifecycle-witness \
  --listen 127.0.0.1:0 \
  --ready-file /lab/witness.ready \
  --store /lab/witness-store \
  --signing-key /lab/witness.seed \
  --node-a-public-key /lab/node-a.public \
  --node-b-public-key /lab/node-b.public \
  --max-connections 64 \
  --timeout-ms 3000 \
  --allow-lifecycle-lab
```

```text
quorumarc-cluster lifecycle-node \
  --node node-a \
  --listen 127.0.0.1:0 \
  --ready-file /lab/node-a.ready \
  --wal /lab/node-a.wal \
  --store /lab/node-a-store \
  --signing-key /lab/node-a.seed \
  --witness-public-key /lab/witness.public \
  --witness 127.0.0.1:WITNESS_PORT \
  --max-connections 64 \
  --timeout-ms 3000 \
  --policy-byte 165 \
  --store-fault none \
  --allow-lifecycle-lab
```

Node B uses the same command with `--node node-b` and its own WAL, authority
store, private key, and readiness file. Private key files must be exact mode
`0600`. All role keys must have distinct values, and stores, WALs, keys, owner
locks, and readiness paths must not alias.

The public `LifecycleClient` test API sends bounded localhost control commands
and verifies the signed node response. It supports status, promotion, tick,
effect, close, stop, and replay checks. This API is for deterministic
integration tests; it is not a management API.

## Crash and fault cases

The suite performs real process `SIGKILL` and `SIGSTOP`/`SIGCONT` operations.
It also injects a failure and a partial write at the authority promotion write
boundary. In either storage case, the store becomes poisoned in that process,
activation is not persisted, and the EffectGate never opens.

A paused old Active is resumed only after another node has safely obtained a
later epoch. Its first effect request advances the logical clock beyond its old
exclusive lease, so it self-fences before the test sink can record output.

## Important limitations

- Promotion is initiated by a test control command. There is no automatic
  failure detector, election scheduler, retry loop, planned-switch workflow,
  or production failback controller.
- Control requests are loopback-only but are not authenticated. They can ask a
  node to attempt or close authority; they cannot bypass candidate/Witness
  signatures, durable state, proof validation, or EffectGate checks. A future
  management plane must authenticate and authorize every command.
- The test clock is supplied by the controller. It is not a trusted,
  pause-aware cross-host clock.
- EffectGate expiry is enforced for calls through the in-process test sink.
  The old process cannot generate autonomous external I/O in this lab. A
  kernel or device-enforced adapter is required before using expiry as a real
  fence.
- The WAL is pre-seeded through the RPO-0 component before services start.
  Continuous replication, durable client acknowledgement through failover,
  repair, snapshot, and resynchronization are not yet integrated.
- All processes share one kernel, storage host, clock source, hypervisor, and
  power domain on a GitHub runner.
- The fixed capsule accepts only one workload and one expected WAL state. It is
  not a generic application profile.

These limits mean this increment improves process-lifecycle evidence but does
not make QuorumArc production-ready and does not establish product parity with
commercial HA or fault-tolerant systems.
