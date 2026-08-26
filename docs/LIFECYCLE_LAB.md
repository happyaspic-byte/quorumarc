# Command-driven lifecycle laboratory

## Evidence boundary

The lifecycle laboratory runs Node A, Node B, and an independent Witness as
three long-lived `quorumarc-cluster` processes on one Ubuntu host. Node A and
Node B use the same binary and differ only by identity, keys, paths, and
configuration. It includes a deterministic automatic-failover decision state
machine, but no autonomous scheduling service or production deployment
profile.

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
- every controller request is signed, bound to its target node, and verified
  before logical time or authority state can change;
- an exact retry of the latest signed request returns the cached decision,
  while stale, cross-node, unsigned, tampered, or conflicting-ID requests are
  rejected before command execution;
- expired leases, clock rollback, store poison, proof failure, and effect
  conflict close or keep closed the test effect sink;
- an early promotion attempt is rejected before it can consume a Witness
  epoch; and
- exact proof replay cannot create a second activation.
- separate bounded Node/Witness proxies can inject drop, delay, duplicate,
  reply loss, corruption, and stale signed-request replay without gaining the
  ability to manufacture a valid vote or authority proof.

The lab-only `LifecycleAutoController` consumes fresh signed Node A/B reports.
It requires multiple failed Active probes, waits for the old exclusive lease
and guard, verifies the candidate's pinned durable progress, and requires the
Witness path before emitting a promotion attempt. A missed probe is only
failure suspicion and is never treated as fencing. The candidate still has to
obtain the durable Witness vote and pass the complete proof/EffectGate path.

The integration suite launches real child processes and covers required
scenario IDs 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 21,
22, 24, and 25.
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

All three modes require explicit `--allow-lifecycle-lab`; they bind only to a
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
  --controller-public-key /lab/controller.public \
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

The optional test proxy is configured independently for each node. Its mode
file must be a small regular non-symlink file containing `pass`, `drop`,
`delay-ms=N` (bounded to 1000), `duplicate`, `reply-drop`, `corrupt`, or
`replay-last`.

```text
quorumarc-cluster fault-proxy \
  --listen 127.0.0.1:0 \
  --ready-file /lab/node-a-proxy.ready \
  --upstream 127.0.0.1:WITNESS_PORT \
  --mode-file /lab/node-a-proxy.mode \
  --max-connections 64 \
  --timeout-ms 3000 \
  --allow-lifecycle-lab
```

The public `LifecycleClient` test API signs bounded localhost control commands
with the configured controller key and verifies the signed node response. It
supports status, promotion, tick, effect, close, stop, exact command retry, and
proof replay checks. This API is for deterministic integration tests; it is
not a multi-user management API.

## Crash and fault cases

The suite performs real process `SIGKILL` and `SIGSTOP`/`SIGCONT` operations.
It also injects a failure and a partial write at the authority promotion write
boundary. In either storage case, the store becomes poisoned in that process,
activation is not persisted, and the EffectGate never opens.

The Node/Witness proxy campaign additionally verifies one-sided Witness
reachability, dual Witness isolation, bounded delay, duplicate delivery,
response loss followed by an exact durable retry, corrupted requests, and an
obsolete signed request/response binding. The proxy never sees private keys and
cannot turn a malformed or replayed exchange into authority.

A paused old Active is resumed only after another node has safely obtained a
later epoch. Its first effect request advances the logical clock beyond its old
exclusive lease, so it self-fences before the test sink can record output.

## Important limitations

- A deterministic state machine selects bootstrap and Active-loss promotion
  attempts, but the test harness supplies signed observations, logical time,
  Witness reachability, scheduling, and command execution. There is no
  autonomous daemon, trusted failure detector, planned-switch workflow, or
  production failback controller.
- Control requests are loopback-only and authenticate one pinned controller
  key. There is no RBAC, operator identity, approval workflow, key rotation,
  audit journal, or network-facing TLS service. The bounded replay cache is
  process-local and protects only the latest accepted request; a node restart
  begins a new lab control session. Production management must durably bind a
  session/sequence or use an equivalent anti-replay mechanism.
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
- The proxy currently covers each node's Witness path. There is no continuous
  A/B replication channel to partition or reorder, and no kernel namespace,
  switch, NIC, or client-path isolation claim.
- The fixed capsule accepts only one workload and one expected WAL state. It is
  not a generic application profile.

These limits mean this increment improves process-lifecycle evidence but does
not make QuorumArc production-ready and does not establish product parity with
commercial HA or fault-tolerant systems.
