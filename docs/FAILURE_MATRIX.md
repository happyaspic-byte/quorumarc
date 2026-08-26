# Failure matrix

## How to read this matrix

The status column describes the strongest **current evidence class**. It does
not declare the row passed as an integrated failover scenario.

- **MODEL:** the compact model has an analogue of part of the scenario. The
  historical depth-12 baseline explored 143,439 states and 836,424 transitions
  with 0 model invariant violations. Its serial-view and logical-clock
  assumptions still apply.
- **COMPONENT SOURCE:** a focused core, wire, store, runtime, RPO-0, or CLI test
  is present. The [Draft PR](https://github.com/happyaspic-byte/quorumarc/pull/2)
  links the exact-head test inventory, workflow, and artifact.
- **WITNESS PROCESS SOURCE:** a client and real Witness child process exercise a
  localhost TCP analogue. Node A, Node B, activation, and failover are absent.
- **THREE-PROCESS LAB:** one peer, one Witness, and one explicitly enabled
  bootstrap candidate run as separate processes for a fixed one-shot genesis.
  The same exact path is also exposed as a one-command release self-test. The
  Draft PR carries exact-head CI evidence; a green result is still not failover
  evidence.
- **LIFECYCLE PROCESS SOURCE:** identical long-running Node A/B services and a
  durable Witness execute a command-driven, signed, lease-guarded authority
  lifecycle against the test EffectGate. The class uses one shared host and a
  controller-supplied test clock. Source presence is not a successful run;
  exact-head results belong in the Draft PR and workflow artifact.
- **LIFECYCLE FAULT-PROXY SOURCE:** the lifecycle processes communicate with
  the Witness through separate bounded, frame-aware localhost proxies. The
  proxies inject declared drop, delay, duplicate, reply-loss, corruption, and
  stale-request modes without terminating or reconfiguring the Witness.
- **AUTOMATIC EXECUTOR SOURCE:** a separate bounded controller process
  authenticates Node A/B reports, requires repeated failure observations, maps
  local monotonic elapsed time into deterministic buckets, waits for lease plus
  guard, and executes the selected signed promotion against the test EffectGate.
- **NOT INTEGRATED:** no complete three-role Active/Standby scenario exists.
- **PHYSICAL-ONLY:** the literal hardware assertion requires independent hosts
  or a real fence/effect adapter.

Exact-head repetition counts, malformed-parser results, model counts, and
coverage are taken from the Draft PR's linked artifact. Static source
documentation does not retain an older workflow result as a current
measurement.

This static file does not turn source presence into a global PASS result. The
lifecycle suite emits scenario, seed, validation class, single-writer, and
acknowledged-loss fields for 24 rows, while the one-shot proxy emits the A/B
replication-partition row; the Draft PR must link an exact successful
workflow before those executions are reported as GitHub-process PASS. Physical
and production enforcement remain separate validation classes.

## Required scenarios

| # | Scenario | Present limited evidence | Evidence status / missing exit condition |
|---:|---|---|---|
| 1 | Normal boot and first Active selection | The model and one-shot lab cover bootstrap; the separate controller observes both Standbys and automatically executes Node A's signed epoch-1 promotion | MODEL; THREE-PROCESS LAB; LIFECYCLE PROCESS SOURCE; AUTOMATIC EXECUTOR SOURCE — deterministic shared-host bootstrap, not a production election |
| 2 | Active process `SIGKILL` | The controller opens one Node A test effect, observes the killed process through repeated signed probes, waits to the policy-derived Epoch-2 bound (currently logical 2250 ms), and automatically promotes/effects Node B through the durable Witness path | MODEL; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE; AUTOMATIC EXECUTOR SOURCE — monotonic shared-host controller time and test sink only |
| 3 | Graceful Active shutdown | The lifecycle closes and exits the Active, still withholding transfer until safe expiry | WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE — no production planned-switch controller |
| 4 | Standby process shutdown | The lifecycle stops a real Standby and verifies the Active test effect remains singular | MODEL; LIFECYCLE PROCESS SOURCE — continuous RPO-0 writes are not integrated |
| 5 | Witness shutdown | The lifecycle kills the Witness and obtains a signed node refusal with zero effects | MODEL; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE |
| 6 | A/B network partition | A one-shot candidate reaches the Witness but its authenticated A/B replication frame is dropped; no write is acknowledged, no vote is requested, and no effect opens | MODEL; THREE-PROCESS LAB; LIFECYCLE FAULT-PROXY SOURCE — fixed one-operation replication path, not continuous lifecycle traffic |
| 7 | Only A can reach Witness | Separate Node/Witness proxies drop B's path; B is refused and A alone can obtain signed authority and emit one test effect | MODEL; LIFECYCLE FAULT-PROXY SOURCE — shared-host Witness-path analogue, not a physical partition |
| 8 | Only B can reach Witness | Separate Node/Witness proxies drop A's path; A is refused and B alone can obtain signed authority and emit one test effect | MODEL; LIFECYCLE FAULT-PROXY SOURCE — shared-host Witness-path analogue, not a physical partition |
| 9 | Complete network partition | Both Node/Witness proxy paths drop requests and both candidates remain ineffective | MODEL; LIFECYCLE FAULT-PROXY SOURCE — A/B data path is not yet continuous, so this covers Witness isolation only |
| 10 | Message delay, duplication, and reordering | A bounded proxy injects delay, duplicate delivery, reply loss with exact retry, and corruption; all paths either complete idempotently or refuse closed | WITNESS PROCESS SOURCE; LIFECYCLE FAULT-PROXY SOURCE — explicit reordering and continuous data-path queues remain open |
| 11 | Candidate data lag | A long-running candidate with an empty WAL is denied before Witness authority | COMPONENT SOURCE; MODEL; LIFECYCLE PROCESS SOURCE |
| 12 | Old PromotionProof replay | The active lifecycle node re-evaluates its retained signed envelope against durable accepted authority and refuses replay | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — restart replay remains to be integrated |
| 13 | Old vote replay | After A epoch 1 and B epoch 2, A's proxy substitutes its correctly signed obsolete epoch-1 Witness request during an epoch-3 attempt; response binding fails and A self-fences | WITNESS PROCESS SOURCE; LIFECYCLE FAULT-PROXY SOURCE — direct transplantation of a previously issued vote into final certification remains open |
| 14 | Simultaneous candidates in one epoch | Concurrent long-running candidates use distinct stores; one Witness vote and one effective test writer result | WITNESS PROCESS SOURCE; THREE-PROCESS LAB; LIFECYCLE PROCESS SOURCE — cloned Witness credentials remain outside scope |
| 15 | Promotion before lease expiry | The lifecycle refuses one millisecond before the policy-derived Epoch-2 bound and accepts the same next epoch only at that safe bound (currently 2250 ms) | MODEL; COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 16 | Clock rollback | A genuinely active lifecycle node emits once, observes rollback, self-fences, and refuses later effects | MODEL; COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 17 | Durable-store failure | A promotion-frame write error poisons the live node store before gate opening | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — other store operations retain component coverage |
| 18 | Partial write and corrupt journal | A partial promotion-frame write poisons and self-fences the lifecycle process before effects | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — arbitrary crash boundaries remain open |
| 19 | Restart with an older epoch | After A epoch 1 and B epoch 2, A is killed, reacquires its OS-released local locks with a higher incarnation, and self-fences when its older durable vote cannot be reused | COMPONENT SOURCE; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE — complete trusted-copy rollback remains outside this evidence |
| 20 | Duplicate workload operation | A two-copy acknowledged operation is recovered after A loss and B promotion; signed exact retries on B confirm the original commit/root without changing either WAL, while an unknown ID is refused | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — the original write is fixture-preseeded, not accepted through a live lifecycle client |
| 21 | State-root mismatch | A valid but different WAL root is refused by the live candidate before activation | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 22 | Policy-hash mismatch | A data node with a different capsule hash receives a fail-closed lifecycle refusal | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — rotation/restart remains open |
| 23 | Witness double-vote attempt | A is certified in epoch 1; B's different same-epoch request is refused by the durable Witness, B remains Standby, and only A's test effect succeeds | COMPONENT SOURCE; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE — cloned Witness identity/storage remains outside scope |
| 24 | Process pause then resume | A real Active is stopped, a later epoch activates on the peer, and the resumed old process self-fences before effect | WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE; physical timing remains PHYSICAL-ONLY |
| 25 | Repeated failover and failback | Four signed authority epochs alternate A/B with monotonic durable Witness state and one effect per epoch | MODEL; LIFECYCLE PROCESS SOURCE — command-driven bounded cycles, not soak evidence |

## Physical extensions

GitHub software analogues cannot substantiate the literal results below. No
physical result has been produced yet.

| Fault | Required physical evidence | Status |
|---|---|---|
| Pull Active power | Independent data host loses power; old effects cannot survive; recovery and measured outage are recorded | PHYSICAL-ONLY |
| Disconnect each NIC/cable | Real control, replication, and service paths behave safely with switches and ARP/neighbor caches | PHYSICAL-ONLY |
| Reboot or isolate a switch | Failure-domain and endpoint-movement behavior is observed | PHYSICAL-ONLY |
| Redfish/IPMI/PDU fence | Read-back proves the intended host is off before a competing gate opens | PHYSICAL-ONLY |
| SSD/controller fault | Acknowledgement, cache-loss, corruption, and repair assumptions are tested | PHYSICAL-ONLY |
| Host suspend/clock disturbance | Conservative lease behavior is measured across firmware and OS time sources | PHYSICAL-ONLY |
| VIP/endpoint movement | Client outage, stale ARP/ND, connection behavior, and p50/p95/p99 timing are measured | PHYSICAL-ONLY |

## Requirements for a row-level PASS

Each automated result must contain:

- exact commit and successful workflow URL;
- scenario ID, deterministic seed, and validation class;
- participant/process topology and fault timeline;
- authority epoch, incarnation, lease, and proof digests;
- effective-writer count over the entire trace;
- acknowledged-operation recovery and loss counts;
- retained failure trace or bounded success artifact.

For the 25 required rows, a component-only or model-only result may remain as
supporting evidence but cannot satisfy the row. A failed trace without enough
data to replay is diagnostic output, not exit evidence.
