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
  controller-supplied logical clock. Source presence is not a successful run;
  exact-head results belong in the Draft PR and workflow artifact.
- **NOT INTEGRATED:** no complete three-role Active/Standby scenario exists.
- **PHYSICAL-ONLY:** the literal hardware assertion requires independent hosts
  or a real fence/effect adapter.

Exact-head repetition counts, malformed-parser results, model counts, and
coverage are taken from the Draft PR's linked artifact. Static source
documentation does not retain an older workflow result as a current
measurement.

This static file does not turn source presence into a global PASS result. The
lifecycle suite emits scenario, seed, validation class, single-writer, and
acknowledged-loss fields for 16 rows; the Draft PR must link an exact successful
workflow before those executions are reported as GitHub-process PASS. Physical
and production enforcement remain separate validation classes.

## Required scenarios

| # | Scenario | Present limited evidence | Evidence status / missing exit condition |
|---:|---|---|---|
| 1 | Normal boot and first Active selection | The model and one-shot lab cover bootstrap; the lifecycle starts both Standbys and command-selects one signed Active | MODEL; THREE-PROCESS LAB; LIFECYCLE PROCESS SOURCE — command-driven selection is not automatic election |
| 2 | Active process `SIGKILL` | The lifecycle kills an effective Active, refuses early promotion, then promotes the Standby after lease plus guard | MODEL; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE — test sink and logical clock only |
| 3 | Graceful Active shutdown | The lifecycle closes and exits the Active, still withholding transfer until safe expiry | WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE — no production planned-switch controller |
| 4 | Standby process shutdown | The lifecycle stops a real Standby and verifies the Active test effect remains singular | MODEL; LIFECYCLE PROCESS SOURCE — continuous RPO-0 writes are not integrated |
| 5 | Witness shutdown | The lifecycle kills the Witness and obtains a signed node refusal with zero effects | MODEL; WITNESS PROCESS SOURCE; LIFECYCLE PROCESS SOURCE |
| 6 | A/B network partition | Compact control-path partitions are explored | MODEL; NOT INTEGRATED — isolate actual A/B replication and control channels without treating disconnect as fencing |
| 7 | Only A can reach Witness | A compact partition analogue exists | MODEL; NOT INTEGRATED — preserve old authority or promote A only after every proof condition succeeds |
| 8 | Only B can reach Witness | Same compact analogue with identities reversed | MODEL; NOT INTEGRATED — same assertion as #7 for B |
| 9 | Complete network partition | Compact partition combinations check the model's writer invariant | MODEL; NOT INTEGRATED — real three-process paths must never emit two effective writers |
| 10 | Message delay, duplication, and reordering | Process tests cover simultaneous duplicate request IDs and a delayed old epoch | WITNESS PROCESS SOURCE; NOT INTEGRATED — add bounded delay/reorder queues across every role and data path |
| 11 | Candidate data lag | A long-running candidate with an empty WAL is denied before Witness authority | COMPONENT SOURCE; MODEL; LIFECYCLE PROCESS SOURCE |
| 12 | Old PromotionProof replay | The active lifecycle node re-evaluates its retained signed envelope against durable accepted authority and refuses replay | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — restart replay remains to be integrated |
| 13 | Old vote replay | A Witness process test sends an older epoch after a newer durable vote | WITNESS PROCESS SOURCE; NOT INTEGRATED — replay a correctly signed obsolete vote through final certification |
| 14 | Simultaneous candidates in one epoch | Concurrent long-running candidates use distinct stores; one Witness vote and one effective test writer result | WITNESS PROCESS SOURCE; THREE-PROCESS LAB; LIFECYCLE PROCESS SOURCE — cloned Witness credentials remain outside scope |
| 15 | Promotion before lease expiry | The lifecycle refuses at 1249 ms and accepts the same next epoch only at its 1250 ms safe bound | MODEL; COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 16 | Clock rollback | A genuinely active lifecycle node emits once, observes rollback, self-fences, and refuses later effects | MODEL; COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 17 | Durable-store failure | A promotion-frame write error poisons the live node store before gate opening | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — other store operations retain component coverage |
| 18 | Partial write and corrupt journal | A partial promotion-frame write poisons and self-fences the lifecycle process before effects | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — arbitrary crash boundaries remain open |
| 19 | Restart with an older epoch | Store/Witness tests preserve highest accepted epoch and refuse stale input after restart | COMPONENT SOURCE; WITNESS PROCESS SOURCE; NOT INTEGRATED — include rolled-back complete-node fixtures and documented trust assumptions |
| 20 | Duplicate workload operation | RPO-0 tests deduplicate operation IDs; exact durable-tail retry returns the same receipt after response loss | COMPONENT SOURCE; NOT INTEGRATED — retry through real failover and prove one application plus an authenticated acknowledgement boundary |
| 21 | State-root mismatch | A valid but different WAL root is refused by the live candidate before activation | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE |
| 22 | Policy-hash mismatch | A data node with a different capsule hash receives a fail-closed lifecycle refusal | COMPONENT SOURCE; LIFECYCLE PROCESS SOURCE — rotation/restart remains open |
| 23 | Witness double-vote attempt | Durable Witness tests refuse a different candidate/proposal for the same workload and epoch | COMPONENT SOURCE; WITNESS PROCESS SOURCE; NOT INTEGRATED — prove the refusal prevents a second certified activation |
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
