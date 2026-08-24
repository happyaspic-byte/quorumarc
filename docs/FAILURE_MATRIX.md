# Failure matrix

## How to read this matrix

The status column describes the strongest **current evidence class**. It does
not declare the row passed as an integrated failover scenario.

- **MODEL:** the compact model has an analogue of part of the scenario. The
  historical depth-12 baseline explored 143,439 states and 836,424 transitions
  with 0 model invariant violations. Its serial-view and logical-clock
  assumptions still apply.
- **COMPONENT SOURCE:** a focused core, wire, store, runtime, RPO-0, or CLI test
  is present in the candidate source. Exact current-tree CI is pending.
- **WITNESS PROCESS SOURCE:** a client and real Witness child process exercise a
  localhost TCP analogue. Node A, Node B, activation, and failover are absent.
- **NOT INTEGRATED:** no complete three-role Active/Standby scenario exists.
- **PHYSICAL-ONLY:** the literal hardware assertion requires independent hosts
  or a real fence/effect adapter.

The candidate contains focused component tests, one bounded Witness clean-exit
test, and two deterministic malformed-wire campaigns. Their exact count and
result require a successful workflow for the exact commit. Historical Extended
Safety run #3 measured 69.28% workspace line coverage, below the required 80%
target.

**None of rows 1–25 currently has a global end-to-end PASS result.** Partial
component/model coverage must not be added together and reported as though Node
A failed over to Node B. A row becomes PASS only when one integrated test emits
the required trace and is linked to the exact successful workflow and commit.

## Required scenarios

| # | Scenario | Present limited evidence | Evidence status / missing exit condition |
|---:|---|---|---|
| 1 | Normal boot and first Active selection | The model can explore promotion decisions | MODEL; NOT INTEGRATED — start Node A, Node B, and Witness, durably certify one generation, and observe exactly one test-sink writer |
| 2 | Active process `SIGKILL` | The model includes a crash action; the process lab kills and restarts a **Witness**, preserving its vote | MODEL; WITNESS PROCESS SOURCE; NOT INTEGRATED — kill an actual Active and prove fence/expiry, non-overlap, and recovery |
| 3 | Graceful Active shutdown | A bounded Witness can exit cleanly after an authenticated request | WITNESS PROCESS SOURCE; NOT INTEGRATED — close Active effects, durably relinquish/expire authority, and transfer safely |
| 4 | Standby process shutdown | The model includes a participant crash analogue | MODEL; NOT INTEGRATED — stop a real Standby and prove the writer gains no authority and two-copy writes stop |
| 5 | Witness shutdown | The model stops/restarts the Witness; a process test observes connection refusal and a separately closed test gate | MODEL; WITNESS PROCESS SOURCE; NOT INTEGRATED — prove the integrated cluster cannot form new quorum authority |
| 6 | A/B network partition | Compact control-path partitions are explored | MODEL; NOT INTEGRATED — isolate actual A/B replication and control channels without treating disconnect as fencing |
| 7 | Only A can reach Witness | A compact partition analogue exists | MODEL; NOT INTEGRATED — preserve old authority or promote A only after every proof condition succeeds |
| 8 | Only B can reach Witness | Same compact analogue with identities reversed | MODEL; NOT INTEGRATED — same assertion as #7 for B |
| 9 | Complete network partition | Compact partition combinations check the model's writer invariant | MODEL; NOT INTEGRATED — real three-process paths must never emit two effective writers |
| 10 | Message delay, duplication, and reordering | Process tests cover simultaneous duplicate request IDs and a delayed old epoch | WITNESS PROCESS SOURCE; NOT INTEGRATED — add bounded delay/reorder queues across every role and data path |
| 11 | Candidate data lag | Core proof rules and RPO-0 recovery tests compare commit/root progress | COMPONENT SOURCE; MODEL; NOT INTEGRATED — a lagging real candidate must be denied in the activation transaction |
| 12 | Old PromotionProof replay | Core/wire/store tests reject stale or altered evidence within component boundaries | COMPONENT SOURCE; NOT INTEGRATED — replay final certified bytes after a later durable activation and restart |
| 13 | Old vote replay | A Witness process test sends an older epoch after a newer durable vote | WITNESS PROCESS SOURCE; NOT INTEGRATED — replay a correctly signed obsolete vote through final certification |
| 14 | Simultaneous candidates in one epoch | Concurrent Witness requests record exactly one durable same-epoch grant and retain it after restart | WITNESS PROCESS SOURCE; NOT INTEGRATED — race complete candidates and prove only one can activate |
| 15 | Promotion before lease expiry | The core/model requires old gate inactivity or fence evidence | MODEL; COMPONENT SOURCE; NOT INTEGRATED — test before, at, and after conservative expiry in the real authority path |
| 16 | Clock rollback | Core logic self-fences on observed rollback; CLI simulation remains effect-free | MODEL; COMPONENT SOURCE; NOT INTEGRATED — inject rollback around a genuinely active process and effect calls |
| 17 | Durable-store failure | Fixed-seed store campaigns inject declared write, sync, rename, and directory-sync failures and withhold receipts | COMPONENT SOURCE; NOT INTEGRATED — exercise the same failures inside promotion and activation |
| 18 | Partial write and corrupt journal | Store campaigns truncate frames and alter checksums; recovery fails closed | COMPONENT SOURCE; NOT INTEGRATED — cover every integrated crash boundary and retained trace |
| 19 | Restart with an older epoch | Store/Witness tests preserve highest accepted epoch and refuse stale input after restart | COMPONENT SOURCE; WITNESS PROCESS SOURCE; NOT INTEGRATED — include rolled-back complete-node fixtures and documented trust assumptions |
| 20 | Duplicate workload operation | RPO-0 tests deduplicate stable operation IDs across recovery and reject changed reuse | COMPONENT SOURCE; NOT INTEGRATED — retry through Node A/B failover and prove one application plus acknowledged recovery |
| 21 | State-root mismatch | Core and signed-envelope validation bind state evidence; RPO-0 recovery detects mismatch | COMPONENT SOURCE; NOT INTEGRATED — alter the root across the full signed/durable activation path |
| 22 | Policy-hash mismatch | Core/wire rules bind policy data | COMPONENT SOURCE; NOT INTEGRATED — cover configuration change, stale signature, and restart in the live control plane |
| 23 | Witness double-vote attempt | Durable Witness tests refuse a different candidate/proposal for the same workload and epoch | COMPONENT SOURCE; WITNESS PROCESS SOURCE; NOT INTEGRATED — prove the refusal prevents a second certified activation |
| 24 | Process pause then resume | A Witness child is paused/resumed and returns vote evidence while a separate test gate remains closed | WITNESS PROCESS SOURCE; NOT INTEGRATED; physical timing remains PHYSICAL-ONLY — pause an Active beyond lease and self-fence before effects |
| 25 | Repeated failover and failback | The compact model explores bounded histories | MODEL; NOT INTEGRATED — run seeded repeated real-role cycles with monotonic durable authority and recovered writes |

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
