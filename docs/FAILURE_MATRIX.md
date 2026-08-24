# Failure matrix

## Status vocabulary

- **CURRENT (Gate 0 model):** a compact-model or core-unit-test analogue exists.
  It is not a three-process or physical result.
- **PLANNED (Gate 1A):** the acceptance scenario must be implemented and linked
  to a successful GitHub Actions run before it may be reported as passed.
- **PHYSICAL-ONLY:** GitHub may exercise a software analogue, but the stated
  hardware behavior cannot be substantiated without independent machines and
  the named physical adapter.

At the time this matrix is introduced, the repository's completed claim remains
Gate 0. A row marked CURRENT describes only the limited Gate 0 scope documented
in `SIMULATION.md`. None of the planned Gate 1A process scenarios is declared
passed by this document.

## Required scenarios

| # | Scenario | Present evidence / target assertion | Status |
|---:|---|---|---|
| 1 | Normal boot and first Active selection | Gate 0 can explore promotion; Gate 1A must start three fresh processes, durably elect one generation, and observe one test-sink writer | PLANNED (Gate 1A) |
| 2 | Active process `SIGKILL` | Compact crash action exists; Gate 1A must kill the real process, retain old authority until fence/expiry, restart from durable state, and never overlap writers | CURRENT (Gate 0 model); PLANNED process test |
| 3 | Graceful Active shutdown | Gate 1A must close effects, durably relinquish/expire authority, and transfer without unsafe overlap | PLANNED (Gate 1A) |
| 4 | Standby process shutdown | Compact crash action exists; Gate 1A must show the current writer does not acquire extra authority and RPO-0 writes stop if dual durability is required | CURRENT (Gate 0 model); PLANNED process test |
| 5 | Witness shutdown | Compact witness stop/restart is explored; Gate 1A must prove no new quorum-dependent promotion while unavailable | CURRENT (Gate 0 model); PLANNED process test |
| 6 | A/B network partition | Compact control-path partitions are explored; Gate 1A must isolate the real process channel and avoid treating loss as fencing | CURRENT (Gate 0 model); PLANNED process test |
| 7 | Only A can reach Witness | Compact partition analogue exists; Gate 1A must preserve the old valid authority or safely promote A only with all other proof conditions | CURRENT (Gate 0 model); PLANNED process test |
| 8 | Only B can reach Witness | Same assertion as #7 with identities reversed | CURRENT (Gate 0 model); PLANNED process test |
| 9 | Complete network partition | Compact combinations are explored; Gate 1A must never produce two externally effective test-sink writers | CURRENT (Gate 0 model); PLANNED process test |
| 10 | Message delay, duplication, and reordering | Explicitly absent from Gate 0; Gate 1A fault proxy must verify bounded queues, idempotency, and stale rejection | PLANNED (Gate 1A) |
| 11 | Candidate data lag | Compact lag/catch-up actions and proof validation exist; Gate 1A must reject a candidate below required commit or with the wrong root | CURRENT (Gate 0 model); PLANNED process test |
| 12 | Old PromotionProof replay | Core rejects stale epochs/bindings; Gate 1A must replay canonical signed bytes after a later durable epoch and after restart | CURRENT (core rule); PLANNED wire/store test |
| 13 | Old vote replay | Gate 0 lacks independent durable voter logs; Gate 1A must reject a correctly signed but obsolete vote | PLANNED (Gate 1A) |
| 14 | Simultaneous candidates in one epoch | Gate 0 has one serial metadata view; Gate 1A must race candidates and demonstrate durable witness single-vote behavior | PLANNED (Gate 1A) |
| 15 | Promotion before lease expiry | Compact model requires old gate inactivity/fence; Gate 1A must attempt just before, at, and after conservative expiry boundaries | CURRENT (Gate 0 model); PLANNED process/clock test |
| 16 | Clock rollback | Core trusted-clock rollback self-fences in its logical boundary; Gate 1A must inject rollback and pause observations around activation/effect calls | CURRENT (core rule); PLANNED process test |
| 17 | Durable-store failure | No production durable adapter is claimed by Gate 0; Gate 1A must inject open/write/sync/rename failures and remain closed | PLANNED (Gate 1A) |
| 18 | Partial write and corrupt journal | Gate 1A must truncate, alter, and duplicate framed records at every crash point; ambiguous recovery blocks voting/promotion | PLANNED (Gate 1A) |
| 19 | Restart with an older epoch | Gate 0 models restart/incarnation but trusts a confirmation adapter; Gate 1A must restart from rolled-back fixtures and detect or block them within its documented store assumptions | CURRENT (limited core/model); PLANNED store test |
| 20 | Duplicate workload operation | Stable operation IDs are an invariant direction only; Gate 1A RPO-0 demo must apply a retried operation exactly once across restart | PLANNED (Gate 1A) |
| 21 | State-root mismatch | Core proof validation binds and compares state evidence; Gate 1A must alter one root in signed/durable paths and reject it | CURRENT (core rule); PLANNED integration test |
| 22 | Policy-hash mismatch | Core proof validation binds policy; Gate 1A must test configuration change, stale signature, and restart | CURRENT (core rule); PLANNED integration test |
| 23 | Witness double-vote attempt | Explicitly absent from Gate 0; Gate 1A must persist the first vote before reply and reject a different candidate/digest for the same workload/epoch | PLANNED (Gate 1A) |
| 24 | Process pause then resume | Gate 0 does not model scheduler suspension; Gate 1A must pause beyond the lease, resume, and observe self-fencing before any effect | PLANNED (Gate 1A); physical timing remains PHYSICAL-ONLY |
| 25 | Repeated failover and failback | Gate 0 explores bounded action histories; Gate 1A must run seeded repeated cycles, restart all roles, and retain monotonically increasing authority | CURRENT (bounded compact model); PLANNED process campaign |

## Physical extensions

The following tests may have GitHub software analogues but require the future
physical lab before their literal result can be reported:

| Fault | Required physical evidence | Status |
|---|---|---|
| Pull Active power | Independent desktop loses power; old effects cannot survive; recovery and measured outage are recorded | PHYSICAL-ONLY |
| Disconnect each NIC/cable | Correct control, replication, and service path behavior with real switches and ARP/neighbor caches | PHYSICAL-ONLY |
| Reboot or isolate a switch | Failure-domain and endpoint movement behavior | PHYSICAL-ONLY |
| Redfish/IPMI/PDU fence | Read-back proves the intended machine is off before a competing gate opens | PHYSICAL-ONLY |
| SSD/controller fault | Durable acknowledgement behavior, cache-loss assumptions, corruption detection, and repair | PHYSICAL-ONLY |
| Host suspend/clock disturbance | Conservative lease behavior across actual firmware/OS time sources | PHYSICAL-ONLY |
| VIP/endpoint movement | Client-observed outage, stale ARP/ND, connection behavior, and p50/p95/p99 timing | PHYSICAL-ONLY |

## Result-record requirements

Each automated scenario result must contain the commit, workflow run, scenario
ID, seed, validation class, fault timeline, authority epochs, writer count, and
acknowledged-operation recovery count. A failed trace must be retained as an
artifact. A result without enough data to replay is diagnostic output, not exit
evidence.
