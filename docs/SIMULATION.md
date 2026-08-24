# Simulation scope

`quorumarc-sim` is a deterministic, exhaustive explorer for a deliberately small
two-node-plus-witness model. Promotion paths call the real `quorumarc-core`
validator and execute `stage → persistence confirmation → activate → effect
check`; they are not a second permissive implementation of proof validation.

## Explored now

- A/B control-path partitions and healing;
- witness stop/restart;
- node crash/restart with a new durable boot incarnation;
- authoritative hardware fencing;
- candidate durable-state lag and catch-up;
- old lease expiry plus guard interval;
- promotion attempts at every reachable compact state;
- the invariant `active_writers <= 1`.

## Not yet explored

- independent, concurrent metadata views at A, B, and witness;
- delayed, duplicated, reordered, or corrupted protocol messages;
- witness double-vote and crash between vote persistence and reply;
- clock uncertainty, skew, stall, suspend, and bounded-drift violations;
- disk acknowledgement lies, torn writes, rollback, and silent corruption;
- actual eBPF, storage reservation, Redfish/PDU, VIP, or workload adapters;
- arbitrary thread scheduling inside the production daemon.

The current report may only be described as **compact single-view model safe for
the explored depth**. It is not a production split-brain proof and does not count
toward the one-million-history exit target yet.

The next simulator revision will give every participant an inbox, durable local
log, independent clock model, and crash points around every persistence boundary.
It will retain seed/history replay and add TLA+ trace comparison, concurrency
schedule checking, and hardware-in-the-loop fault campaigns.
