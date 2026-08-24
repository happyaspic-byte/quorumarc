# Safety model

## Invariants

| ID | Invariant | Enforcement direction |
|---|---|---|
| S1 | At most one externally effective writer per workload | Epoch + fence proof + EffectGate |
| S2 | Every acknowledged RPO-0 write is recoverable | Dual durable ACK or recoverable witness journal |
| S3 | Stale epochs cannot cause side effects | Epoch checked at every effect boundary |
| S4 | Promotion cannot precede fencing | Fence evidence is mandatory in PromotionProof |
| S5 | Missing evidence fails closed | Validator returns a typed refusal; gate remains closed |
| S6 | External operations are not duplicated | Stable operation IDs at cooperative boundaries |
| S7 | A candidate cannot promote behind durable state | Required and candidate commit indexes are compared |

## Failure assumptions

Gate 0 models crash-stop processes, partitions, stale messages, duplicate votes,
expired leases, lagging durable state, invalid health evidence, and incomplete
fencing. Production design must additionally handle process pause, clock jumps,
disk lies, silent corruption, BMC compromise, rollback, dependency failure, and
operator error.

Gate 0 emits an anti-replay persistence record and will not activate until a
trusted adapter confirms that exact record. It does not implement the adapter.
If a caller falsely confirms persistence, rolls storage back, or reuses a boot
incarnation, the core cannot preserve the invariant. The command shells therefore
cannot vote or promote; rollback-resistant epoch/incarnation storage is a Gate 1
prerequisite.

No asynchronous network can provide both immediate failover and split-brain
freedom after an arbitrary partition without a trusted authority boundary.
QuorumArc therefore requires either:

- confirmed hardware/storage fencing; or
- a fail-closed EffectGate whose worst-case lease expiry plus guard time is
  known and has elapsed.

If neither fact can be proved, automatic promotion is refused.

## Time and leases

Wall-clock timestamps in the Gate 0 data types are test scaffolding, not a clock
safety claim. Production leases require a bounded monotonic time source,
conservative uncertainty, pause detection, and guard intervals. If these bounds
cannot be established, hardware fencing is required.

The local gate owns a `TrustedClock` and self-fences if time moves backward. The
trait is an explicit trust boundary, not evidence that an arbitrary clock is
safe. Production must also handle process pause and enforce expiry at the actual
I/O boundary; a userspace `check_effect` result has a check/use race by itself.

Future progress leases renew only after durable useful progress such as WAL
commit/application, never solely because consensus heartbeats are still sent.

## Fence strength

Accepted production classes are expected to include BMC/Redfish or PDU power
control, exclusive storage reservations, independently enforced switch/eBPF
gates, and combinations of these. Graceful shutdown and SSH commands are useful
operational steps but are not authoritative fence evidence.

## RPO labels

`RPO 0` is a policy with measurable prerequisites, not a marketing synonym for
replication. If the witness stores no recoverable data, an acknowledged write
must be durable on both data nodes. During loss of either data node, availability
may be sacrificed rather than silently weakening the RPO contract.
