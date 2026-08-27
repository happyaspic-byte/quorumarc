# Known limitations

## Current repository status

The completed safety baseline is Gate 0: in-memory promotion validation, logical
EffectGate transitions, and a deliberately compact single-view model. Gate 1A
adds a substantial **component foundation**—wire, durable store, Witness
runtime, RPO-0 demonstration, process harness, and refusal CLIs—but does not yet
connect those pieces into a production automatic three-role failover system. A
bounded lab composes a peer, Witness, and explicitly enabled bootstrap process
for one lab-genesis activation. A second command-driven lifecycle lab keeps
Node A, Node B, and the Witness alive across multiple authority epochs. A
deterministic state machine and separate bounded process now select and execute
safe-window bootstrap and Active-loss promotion attempts. The controller still
supplies lab logical time and shares the host; it is not a trusted production
failover service.
The release binary can now orchestrate that same bounded transaction through a
one-command self-test. This removes manual fixture assembly only; the separate
lifecycle modes add test authority transfer but no topology independence or
production enforcement.

The command-driven lifecycle lab starts identical long-running data-node
services plus a durable Witness. It exercises Active kill, lease-guarded
promotion, failback, pause/resume, replay, policy/root mismatch, and injected
promotion-store failures against a generation-scoped test sink. The control
command is signed by one pinned lab controller key, supplies logical time, and
initiates each transition. Its anti-replay cache is process-local and covers
the latest request only; it is not a durable multi-operator management plane.
Consequently, trusted production failure detection, externally enforced global
single-writer safety, and end-to-end client-observed RPO-0 remain unimplemented
claims even though the bounded lab now executes automatic promotion.

The localhost process lab runs a real Witness child and exchanges authenticated,
bounded frames. It includes focused kill/restart, conflict, replay, concurrency,
pause/resume, and bounded clean-exit behavior. These are Witness-path analogues,
not Active/Standby scenarios. A separately closed test EffectGate proves those
test paths do not themselves grant authority; it does not prove an integrated
promotion lifecycle.

The agent and witness CLIs are intentionally safe-default inspection and refusal
shells. They report status and health, inspect selected artifacts, and simulate
bounded failure paths, but they do not perform automatic promotion, open an
externally effective writer, provide a production voting endpoint, or execute
physical fencing. Their refusal behavior is part of the present safety boundary,
not a missing-success test to bypass.

The public repository and workflow artifacts are useful reproducibility
evidence, but neither is a certification, formal proof, independent audit, or
production-readiness claim. Lifecycle source tests now cover 24 required
scenario IDs and the one-shot A/B proxy covers the remaining ID in shared-host
validation classes; exact-head GitHub success is tracked in the Draft PR.
Physical enforcement and production end-to-end PASS classes remain incomplete.
Extended Safety computes p50/p95/p99/max and failure rate only for the bounded
logical-time controller path. It separates transport-miss confirmation,
lease-wait, post-lease promotion-readiness, durable promotion, and test-sink
effect timing; client-observed
failover and write-latency distributions do not exist.

## Evidence classification and current measurements

| Class | What currently exists | Limitation |
|---|---|---|
| Exact-head workspace tests | The [Draft PR](https://github.com/happyaspic-byte/quorumarc/pull/2) links the exact commit, run, inventory, and artifact | These are component/process results, not global scenario PASS results |
| Exact-head compact model | The Draft PR links the depth-12 report for its current head | Applies only to that exact model revision and assumptions |
| Exact-head coverage | The Draft PR links the generated coverage report and digest | A workspace percentage does not establish 90% aggregate critical-path compliance |
| GitHub-hosted process | Long-running Node A/B plus Witness, automatic controller/fault proxies, one-shot labs, and a sequential continuous-to-lifecycle bridge binding live commit/root through successor recovery | Shared host; continuous writes stop before lifecycle handoff, and no physical failure-domain or endpoint enforcement exists |
| Physical lab | No completed run | No independent host, fence, switch, VIP, storage, or hardware-clock evidence |

A source count, old workflow number, or green badge must not be substituted for
the exact final commit's successful run and artifact. Static documentation does
not preserve an older run as a current measurement. Coverage targets must be
met by meaningful tests, not lowered or described as passing when they are not.

## Current promotion-integration blocker

The earlier proposal/final-digest cycle is resolved in source. The wire crate
computes a domain-separated digest of the canonical pre-certificate quorum
binding. The Witness persists it before releasing a vote. Authority journal
format v3 stores that proposal digest separately from the digest of the final
signed envelope and binds the local store identity; promotion and activation
recovery compare the appropriate values. Format v1 and v2 are rejected
fail-closed and have no automatic migration.

The lifecycle lab connects those transitions through identical Node A/B
services and the Witness using a fixed logical lease schedule and test
EffectGate. Trusted time, real fencing, continuous replication, production
control, and external enforcement are still absent. The safe-default agent is
not wired to this lab and continues to refuse `run` with
`ACTIVATION_CONTROL_PLANE_UNAVAILABLE`.

## Gate 0 limitations

- The simulator uses one serial metadata view and one trusted logical clock.
- It does not deliver delayed, duplicated, reordered, corrupt, or adversarial
  messages through independent participant inboxes.
- It does not persist actual witness votes or survive crashes in a production
  authority store.
- Persistence confirmation is a trust boundary; a dishonest adapter can violate
  the model's assumptions.
- `EffectGate::check_effect` is a logical user-space check and has a check/use
  race relative to real network, storage, or device I/O.
- Wall-clock values are scaffolding, not a proof of bounded time uncertainty.
- The model does not establish safety under Byzantine or majority compromise.
- Reported state and transition counts apply only to the exact documented depth
  and model revision.

## Gate 1A does not remove every limitation

Even after all GitHub-hosted Gate 1A acceptance tests pass, the following remain:

The current branch has not yet reached that condition: physical fencing,
production-class all-scenario evidence, aggregate critical-path coverage, and
timing distributions remain incomplete. Automatic promotion exists only in the
bounded logical-time lab.

### One-shot genesis scope

The bounded bootstrap is explicitly named `LAB_GENESIS_ONE_SHOT`. A
role-independent OS advisory owner lock prevents local peer/candidate/Witness roles
from claiming the same declared store path. WAL ownership additionally locks the
WAL inode itself so a hard-link alias cannot acquire a second owner. Readiness,
keys, journals, lock sidecars, and WAL paths are also checked for local aliases.
These checks may prevent concurrent honest processes from owning the same local
files and the kernel releases ownership after `SIGKILL`, but they are not
distributed locks.
Copying the trusted directories and
Witness credential to another instance can authorize another logical effect.
This slice must never be reported as global single-writer proof or scenario 1
PASS.

The `self-test` command uses the same scope and publicly known deterministic
test keys. Its `SELF_TEST_PASS` result means the candidate, peer, Witness, WAL,
store, proof, test sink, lock-release, and cleanup checks completed on one host.
It is not an HA health result and must not be used as a service readiness probe.

The execution path separates the Witness private-key file from candidate
public-key inputs and rejects equal role public-key values, but a same-binary,
same-user GitHub fixture is not strong
administrative or hardware-backed key isolation. Production needs a protected
secret provider or separately governed service, provisioning, revocation, and
auditable ownership.

### Shared runner failure domain

Node A, Node B, and Witness share one hosted virtual machine, kernel, clock,
storage stack, and power source. Process isolation and user-space partitions do
not demonstrate physical independence.

### Test EffectGate only

A generation-aware sink can verify authority logic, but cannot prove nftables,
eBPF, storage reservations, VIP movement, serial/USB/PLC blocking, or a BMC/PDU
fence. Each real effect needs enforcement and negative testing at its actual I/O
boundary.

### Bounded crash-store model

File-store tests can cover declared write/sync/rename/truncation fault points.
They cannot prove that arbitrary disks, controllers, filesystems, hypervisors,
or firmware honor flushes, nor defeat an undetectable rollback of every trusted
copy.

Authority frame v3 binds cluster/workload/node/role and a non-zero local
store-instance identity. Lifecycle roles derive that identity from the
provisioned role ID plus the exact progress contract, so a committed journal
cannot reopen under another commit/root pair. A frame opened with any different
expected identity is refused before staging cleanup. This prevents accidental
cross-node, cross-workload, contract-drift, and data-node/Witness journal reuse,
but it is not a global
uniqueness root: a perfect copy of the journal, expected identity/configuration,
and Witness credential creates an authority clone that the first instance
cannot observe. The CRC is damage detection, not malicious-frame
authentication, and the base store has no inter-process lock or compare-and-swap.
Global single-writer safety still needs protected Witness ownership,
hardware-backed or authenticated anti-rollback identity, and real effect
fencing; a local identity or filesystem lock cannot supply those properties.

### Capability and acknowledgement boundaries

Durability receipts and EffectGate persistence confirmations are ordinary Rust
values passed across caller-trusted interfaces, not unforgeable capabilities.
A malicious in-process adapter can fabricate them. The small RPO-0 demo likewise
accepts public replica IDs and receipts; two different names do not prove two
failure domains, and one surviving WAL does not encode whether a two-copy client
acknowledgement occurred. A production design needs authenticated peer commit
evidence, a durable two-copy commit decision, and a gate token that only the
trusted store/effect adapter can create.

### Clock and process suspension

Injected rollback and pause tests validate software response to observations.
They do not prove monotonic-clock bounds, oscillator drift, firmware behavior,
or lease expiry enforcement while a physical host is suspended or partitioned.

### Non-Byzantine quorum

Signatures authenticate messages; they do not make a compromised signer honest.
The design is not Byzantine fault tolerant. A compromised authorized majority,
host kernel, or administrator can violate assumptions or deny service.

### Demonstration RPO-0 scope

Dual-durable acknowledgement for a small WAL-backed demo does not automatically
protect PostgreSQL, arbitrary filesystems, virtual disks, guest memory, external
queues, controllers, or in-flight client sessions. Each workload needs a native
consistency and recovery contract.

### Key lifecycle

Key identifiers, rotation hooks, and retired-key rejection are not a complete
key-management system. Secure provisioning, hardware-backed storage, emergency
revocation, recovery, audit, and closed-network ceremonies require operational
design and testing.

### Availability and performance

Fail-closed decisions intentionally sacrifice availability. GitHub runner
latencies are noisy and do not establish an RTO SLA. A p95 target must never be
met by shortening a safety lease or bypassing fencing. Real client downtime,
ARP/ND convergence, workload recovery, and sustained load require a physical
campaign.

### Scale and membership

The target topology is two data nodes and one witness for one or a small number
of test workloads. Dynamic membership, multi-site latency, large workload sets,
rolling protocol upgrades, mixed versions, and disaster recovery are not yet
production designs.

### Operations and repair

Safe unattended upgrade, rollback, disk replacement, node identity replacement,
backup/restore, disaster recovery, operator approval, and repair of ambiguous
authority state require more implementation and destructive testing.

### Security assurance

Standard cryptographic libraries reduce risk but do not replace protocol review,
fuzzing depth, dependency maintenance, secret scanning, penetration testing, or
an independent security audit. Dependency scans find known issues only.

### Platform support

Gate 1A initially targets a GitHub-hosted Ubuntu environment. Other Linux
distributions, kernels, architectures, Windows, KVM, containers, storage stacks,
NICs, BMCs, PDUs, and switches are unsupported until explicitly tested.

### R8 boundary

R8 remains an optional future data-transport adapter after separate review and
commit pinning. It is not authority, quorum, durable consensus, fencing, or proof
that replicated data is application-consistent. The existing R8 repository is
not modified by Gate 1A.

## Claims that must not be made

Do not describe the current or GitHub-only build as:

- production ready, zero-downtime, fault tolerant, or formally verified;
- proven RPO 0 for arbitrary applications;
- protected from arbitrary partitions without fence/lease assumptions;
- hardware fenced when only a process, mock, SSH command, or user-space flag was
  used;
- physically validated when all roles ran on one hosted runner;
- secure against compromised voters, kernels, administrators, or firmware.

## Path to reducing these limitations

1. Replace controller-supplied logical time and the test EffectGate with trusted
   time, real fence read-back, and an I/O-bound adapter without weakening the
   existing proof and durable-activation ordering.
2. Integrate continuous live RPO-0 client acknowledgement, replication, repair,
   and resynchronization with the automatic lifecycle path.
3. Elevate all shared-host scenarios in `FAILURE_MATRIX.md` to retained
   production-class traces and green exact-head CI evidence.
4. Measure and publish coverage and latency distributions from linked CI runs;
   do not estimate missing values or weaken safety conditions to meet targets.
5. Run the ordinary Ubuntu desktop A/B plus independent Witness lab in
   `LAB_SETUP.md`.
6. Implement and test at least one real fence and one I/O-bound EffectGate
   adapter on supported hardware.
7. Validate a named workload's consistency, recovery, client behavior, upgrade,
   and repair contracts under sustained faults.
8. Obtain independent distributed-systems and security review before expanding
   any product claim.

Limitations are exit criteria, not footnotes. Removing an item requires a linked
implementation, an appropriate validation class, repeatable evidence, and a
reviewed change to this document.
