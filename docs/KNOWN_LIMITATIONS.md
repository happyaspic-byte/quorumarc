# Known limitations

## Current repository status

The completed baseline is Gate 0. It validates promotion evidence in memory,
models logical EffectGate transitions, and explores a deliberately compact,
single-view state space. Gate 1A adds tested wire, durable-store,
witness-runtime, and demonstration RPO-0 components. A GitHub-hosted test also
runs a Witness child process and exchanges authenticated frames over a real
localhost TCP connection, including a `SIGKILL` and durable restart case. This
is a limited process lab, not a complete three-role failover system.

The agent and witness CLIs are intentionally safe-default inspection and refusal
shells. They report status and health, inspect selected artifacts, and simulate
bounded failure paths, but they do not perform automatic promotion, open an
externally effective writer, provide a production voting endpoint, or execute
physical fencing. Their refusal behavior is part of the present safety boundary,
not a missing-success test to bypass.

The public repository and green workflows are useful reproducibility evidence,
but neither is a certification, formal proof, independent audit, or
production-readiness claim. The full 25-scenario campaign, coverage targets,
and p50/p95/p99 failover and write-latency measurements have not yet been
completed.

## Current promotion-integration blocker

The durable vote is made before a quorum certificate can be assembled, so its
`VoteRecord` binds a pre-certificate `proposal_digest`. The final signed
promotion-envelope digest includes the certificate produced from those votes.
Requiring the vote's proposal digest to equal that final digest creates a cycle:
the final digest depends on vote signatures that would themselves have to sign
that final digest.

The Witness runtime currently avoids pretending this cycle is solved by using a
distinct proposal-binding digest. Full promotion persistence and activation stay
disabled. The protocol and durable schema must first distinguish, bind, and
persist both the pre-certificate proposal digest and the final certified
envelope digest, then verify the relationship during replay and crash recovery.
Until that work is integrated, the safe-default agent refuses `run` activation.

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

The current branch has not yet reached that condition: automatic promotion,
physical fencing, all 25 required scenarios, coverage exit thresholds, and
timing distributions remain incomplete.

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

1. Resolve the proposal/final-digest distinction and complete a restart-safe,
   signed durable-authority transaction without weakening the CLI refusals.
2. Integrate identical Node A/B agents, the Witness, RPO-0 commit evidence, and
   the EffectGate into one automatic-promotion lab path.
3. Complete all three-process scenarios in `FAILURE_MATRIX.md` with replayable
   traces and green CI.
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
