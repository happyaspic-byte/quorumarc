# Gate 1A operations guide

## Operational status

This is a fail-closed lab guide, not a production runbook.

## Pre-installation lab self-test

The release `quorumarc-cluster` binary provides one bounded diagnostic:

```bash
quorumarc-cluster self-test --allow-lab-genesis
```

It launches localhost candidate, peer, and Witness roles with deterministic
test-only identities, validates one exact durable genesis transaction, and
cleans successful state. `SELF_TEST_PASS` validates packaging and the bounded
lab path only. It does not report cluster readiness, install a daemon, enable
automatic promotion, or test a physical fault domain. Detailed behavior is in
the [quick start](QUICKSTART.md).

| Class | Current repository state |
|---|---|
| **IMPLEMENTED** | Canonical signed-envelope library; local authority store; bounded frame codec; durable Witness actor; long-running localhost Node A/B/Witness lab services; bounded automatic-controller process; core logical EffectGate; in-memory test sink; status/refusal command shells; bounded strict agent configuration subset; fail-closed production TOML parser; closed-gate agent/Witness `daemon` loops; redacted support-bundle export; sandboxed systemd unit templates |
| **CI-VERIFIED** | Nothing is asserted here without a linked successful run for the exact commit |
| **SIMULATED** | Deterministic model, injected storage faults, in-process clock/effect fixtures, and future hosted-runner fault analogues |
| **PHYSICAL-REQUIRED** | Independent failure domains, power/NIC/switch faults, real clock bounds, endpoint movement, actual BMC/PDU/storage/eBPF/device fencing and negative tests |
| **NOT-IMPLEMENTED** | Independent Witness transport, continuous live replication protocol, trusted automatic promotion, general TOML schema migration, privileged admin mutation API, real EffectGate/fence/VIP adapters, key-management commands, membership changes, backup/restore tooling |

`quorumarc-agent` always reports `effect_gate=closed` and refuses promotion or
activation. `quorumarc-witness` reports voting disabled and refuses vote or
certificate commands. **Automatic promotion defaults to disabled.** The agent
accepts `automatic_promotion = true` as configuration input, but that value only
changes its status/refusal context: it does not authorize activation, open the
EffectGate, or make `run` succeed. Do not replace these fail-closed shells with
an ad-hoc orchestration script.

The separate `quorumarc-cluster lifecycle-controller` mode does execute bounded
automatic promotions for the shared-host logical-time laboratory. It requires
explicit lab opt-in and does not change the safe-default production-agent
refusal described above. See [the lifecycle lab](LIFECYCLE_LAB.md).

## Current agent configuration subset

`quorumarc-agent status --config PATH`, `health --config PATH`, and
`run --config PATH` parse a bounded, UTF-8, flat `name = value` file. This is a
purpose-built TOML-like subset, **not a general TOML parser**. It accepts only
the fields shown below:

```toml
# Parsed by quorumarc-agent; this example still grants no authority.
node_id = "node-a"
workload_id = "demo-counter"
role = "data"
store_dir = "/var/lib/quorumarc/demo-counter/authority"
proof_path = "/var/lib/quorumarc/demo-counter/promotion-envelope.bin"
automatic_promotion = false
verification_key = "node-a:node-a-2026-01:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
verification_key = "witness-1:witness-1-2026-01:3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
```

The exact field rules are:

- `node_id` is required exactly once and is a double-quoted canonical ID.
- `workload_id` is required exactly once and is a double-quoted canonical ID.
- `role` is required exactly once; its quoted value is `data` or `witness`.
- `store_dir` is optional and may appear once. It names the directory containing
  the authority journal; a relative path is resolved relative to the
  configuration file's parent directory.
- `proof_path` is optional and may appear once. It names a canonical signed
  promotion-envelope file; a relative path is resolved the same way.
- `automatic_promotion` is optional and may appear once. It is the unquoted
  literal `true` or `false` and defaults to `false`. Even `true` does not enable
  activation in the current agent.
- `verification_key` may be repeated. Each double-quoted value has the exact
  form `principal:key-id:64-hex-public-key`; the first two parts must be
  canonical IDs and the final part must decode to a valid 32-byte Ed25519 public
  key. Each `(principal, key-id)` pair must be unique; even an exact duplicate is
  rejected so file order can never choose a trust anchor. These are verification
  keys only, not private signing keys.

Blank lines and whole-line comments whose first non-space character is `#` are
accepted. Other fields, duplicate singleton fields, tables, arrays, escapes,
embedded quotes, control characters, inline comments, and non-UTF-8 input are
rejected. String values must use double quotes and cannot be empty. The file
must be a regular file no larger than 65,536 bytes.

The public keys above are well-formed test-vector values for parser examples;
never treat their corresponding private material as operational credentials. A
data-role `run` additionally requires `store_dir`, `proof_path`, and sufficient
configured verification keys to inspect their consistency. Passing all of
those checks still ends with `ACTIVATION_CONTROL_PLANE_UNAVAILABLE`, leaves the
EffectGate closed, and exits with a refusal because trusted time, fencing,
lease activation, and enforced EffectGate integration are incomplete. Proposal
and final signed-envelope digests are inspected separately. A `witness` role is
also refused by the node agent's `run` command.

The standalone `quorumarc-witness` refusal shell does not consume this agent
configuration as a production voting-service configuration. Future peer,
policy, lease, logging, private-key, and membership configuration needs a
separately versioned and reviewed schema. Loopback peers remain suitable only
for a hosted process lab and prove no host independence.

Recommended ownership for a future service is root-owned configuration
(`0640`, service group), a service-account-owned local state directory (`0700`),
and a private key readable only by that service account (`0600`). Private keys
must not be stored in Git, logs, traces, backups without encryption, or shared
between roles.

## Fail-closed production daemon templates

Closed-gate `daemon` commands exist. They stay `effect_gate=closed`,
`authority=denied`, drain on `SIGTERM`/`SIGINT`, and never send systemd
`READY=1`. Process liveness is not production activation.

```bash
quorumarc-agent validate-config --config /etc/quorumarc-agent/agent.toml
quorumarc-agent export-support-bundle --config /etc/quorumarc-agent/agent.toml
quorumarc-agent daemon --config /etc/quorumarc-agent/agent.toml --status-socket /run/quorumarc/status.sock
quorumarc-witness daemon --config /etc/quorumarc-witness/witness.toml
```

Production TOML requires exactly two data members and one independent Witness,
unique IDs/addresses/data hosts, local `node_id`/`role`/`listen` binding, and
a Witness endpoint that matches the Witness member. Shared-host Witness and
IPv4-mapped aliases of `172.30.1.84` are refused. Support bundles redact
private-key paths and serialize an unknown management commit as JSON `null`.
Unix status sockets refuse `PROMOTE`/`ACTIVATE`, survive peer close, serve
repeated polls, and unlink only the inode they created.

Unit templates live in `packaging/systemd/`. They use dedicated
`quorumarc` / `quorumarc-witness` users, empty `CapabilityBoundingSet`,
`ProtectSystem=strict`, `Type=simple`, and `NotifyAccess=none`. Do not add
`--allow-*-lab` flags. Do not enable these units as a certified failover
service. Witness state is `/var/lib/quorumarc-witness`, never the data-node
authority directory. Config directories are
`/etc/quorumarc-agent` (`0750 root:quorumarc`) and
`/etc/quorumarc-witness` (`0750 root:quorumarc-witness`).

## Logs and refusal codes

Current shells write short status/refusal text to stdout/stderr; systemd sends
that to the journal. Example inspection:

```bash
systemctl status quorumarc-agent-check.service
journalctl -u quorumarc-agent-check.service --since today --no-pager
quorumarc-agent inspect-store --store /var/lib/quorumarc/agent
quorumarc-witness inspect-store --store /var/lib/quorumarc/witness
```

Store inspection decodes the committed frame read-only and reports the v3
cluster, workload, node, role, store ID, generation, and durable authority
summary. It does not open a writable store, remove
`authority.journal.tmp`, verify global uniqueness, or grant authority.

The runtime libraries expose stable reason-code strings for frame refusals,
witness vote decisions/recovery, and test-effect refusals. A future service
should log time domain, role, workload, message ID, epoch, incarnation, durable
generation, decision code, and trace/seed without logging private keys or raw
secrets. Library reason codes are not currently emitted by the command shells.

Journald retention should be managed with the host's reviewed
`journald.conf`; logrotate does not rotate the journal. If a future wrapper
explicitly writes `/var/log/quorumarc/*.log`, this is an **EXAMPLE LOGROTATE
CONFIGURATION**, not a current application requirement:

```text
# /etc/logrotate.d/quorumarc — EXAMPLE ONLY
/var/log/quorumarc/*.log {
    daily
    rotate 14
    size 20M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su quorumarc adm
}
```

`copytruncate` can lose or duplicate lines and is unsuitable for a durable audit
ledger. A future daemon should reopen logs on signal or use journald. Authority
frames and activation receipts are state, not log files; never rotate them.

## Start, stop, and promotion safety

For the present binaries, start means running a status check, a fail-closed
`run --config PATH` material inspection, or a closed-gate `daemon` loop; stop
means SIGTERM drain with effects remaining closed. `run` always refuses
activation after inspection. The production `daemon` loop does not authorize
promotion. For any future lab integration, enforce this sequence:

1. Begin with `automatic_promotion = false` and every EffectGate closed.
2. Validate unique identities, store directories, keys, policy hash,
   membership, commit/root, and time/fence assumptions out of band.
3. Start the witness and standby first, but do not infer readiness from a fixed
   sleep; require explicit health once implemented.
4. Permit a manual lab activation only after the complete signed proof and
   exact durable authority decision are validated.
5. On uncertainty, storage error, corrupt state, clock rollback, missing key,
   lost witness, or conflicting evidence, keep effects closed and stop.

A stopped process, ping failure, SSH failure, or absent heartbeat is not a
fence. Never manually promote merely because the peer looks down.

## Backup procedure

Backup/restore automation is **NOT-IMPLEMENTED**. The safest currently defined
procedure is an offline evidence copy:

1. Disable any external automation and record that automatic promotion is off.
2. Close the real workload's external effects independently and stop all
   QuorumArc/workload writers for the protected workload.
3. Record cluster/workload/node/role/store IDs, current
   incarnations/epochs/generations, policy and membership hashes,
   binary/source digest, workload commit/root, and time.
   Current shells cannot report these fields; if they cannot be established,
   abort the backup rather than guessing.
4. Copy each role's `authority.journal`, matching workload WAL/checkpoint,
   configuration, membership and public-key status as one immutable labelled
   set. Copy private keys only through an approved encrypted key-backup process.
5. Exclude `authority.journal.tmp`; it is non-authoritative staging.
6. Hash, sign, encrypt as required, transfer to separate storage, and perform a
   closed-gate restore drill before relying on the set.

Do not take independent live copies of authority and workload state and assume
they form a coherent backup.

## Recovery and corrupt state

On recovery error, keep all effects closed, stop the owning role, preserve the
original directory read-only, and capture logs plus filesystem/storage health.
Do not delete `authority.journal`, edit its CRC/fields, copy a peer's store, or
create a fresh directory under the old identity.

Restore is safe only if an operator can establish that no node retains or can
regain a later authority/lease, all old effects are physically or independently
fenced, and the chosen authority snapshot matches the recovered workload
commit/root and key/policy history. The current store cannot detect restoration
of an older but internally valid frame or a perfect clone carrying the same v3
identity/configuration. There is no implemented command that proves these
preconditions, so unattended restore is **NOT-IMPLEMENTED** and a
rollback-ambiguous restore must remain blocked.

Authority journal v3 deliberately refuses v1/v2 frames. There is no in-place
migration command. Keep effects fenced, archive the old frame and matching
workload evidence, and do not relabel or edit its version. Creating a fresh v3
store starts a new authority history and is permitted only in the bounded lab;
it is not an operational recovery procedure.

For laboratory diagnosis, retain both damaged and backup copies, work on a
third copy, and report the event as recovery/repair evidence—not successful
automatic failover.

## Key rotation or compromise

The wire verifier supports principal plus rotation-aware key ID and can reject
retired keys, but provisioning, encrypted storage, revocation distribution,
rotation transactions, and recovery are **NOT-IMPLEMENTED**.

The safe design sequence is: generate a unique replacement key through an
approved mechanism; distribute and verify its public key while the old key is
still accepted; change policy/membership in a separately authorized durable
epoch; verify every voter uses the same key status; then retire the old key.
Never reuse private keys between nodes or restore a retired private key merely
to make an old envelope verify.

For compromise, disable automatic promotion, close/fence effects, revoke the
affected principal/key ID on every verifier, preserve evidence, and require a
new identity/incarnation/policy before lab re-entry. Because no coordinated
revocation service exists, current binaries cannot safely execute this plan.

## Node or disk replacement

Dynamic membership and node replacement are **NOT-IMPLEMENTED**. A replacement
must not boot from a clone of the failed node's authority directory or private
key. The safe future procedure requires:

1. independently fence the old machine and every mapped external effect;
2. disable automatic promotion and block the old identity at network/fence/key
   boundaries;
3. create a new node identity, signing key, empty role-specific directory, and
   strictly new durable incarnation through an authorized membership change;
4. restore/catch up workload data, verify commit/root, and keep effects closed;
5. obtain a new policy hash and quorum approval that names the replacement; and
6. run planned switchover and fault tests before allowing any activation.

Replacing only a disk has the same rollback concern: an empty or old store does
not inherit authority safely. If the prior monotonic epoch/incarnation history
cannot be proven, keep the node ineligible.

## Escalation rule

Availability is subordinate to the safety invariant. Missing witness, ambiguous
store, inconsistent commit/root, unverifiable signature, unknown key, expired
lease, incomplete fence, or operator uncertainty means no promotion and no
external effect. Physical-lab procedures are in [lab setup](LAB_SETUP.md), and
the non-production claim boundary is maintained in
[known limitations](KNOWN_LIMITATIONS.md).
