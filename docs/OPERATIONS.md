# Gate 1A operations guide

## Operational status

This is a fail-closed lab guide, not a production runbook.

| Class | Current repository state |
|---|---|
| **IMPLEMENTED** | Canonical signed-envelope library; local authority store; bounded frame codec; single-process durable witness actor library; core logical EffectGate; in-memory test sink; status/refusal command shells |
| **CI-VERIFIED** | Nothing is asserted here without a linked successful run for the exact commit |
| **SIMULATED** | Deterministic model, injected storage faults, in-process clock/effect fixtures, and future hosted-runner fault analogues |
| **PHYSICAL-REQUIRED** | Independent failure domains, power/NIC/switch faults, real clock bounds, endpoint movement, actual BMC/PDU/storage/eBPF/device fencing and negative tests |
| **NOT-IMPLEMENTED** | Agent/witness daemons, live peer protocol, automatic promotion, config loader, admin/status API, real EffectGate/fence adapters, key-management commands, membership changes, backup/restore tooling, RPO-0 workload |

`quorumarc-agent` always reports `effect_gate=closed` and refuses promotion or
activation. `quorumarc-witness` reports voting disabled and refuses vote or
certificate commands. **Automatic promotion is disabled by default and cannot
be enabled by current configuration.** Do not replace these fail-closed shells
with an ad-hoc orchestration script.

## Illustrative configuration only

The following is an **EXAMPLE TOML SCHEMA** for design review. No current binary
parses it, so saving it does not configure QuorumArc.

```toml
# EXAMPLE ONLY — NOT CONSUMED BY CURRENT BINARIES
schema_version = 1
role = "node"
node_id = "node-a"
workload_id = "demo-counter"
automatic_promotion = false  # must remain false for Gate 1A setup
authority_store = "/var/lib/quorumarc/demo-counter/authority"
max_frame_bytes = 65536
max_lease_ms = 5000

[identity]
key_id = "node-a-2026-01"
private_key = "/etc/quorumarc/keys/node-a-2026-01.key"

[policy]
policy_hash_hex = "REPLACE_WITH_REVIEWED_64_HEX_DIGITS"
threshold = 2
voters = ["node-a", "node-b", "witness-1"]
candidates = ["node-a", "node-b"]

[peers]
node_b = "127.0.0.1:7422"
witness = "127.0.0.1:7423"

[logging]
target = "journald"
level = "info"
```

For an eventual witness configuration, use `role = "witness"`, exclude the
witness from candidates, give it a distinct store/key, and pin the workload,
candidate set, policy hash, and maximum lease. Loopback peers are suitable only
for a three-process hosted lab and prove no host independence. Never use
placeholder hashes or example keys.

Recommended ownership for a future service is root-owned configuration
(`0640`, service group), a service-account-owned local state directory (`0700`),
and a private key readable only by that service account (`0600`). Private keys
must not be stored in Git, logs, traces, backups without encryption, or shared
between roles.

## Illustrative systemd units

Because no daemon exists, the only honest units are one-shot safe-default
checks. The following is an **EXAMPLE**, not installed by the repository:

```ini
# /etc/systemd/system/quorumarc-agent-check.service
# EXAMPLE ONLY — runs the current closed-gate status command and exits.
[Unit]
Description=QuorumArc agent safe-default status check
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/quorumarc-agent status
User=quorumarc
Group=quorumarc
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/quorumarc

[Install]
WantedBy=multi-user.target
```

Create a separate witness check unit with
`ExecStart=/usr/local/bin/quorumarc-witness status` and a distinct
`quorumarc-witness` user/state path. Do not use `Restart=always` around a
one-shot command and do not add `promote`, `activate`, `vote`, or `certify` to
`ExecStart`. A future daemon unit needs its own reviewed sandbox, readiness,
shutdown, watchdog, and state-directory behavior.

## Logs and refusal codes

Current shells write short status/refusal text to stdout/stderr; systemd sends
that to the journal. Example inspection:

```bash
systemctl status quorumarc-agent-check.service
journalctl -u quorumarc-agent-check.service --since today --no-pager
```

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

For the present binaries, start means running a status check; stop means no
QuorumArc process is active. There is no automatic promotion path to operate.
For any future lab integration, enforce this sequence:

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
3. Record node identities, current incarnations/epochs/generations, policy and
   membership hashes, binary/source digest, workload commit/root, and time.
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
of an older but internally valid frame. There is no implemented command that
proves these preconditions, so unattended restore is **NOT-IMPLEMENTED** and a
rollback-ambiguous restore must remain blocked.

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

