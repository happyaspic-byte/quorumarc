# Gate 1A quick start

## What this proves

The quick check launches the exact `quorumarc-cluster` binary as a candidate,
peer, and Witness on localhost. It performs one two-copy durable demonstration
write, obtains one durable Witness decision, validates the signed promotion
envelope, recovers both authority stores and both WALs, emits one in-memory test
effect, verifies that owner locks were released, and cleans its temporary state.

It is a pre-installation diagnostic for the bounded Gate 1A lab. It does **not**
test automatic failover, physical host independence, a real fence, a production
EffectGate, or an application workload.

## Source build on Ubuntu

The repository pins Rust 1.85.1. On a connected x86-64 Ubuntu preparation host:

```bash
git clone https://github.com/happyaspic-byte/quorumarc.git
cd quorumarc
git checkout gate1a/github-lab
rustup toolchain install 1.85.1 --profile minimal --component rustfmt,clippy
cargo build --locked --release -p quorumarc-cluster
```

Run the one-command diagnostic:

```bash
./target/release/quorumarc-cluster self-test --allow-lab-genesis
```

Success is one line beginning with:

```text
code=SELF_TEST_PASS topology=three-process commit_index=1 value=1 effects=1
```

The command returns zero only after exact durable recovery checks succeed. A
typed refusal is printed to standard error and the exit status is non-zero on
configuration, key, process, protocol, storage, proof, or cleanup failure.

## Retaining diagnostic state

State is deleted after success by default. To inspect the deterministic
test-only fixture, supply a path that does not yet exist:

```bash
./target/release/quorumarc-cluster self-test \
  --allow-lab-genesis \
  --root /var/tmp/quorumarc-inspection-1 \
  --keep-state
```

An existing path is refused instead of reused or overwritten. Retained
directories contain publicly known deterministic test seeds and must never be
converted into operational identities. Remove the directory after inspection.

On a failed self-test, the diagnostic detail identifies the retained state
directory. Preserve it only as bounded lab evidence; it contains no operational
secret unless a user has incorrectly replaced the fixture inputs.

## Release evidence bundle

Extended Safety CI builds the Ubuntu release binaries, executes the copied
`quorumarc-cluster` self-test, produces deterministic file checksums, packs all
five release binaries with the offline documents and protocol specification,
and proves that two packages from the same inputs are byte-identical. A
workflow artifact is reproducibility evidence for its exact commit, not a
signed production release or an installer.

Offline source and toolchain preparation remains documented in
[offline installation](OFFLINE_INSTALL.md). Physical Node A/Node B/Witness
preparation remains in [lab setup](LAB_SETUP.md).
