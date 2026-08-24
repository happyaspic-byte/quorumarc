# Offline Ubuntu build and safe installation

## Status and scope

The Rust libraries and safe-default command shells are **IMPLEMENTED**. The
agent reports status and refuses `promote`/`activate`; the witness reports
status and refuses `vote`/`certify`. Automatic promotion is disabled by
construction. Installing these binaries does not install an HA service.

An offline installer, Debian package, signed release bundle, SBOM/provenance
pipeline, application configuration loader, and long-running daemon are
**NOT-IMPLEMENTED**. No offline procedure is **CI-VERIFIED** by this document.
Host independence, real fencing, storage durability, and I/O-bound effect
enforcement are **PHYSICAL-REQUIRED**.

This repository does not vendor crates or the Rust toolchain. Before an offline
transfer, a connected preparation machine must produce and verify a complete
bundle. Never fetch new dependencies on the isolated target and then describe
the result as an offline or reproducible build.

## Supported preparation match

Use a connected machine with the same Ubuntu release, CPU architecture, and
libc family as the isolated target. The workspace pins Rust 1.85.1 with the
minimal profile plus `rustfmt` and `clippy`. The Cargo workspace declares a
minimum Rust version of 1.85.

The committed `Cargo.lock` must describe every workspace member and all
transitive dependencies before bundling. Check this first:

```bash
cargo +1.85.1 metadata --locked --format-version 1 >/dev/null
```

If Cargo says the lockfile must be updated, stop. A maintainer must resolve and
review the lockfile on a connected review branch; do not bypass `--locked` on
the offline target. At the time this guide was added, the repository had no
committed vendor directory, so the source tree alone was not a complete offline
bundle.

## Connected bundle preparation

The following is an **EXAMPLE** preparation flow, not a release-signing system.
Review destination paths and organizational supply-chain requirements first.

```bash
rustup toolchain install 1.85.1 --profile minimal --component rustfmt,clippy
cargo +1.85.1 metadata --locked --format-version 1 >/dev/null
cargo +1.85.1 test --locked --workspace --all-targets

mkdir -p quorumarc-offline/source/.cargo quorumarc-offline/toolchain
cp -a "$(rustc +1.85.1 --print sysroot)/." quorumarc-offline/toolchain/
cp -a Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml \
  apps crates docs spec LICENSE README.md SECURITY.md quorumarc-offline/source/
(cd quorumarc-offline/source && \
  cargo +1.85.1 vendor --locked vendor > .cargo/config.toml)
(cd quorumarc-offline && \
  find . -type f ! -name SHA256SUMS -print0 | sort -z | \
  xargs -0 sha256sum > SHA256SUMS)
tar --sort=name --owner=0 --group=0 --numeric-owner \
  -czf quorumarc-offline.tar.gz quorumarc-offline
sha256sum quorumarc-offline.tar.gz
```

Keep the generated vendor configuration: it tells Cargo to replace crates.io
with the copied sources. The example checksum manifest detects transfer damage
but is not authenticity. Sign the archive and checksum through the
organization's approved offline release process, and verify that signature
through a separately trusted channel.

If the isolated Ubuntu image lacks compiler/linker prerequisites, prepare its
`.deb` packages and dependencies from the same Ubuntu release and architecture
using an approved repository mirror. Record package versions and repository
signatures. Do not mix distributions or copy an unreviewed package cache. The
Rust toolchain copy is an example convenience for a matched lab; a controlled
offline Rust/package mirror is preferable for maintained environments.

## Offline verification and build

On the isolated host, verify the signed archive first, unpack it into a
non-world-writable staging directory, then verify the checksum manifest. The
following is an **EXAMPLE** build using the bundled toolchain:

```bash
cd /opt/quorumarc-build/quorumarc-offline
sha256sum --check SHA256SUMS

export PATH="$PWD/toolchain/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.85.1
export CARGO_NET_OFFLINE=true
cd source
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo build --locked --offline --release --workspace
cargo test --locked --offline --release --workspace --all-targets
```

If the copied toolchain is invoked without rustup, unset `RUSTUP_TOOLCHAIN` if
it causes rustup selection and ensure `toolchain/bin` is first in `PATH`. Record
`rustc -Vv`, `cargo -V`, Ubuntu release, architecture, source archive digest,
lockfile digest, build command, and test result. A local successful test is not
CI-VERIFIED and is not a production qualification.

Do not use `cargo generate-lockfile`, omit `--locked`, or allow network access
on the isolated build merely to make a failure disappear. A missing vendored
crate, checksum mismatch, toolchain mismatch, or lockfile change is a failed
bundle and should be repaired on the connected preparation side.

## Safe-default binary installation

After verifying the exact built artifacts, this **EXAMPLE** installs only the
two current command shells:

```bash
sudo install -o root -g root -m 0755 \
  target/release/quorumarc-agent /usr/local/bin/quorumarc-agent
sudo install -o root -g root -m 0755 \
  target/release/quorumarc-witness /usr/local/bin/quorumarc-witness

/usr/local/bin/quorumarc-agent status
/usr/local/bin/quorumarc-witness status
```

Expected status output says the EffectGate or voting is disabled. Do not wrap
the refusal commands in scripts that reinterpret exit code 78 as success, and
do not patch the binaries to enable promotion. The TOML and systemd material in
[operations](OPERATIONS.md) is explicitly illustrative because no configuration
parser or daemon consumes it yet.

## Update and rollback

Treat each offline update as a new reviewed, signed bundle. Keep the old binary
for executable rollback, but never roll back an authority store, incarnation,
epoch, membership, policy, key status, or workload commit. Mixed protocol
versions and unattended rolling upgrades are **NOT-IMPLEMENTED**. Stop with all
effects closed, back up the coherent recovery set, verify both nodes and the
witness use the intended artifact, and run only lab validation until a tested
upgrade procedure exists.
