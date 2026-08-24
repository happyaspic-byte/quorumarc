# Gate 1A wire protocol

## Claim vocabulary

This document uses the following labels literally:

- **IMPLEMENTED** means code exists in this repository.
- **CI-VERIFIED** means a successful CI run for the exact commit is linked. No
  such run is linked from this document, so nothing below is marked
  CI-VERIFIED.
- **SIMULATED** means a deterministic in-process test double or fault injector
  is involved. It is not physical evidence.
- **PHYSICAL-REQUIRED** means independent hosts or a real I/O/fence adapter are
  needed before the stated behavior can be claimed.
- **NOT-IMPLEMENTED** means the capability is absent, even if a format or
  interface for it exists.

The canonical envelope and signature code is **IMPLEMENTED** in
`quorumarc-wire`. Bounded stream framing and a single-process witness vote actor
are **IMPLEMENTED** in `quorumarc-runtime`. A network listener, peer handshake,
request/response message set, transport authentication, three-process agent
protocol, and automatic promotion service are **NOT-IMPLEMENTED**. Network and
hardware failure claims remain **PHYSICAL-REQUIRED** where identified in
[the failure matrix](FAILURE_MATRIX.md).

## Canonical scalar encoding

Promotion-envelope protocol version 1 is a fixed schema. It is not CBOR, JSON,
TOML, protobuf, or Rust's memory representation.

| Type | Canonical encoding |
|---|---|
| `u8`, tag | One byte |
| `u16`, `u32`, `u64` | Unsigned, big-endian, fixed width |
| Boolean | One byte: `0` or `1`; every other value is refused |
| Digest | Exactly 32 opaque bytes |
| Message ID | Exactly 16 bytes; all zero is refused |
| Signature | Exactly 64 Ed25519 signature bytes |
| Identifier | `u16` byte length followed by ASCII bytes |
| Optional identifier | `u8` tag (`0` absent, `1` present), then an identifier when present |

Identifiers contain 1 through 128 bytes and only ASCII letters, digits, `-`,
`_`, or `.`. Protocol version, epoch, candidate incarnation, required digests,
and message ID are validated; zero sentinels are rejected where the model
reserves them. Decoders refuse truncation, invalid tags, unsupported versions,
non-canonical voter order, and all trailing bytes. Unknown fields are not
ignored.

The unsigned envelope is limited to 49,152 bytes. The signed outer frame is
limited to 65,536 bytes. A certificate carries at most 64 votes. These are
defensive parsing limits, not throughput or denial-of-service guarantees.

## Unsigned promotion envelope

`PromotionEnvelope::to_canonical_bytes` emits the following fields in this
exact order:

1. magic: the eight bytes `QARCENV\0`;
2. protocol version (`u16`, currently exactly `1`);
3. message ID (16 bytes);
4. workload identifier;
5. candidate node identifier;
6. candidate durable incarnation (`u64`);
7. authority epoch (`u64`);
8. policy hash (32 bytes);
9. quorum certificate;
10. signed fence receipt;
11. required commit (`u64`);
12. candidate durable commit (`u64`);
13. state root (32 bytes);
14. health attestation; and
15. lease grant.

The quorum certificate contains, in order, the complete quorum binding,
threshold (`u16`), vote count (`u16`), and votes. Each vote contains voter ID,
key ID, and signature. Voters must be unique and sorted by identifier in
strictly increasing byte order. The threshold must be non-zero and no greater
than the number of votes.

The quorum binding repeats and signs the protocol version, message ID,
workload, candidate, incarnation, epoch, policy hash, required commit, durable
commit, state root, lease start, and lease expiry. Every repeated value must
equal the outer envelope.

The fence receipt contains optional old-authority target, verifier ID, key ID,
mechanism tag, observation time, evidence digest, and signature. Mechanism tags
are `0` bootstrap, `1` hardware power, `2` storage reservation, and `3` expired
EffectGate. Bootstrap requires no target; every other mechanism requires a
target. The verifier must also appear among the certificate voters. A mechanism
tag expresses what the signed evidence says; the codec does not operate or
independently validate hardware.

The health attestation contains node ID, incarnation, epoch, healthy boolean,
passed-check count, observation time, and digest. The node/incarnation/epoch
must match the candidate; `healthy` must be true and at least one check must
have passed. The lease contains holder, incarnation, epoch, inclusive start,
and exclusive expiry, and must bind the same candidate. The durable commit
cannot be below the required commit.

## Candidate-signed frame

`SignedPromotionEnvelope::to_canonical_bytes` emits:

1. magic: the eight bytes `QARCSIG\0`;
2. outer protocol version (`u16`, exactly `1`);
3. unsigned-envelope byte length (`u32`);
4. the complete canonical unsigned envelope;
5. candidate signer ID;
6. candidate key ID; and
7. candidate Ed25519 signature (64 bytes).

The signer ID must equal the candidate ID. Decoding proves only that the bytes
are structurally canonical. A caller must separately invoke signature
verification with an active-key resolver and must then apply the local safety
policy and durable anti-replay rules. Treating successful decoding as
authentication is an error.

`verify` strictly verifies the outer candidate signature, every vote, and the
fence signature. The key resolver may reject an unknown or retired
principal/key-ID pair. The wire crate validates structural threshold and
binding rules, but it does not decide whether a voter set is the deployment's
authorized membership; that policy decision remains outside this codec.

## Signature and digest domains

The implementation prepends these NUL-terminated domain strings before
Ed25519 signing:

| Object | Domain | Statement |
|---|---|---|
| Vote | `quorumarc/quorum-vote/ed25519/v1\0` | Canonical quorum binding, voter ID, key ID |
| Fence | `quorumarc/fence-receipt/ed25519/v1\0` | Binding, target, verifier/key IDs, mechanism, observation, evidence digest |
| Outer envelope | `quorumarc/promotion-envelope/ed25519/v1\0` | `u32` envelope length, canonical envelope, signer ID, key ID |

The durable/audit envelope digest is SHA-256 over
`quorumarc/promotion-envelope/sha256/v1\0` followed by the complete canonical
signed frame. The witness actor uses a separate
`quorumarc/witness-binding/sha256/v1\0` domain for its durable vote record.
Changing an identifier, key ID, state root, lease bound, message ID, or other
bound field changes the signed statement.

## Stream frame

`FrameCodec` is **IMPLEMENTED** as a generic blocking stream primitive: a
four-byte big-endian payload length followed by that many bytes. Frames must be
non-empty. The configured maximum must be non-zero and no larger than the hard
limit of 1,048,576 bytes. A clean EOF before the first header byte is normal;
EOF after any header or payload byte is a typed truncation refusal.

This frame does not identify message type and authenticates nothing. Callers
must set a maximum appropriate to the expected payload (65,536 bytes is enough
for a signed promotion envelope), apply timeouts and connection limits, decode
the payload, verify signatures, authorize identities, and durably reject
replays. Those connection and service controls are **NOT-IMPLEMENTED**.

## Interoperability rule

The Rust encoder is the canonical reference for version 1. Another
implementation is interoperable only if it produces byte-for-byte identical
objects and refuses the same non-canonical forms. Any schema extension requires
a new explicitly supported protocol version; appending fields to version 1 is
invalid. No rolling mixed-version protocol or compatibility negotiation is
implemented.

