use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Failure while constructing, encoding, decoding, or verifying an envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// An identifier contained no bytes.
    EmptyIdentifier,
    /// An identifier exceeded the canonical 128-byte limit.
    IdentifierTooLong,
    /// An identifier used a byte outside the canonical ASCII subset.
    InvalidIdentifierCharacter,
    /// A decoded identifier was not valid UTF-8.
    InvalidUtf8,
    /// The wire magic did not identify the expected QuorumArc object.
    InvalidMagic,
    /// Only the exact current protocol version is accepted.
    UnsupportedVersion(u16),
    /// The input ended before the declared field was complete.
    UnexpectedEnd,
    /// Bytes remained after the complete fixed-schema object.
    TrailingBytes(usize),
    /// The encoded object exceeded its defensive size limit.
    SizeLimitExceeded {
        /// Observed byte count.
        actual: usize,
        /// Maximum accepted byte count.
        maximum: usize,
    },
    /// An in-memory length could not be represented by the wire type.
    LengthOverflow,
    /// A fixed boolean field used a tag other than zero or one.
    InvalidBoolean(u8),
    /// An optional field used an unknown tag.
    InvalidOptionTag(u8),
    /// A fence mechanism tag is unknown in this protocol version.
    UnknownFenceMechanism(u8),
    /// The all-zero message ID is reserved and cannot provide replay identity.
    ZeroMessageId,
    /// Epoch zero is reserved for the pre-authority state.
    ZeroEpoch,
    /// Incarnation zero cannot identify a durable process generation.
    ZeroIncarnation,
    /// A digest required as evidence was the all-zero sentinel.
    ZeroDigest(&'static str),
    /// The candidate does not contain the quorum-required durable state.
    CandidateStateBehind,
    /// A lease was empty or ran backwards.
    InvalidLeaseInterval,
    /// The health attestation did not report a usable result.
    InvalidHealthAttestation,
    /// A repeated component was not bound to the outer envelope.
    BindingMismatch(&'static str),
    /// The quorum threshold was zero or larger than the admitted vote set.
    InvalidQuorumThreshold,
    /// A certificate contained more voters than the protocol limit.
    TooManyVotes,
    /// Voter entries were not in strict canonical identifier order.
    NonCanonicalVoterOrder,
    /// A voter identity occurred more than once in a certificate.
    DuplicateVoter,
    /// Bootstrap and non-bootstrap fence target semantics were inconsistent.
    InvalidFenceTarget,
    /// The fence verifier was not represented in the quorum certificate.
    FenceVerifierNotInQuorum,
    /// The signed envelope was not signed by its candidate.
    CandidateSignerMismatch,
    /// No active verification key exists for the named principal and key ID.
    UnknownVerificationKey {
        /// Node or verifier identity.
        principal: String,
        /// Rotation-aware key identifier.
        key_id: String,
    },
    /// An Ed25519 signature failed strict verification.
    InvalidSignature {
        /// Node or verifier identity.
        principal: String,
        /// Rotation-aware key identifier.
        key_id: String,
    },
}

impl Display for EnvelopeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier => formatter.write_str("identifier is empty"),
            Self::IdentifierTooLong => {
                formatter.write_str("identifier is longer than 128 bytes")
            }
            Self::InvalidIdentifierCharacter => {
                formatter.write_str("identifier contains a non-canonical character")
            }
            Self::InvalidUtf8 => formatter.write_str("identifier is not valid UTF-8"),
            Self::InvalidMagic => formatter.write_str("wire object has invalid magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "protocol version {version} is not supported")
            }
            Self::UnexpectedEnd => formatter.write_str("wire object ended unexpectedly"),
            Self::TrailingBytes(count) => {
                write!(formatter, "wire object has {count} trailing bytes")
            }
            Self::SizeLimitExceeded { actual, maximum } => write!(
                formatter,
                "wire object size {actual} exceeds limit {maximum}"
            ),
            Self::LengthOverflow => formatter.write_str("field length cannot be encoded"),
            Self::InvalidBoolean(tag) => write!(formatter, "invalid boolean tag {tag}"),
            Self::InvalidOptionTag(tag) => write!(formatter, "invalid option tag {tag}"),
            Self::UnknownFenceMechanism(tag) => {
                write!(formatter, "unknown fence mechanism tag {tag}")
            }
            Self::ZeroMessageId => formatter.write_str("message ID is the zero sentinel"),
            Self::ZeroEpoch => formatter.write_str("promotion epoch is zero"),
            Self::ZeroIncarnation => formatter.write_str("candidate incarnation is zero"),
            Self::ZeroDigest(field) => write!(formatter, "{field} is the zero digest"),
            Self::CandidateStateBehind => {
                formatter.write_str("candidate durable commit is behind the required commit")
            }
            Self::InvalidLeaseInterval => formatter.write_str("lease interval is invalid"),
            Self::InvalidHealthAttestation => {
                formatter.write_str("health attestation is not healthy or has no passed checks")
            }
            Self::BindingMismatch(field) => {
                write!(formatter, "{field} is not bound to the outer envelope")
            }
            Self::InvalidQuorumThreshold => formatter.write_str("quorum threshold is invalid"),
            Self::TooManyVotes => formatter.write_str("quorum certificate has too many votes"),
            Self::NonCanonicalVoterOrder => {
                formatter.write_str("voters are not in strict canonical order")
            }
            Self::DuplicateVoter => formatter.write_str("quorum certificate repeats a voter"),
            Self::InvalidFenceTarget => formatter.write_str("fence target is invalid"),
            Self::FenceVerifierNotInQuorum => {
                formatter.write_str("fence verifier is absent from the quorum certificate")
            }
            Self::CandidateSignerMismatch => {
                formatter.write_str("envelope signer is not the promotion candidate")
            }
            Self::UnknownVerificationKey { principal, key_id } => write!(
                formatter,
                "verification key {key_id} for principal {principal} is unavailable"
            ),
            Self::InvalidSignature { principal, key_id } => write!(
                formatter,
                "signature by principal {principal} with key {key_id} is invalid"
            ),
        }
    }
}

impl Error for EnvelopeError {}
