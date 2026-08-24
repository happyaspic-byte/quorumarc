use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A validated node identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(String);

impl NodeId {
    /// Builds an identifier suitable for policy and proof comparison.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        validate_identifier(value.into()).map(Self)
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for NodeId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A validated protected-workload identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkloadId(String);

impl WorkloadId {
    /// Builds a workload identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        validate_identifier(value.into()).map(Self)
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for WorkloadId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_identifier(value: String) -> Result<String, IdError> {
    if value.is_empty() {
        return Err(IdError::Empty);
    }
    if value.len() > 128 {
        return Err(IdError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdError::InvalidCharacter);
    }
    Ok(value)
}

/// Identifier construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    /// The identifier contained no bytes.
    Empty,
    /// The identifier exceeded the Gate 0 limit.
    TooLong,
    /// The identifier used a character outside the canonical subset.
    InvalidCharacter,
}

impl Display for IdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier is empty"),
            Self::TooLong => formatter.write_str("identifier is longer than 128 bytes"),
            Self::InvalidCharacter => {
                formatter.write_str("identifier contains an invalid character")
            }
        }
    }
}

impl Error for IdError {}

/// Monotonically increasing authority generation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Epoch(pub u64);

/// Durable boot generation used to reject proofs from an earlier process life.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Incarnation(pub u64);

/// Durable workload log position.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitIndex(pub u64);

/// A cryptographic state digest supplied by a future trusted adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StateRoot([u8; 32]);

impl StateRoot {
    /// Constructs a state root without claiming how it was produced.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether the sentinel all-zero root was supplied.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Digest of the complete safety policy and capsule version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PolicyHash([u8; 32]);

impl PolicyHash {
    /// Constructs a policy digest without claiming how it was produced.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
