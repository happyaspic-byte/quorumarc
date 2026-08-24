//! Deterministic public fixtures used only by the GitHub-hosted lab.

use quorumarc_runtime::{WitnessPolicy, WitnessPolicyError};
use quorumarc_wire::{
    CanonicalId, EnvelopeError, MessageId, PROTOCOL_VERSION, QuorumBinding, SigningKey,
    VerifyingKey,
};

use crate::protocol::PeerKeyResolver;

/// Key identifier for every deterministic lab key.
pub const TEST_KEY_ID: &str = "test-key-1";
/// Fixed lab policy digest. This is not derived from an operational policy.
pub const TEST_POLICY_HASH: [u8; 32] = [5; 32];
/// Fixed lab workload state digest.
pub const TEST_STATE_ROOT: [u8; 32] = [7; 32];

const NODE_A_SEED: [u8; 32] = [11; 32];
const NODE_B_SEED: [u8; 32] = [17; 32];
const WITNESS_SEED: [u8; 32] = [29; 32];

/// Resolver for public deterministic candidate keys used by localhost CI.
///
/// These keys are intentionally embedded and provide no production secrecy.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestPeerKeys;

impl TestPeerKeys {
    /// Returns the deterministic lab signing key for an admitted candidate.
    pub fn candidate_signing_key(candidate: &CanonicalId) -> Option<SigningKey> {
        match candidate.as_str() {
            "node-a" => Some(SigningKey::from_bytes(&NODE_A_SEED)),
            "node-b" => Some(SigningKey::from_bytes(&NODE_B_SEED)),
            _ => None,
        }
    }
}

impl PeerKeyResolver for TestPeerKeys {
    fn resolve_candidate_key(
        &self,
        candidate: &CanonicalId,
        key_id: &CanonicalId,
    ) -> Option<VerifyingKey> {
        if key_id.as_str() != TEST_KEY_ID {
            return None;
        }
        Self::candidate_signing_key(candidate).map(|key| key.verifying_key())
    }
}

/// Builds the narrow deterministic witness policy used by the process lab.
pub fn lab_policy() -> Result<WitnessPolicy, FixtureError> {
    WitnessPolicy::new(
        id("witness")?,
        id(TEST_KEY_ID)?,
        id("orders")?,
        TEST_POLICY_HASH,
        [id("node-a")?, id("node-b")?],
        1_000,
    )
    .map_err(FixtureError::Policy)
}

/// Returns the public deterministic witness signing key used only by CI.
#[must_use]
pub fn lab_witness_signing_key() -> SigningKey {
    SigningKey::from_bytes(&WITNESS_SEED)
}

/// Builds a deterministic binding for one lab candidate and epoch.
pub fn lab_binding(
    candidate: &str,
    epoch: u64,
    message_byte: u8,
) -> Result<QuorumBinding, FixtureError> {
    Ok(QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new([message_byte; 16]),
        workload_id: id("orders")?,
        candidate_node_id: id(candidate)?,
        candidate_incarnation: 7,
        epoch,
        policy_hash: TEST_POLICY_HASH,
        required_commit: 41,
        durable_commit: 41,
        state_root: TEST_STATE_ROOT,
        lease_not_before_ms: 10_000,
        lease_expires_at_ms: 10_500,
    })
}

fn id(value: &str) -> Result<CanonicalId, FixtureError> {
    CanonicalId::new(value).map_err(FixtureError::Identifier)
}

/// Deterministic fixture construction failure.
#[derive(Debug)]
pub enum FixtureError {
    /// A built-in or caller-provided identifier was invalid.
    Identifier(EnvelopeError),
    /// The built-in witness policy was internally inconsistent.
    Policy(WitnessPolicyError),
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identifier(error) => write!(formatter, "invalid lab identifier: {error}"),
            Self::Policy(error) => write!(formatter, "invalid lab witness policy: {error}"),
        }
    }
}

impl std::error::Error for FixtureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identifier(error) => Some(error),
            Self::Policy(error) => Some(error),
        }
    }
}
