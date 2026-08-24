use ed25519_dalek::{Signature, Signer};
use sha2::{Digest, Sha256};

use crate::codec::{
    encode_fence_statement, encode_outer_signature_statement, encode_vote_statement,
};
use crate::model::{
    CanonicalId, FenceMechanism, FenceReceipt, PromotionEnvelope, QuorumBinding, SignedVote,
};
use crate::EnvelopeError;

const VOTE_SIGNATURE_DOMAIN: &[u8] = b"quorumarc/quorum-vote/ed25519/v1\0";
const FENCE_SIGNATURE_DOMAIN: &[u8] = b"quorumarc/fence-receipt/ed25519/v1\0";
const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"quorumarc/promotion-envelope/ed25519/v1\0";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"quorumarc/promotion-envelope/sha256/v1\0";

/// Resolves active verification keys by principal and rotation-aware key ID.
///
/// Implementations can reject retired keys by returning `None`, allowing key
/// rotation and revocation policy to remain outside the wire parser.
pub trait VerificationKeyResolver {
    /// Returns the currently trusted Ed25519 key for this identity and key ID.
    fn resolve(
        &self,
        principal: &CanonicalId,
        key_id: &CanonicalId,
    ) -> Option<ed25519_dalek::VerifyingKey>;
}

impl SignedVote {
    /// Creates a domain-separated Ed25519 vote over the complete quorum binding.
    pub fn sign(
        binding: &QuorumBinding,
        voter_id: CanonicalId,
        key_id: CanonicalId,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, EnvelopeError> {
        let statement = encode_vote_statement(binding, &voter_id, &key_id)?;
        let signature = signing_key.sign(&domain_preimage(VOTE_SIGNATURE_DOMAIN, &statement));
        Ok(Self {
            voter_id,
            key_id,
            signature: signature.to_bytes(),
        })
    }

    pub(crate) fn verify<R: VerificationKeyResolver>(
        &self,
        binding: &QuorumBinding,
        resolver: &R,
    ) -> Result<(), EnvelopeError> {
        let key = resolve_key(resolver, &self.voter_id, &self.key_id)?;
        let statement = encode_vote_statement(binding, &self.voter_id, &self.key_id)?;
        verify_strict(
            &key,
            &domain_preimage(VOTE_SIGNATURE_DOMAIN, &statement),
            &self.signature,
            &self.voter_id,
            &self.key_id,
        )
    }
}

impl FenceReceipt {
    /// Creates verifier-signed fencing evidence bound to this exact promotion attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        binding: &QuorumBinding,
        target: Option<CanonicalId>,
        verifier_id: CanonicalId,
        key_id: CanonicalId,
        mechanism: FenceMechanism,
        observed_at_ms: u64,
        evidence_digest: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, EnvelopeError> {
        let statement = encode_fence_statement(
            binding,
            target.as_ref(),
            &verifier_id,
            &key_id,
            mechanism,
            observed_at_ms,
            &evidence_digest,
        )?;
        let signature = signing_key.sign(&domain_preimage(FENCE_SIGNATURE_DOMAIN, &statement));
        let receipt = Self {
            target,
            verifier_id,
            key_id,
            mechanism,
            observed_at_ms,
            evidence_digest,
            signature: signature.to_bytes(),
        };
        receipt.validate_structure()?;
        Ok(receipt)
    }

    pub(crate) fn verify<R: VerificationKeyResolver>(
        &self,
        binding: &QuorumBinding,
        resolver: &R,
    ) -> Result<(), EnvelopeError> {
        let key = resolve_key(resolver, &self.verifier_id, &self.key_id)?;
        let statement = encode_fence_statement(
            binding,
            self.target.as_ref(),
            &self.verifier_id,
            &self.key_id,
            self.mechanism,
            self.observed_at_ms,
            &self.evidence_digest,
        )?;
        verify_strict(
            &key,
            &domain_preimage(FENCE_SIGNATURE_DOMAIN, &statement),
            &self.signature,
            &self.verifier_id,
            &self.key_id,
        )
    }
}

/// Candidate-signed outer frame for an immutable canonical promotion envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPromotionEnvelope {
    pub(crate) envelope: PromotionEnvelope,
    pub(crate) signer_id: CanonicalId,
    pub(crate) key_id: CanonicalId,
    pub(crate) signature: [u8; 64],
}

impl SignedPromotionEnvelope {
    /// Signs an already structurally valid envelope as its candidate.
    pub fn sign(
        envelope: PromotionEnvelope,
        key_id: CanonicalId,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, EnvelopeError> {
        envelope.validate()?;
        let signer_id = envelope.candidate_node_id.clone();
        let envelope_bytes = envelope.to_canonical_bytes()?;
        let statement = encode_outer_signature_statement(&envelope_bytes, &signer_id, &key_id)?;
        let signature =
            signing_key.sign(&domain_preimage(ENVELOPE_SIGNATURE_DOMAIN, &statement));
        Ok(Self {
            envelope,
            signer_id,
            key_id,
            signature: signature.to_bytes(),
        })
    }

    pub(crate) fn from_parts(
        envelope: PromotionEnvelope,
        signer_id: CanonicalId,
        key_id: CanonicalId,
        signature: [u8; 64],
    ) -> Self {
        Self {
            envelope,
            signer_id,
            key_id,
            signature,
        }
    }

    /// Unsigned envelope whose signatures still require explicit verification.
    #[must_use]
    pub const fn envelope(&self) -> &PromotionEnvelope {
        &self.envelope
    }

    /// Candidate identity carried by the signature frame.
    #[must_use]
    pub const fn signer_id(&self) -> &CanonicalId {
        &self.signer_id
    }

    /// Rotation-aware candidate key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    /// Raw outer Ed25519 signature bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verifies the candidate, all quorum voters, and fence verifier.
    ///
    /// Decoding alone never calls this method and must not be treated as trust.
    pub fn verify<R: VerificationKeyResolver>(&self, resolver: &R) -> Result<(), EnvelopeError> {
        self.validate_structure()?;
        let candidate_key = resolve_key(resolver, &self.signer_id, &self.key_id)?;
        let envelope_bytes = self.envelope.to_canonical_bytes()?;
        let statement =
            encode_outer_signature_statement(&envelope_bytes, &self.signer_id, &self.key_id)?;
        verify_strict(
            &candidate_key,
            &domain_preimage(ENVELOPE_SIGNATURE_DOMAIN, &statement),
            &self.signature,
            &self.signer_id,
            &self.key_id,
        )?;
        for vote in self.envelope.quorum_certificate.votes() {
            vote.verify(&self.envelope.quorum_certificate.binding, resolver)?;
        }
        self.envelope.fence_receipt.verify(
            &self.envelope.quorum_certificate.binding,
            resolver,
        )
    }

    /// Domain-separated SHA-256 digest used by durable replay and audit stores.
    pub fn digest(&self) -> Result<[u8; 32], EnvelopeError> {
        let bytes = self.to_canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(ENVELOPE_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }

    pub(crate) fn validate_structure(&self) -> Result<(), EnvelopeError> {
        self.envelope.validate()?;
        if self.signer_id != self.envelope.candidate_node_id {
            return Err(EnvelopeError::CandidateSignerMismatch);
        }
        Ok(())
    }
}

fn domain_preimage(domain: &[u8], statement: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(statement.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(statement);
    preimage
}

fn resolve_key<R: VerificationKeyResolver>(
    resolver: &R,
    principal: &CanonicalId,
    key_id: &CanonicalId,
) -> Result<ed25519_dalek::VerifyingKey, EnvelopeError> {
    resolver
        .resolve(principal, key_id)
        .ok_or_else(|| EnvelopeError::UnknownVerificationKey {
            principal: principal.as_str().to_owned(),
            key_id: key_id.as_str().to_owned(),
        })
}

fn verify_strict(
    key: &ed25519_dalek::VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8; 64],
    principal: &CanonicalId,
    key_id: &CanonicalId,
) -> Result<(), EnvelopeError> {
    let signature = Signature::from_bytes(signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| EnvelopeError::InvalidSignature {
            principal: principal.as_str().to_owned(),
            key_id: key_id.as_str().to_owned(),
        })
}
