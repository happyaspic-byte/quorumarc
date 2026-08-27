//! Deterministic, fail-closed promotion-envelope wire primitives.
//!
//! The codec uses a fixed-schema, big-endian format rather than a permissive
//! self-describing serializer. Decoders accept exactly protocol version 1,
//! enforce defensive size bounds, reject non-canonical voter ordering, and
//! reject every trailing byte. Decoding is deliberately separate from
//! [`SignedPromotionEnvelope::verify`].
//!
//! Ed25519 signatures cover the candidate envelope, each quorum vote, and the
//! fence receipt under three distinct domain separators. The replay-relevant
//! [`MessageId`] is included in voter and fence statements as well as the outer
//! candidate signature.

#![forbid(unsafe_code)]

mod codec;
mod crypto;
mod error;
mod model;

pub use codec::{MAX_ENVELOPE_SIZE, MAX_SIGNED_ENVELOPE_SIZE};
pub use crypto::{SignedPromotionEnvelope, VerificationKeyResolver};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::EnvelopeError;
pub use model::{
    CanonicalId, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant, MAX_VOTES, MessageId,
    PROTOCOL_VERSION, ProductionQuorumCertificate, ProductionSignedVote, PromotionEnvelope,
    QuorumBinding, QuorumCertificate, SignedVote,
};

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_SEED: [u8; 32] = [11; 32];
    const WITNESS_SEED: [u8; 32] = [29; 32];

    struct TestResolver {
        candidate: bool,
        witness: bool,
    }

    impl TestResolver {
        const fn all() -> Self {
            Self {
                candidate: true,
                witness: true,
            }
        }
    }

    impl VerificationKeyResolver for TestResolver {
        fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
            if key_id.as_str() != "key-1" {
                return None;
            }
            match principal.as_str() {
                "node-a" if self.candidate => {
                    Some(SigningKey::from_bytes(&CANDIDATE_SEED).verifying_key())
                }
                "witness" if self.witness => {
                    Some(SigningKey::from_bytes(&WITNESS_SEED).verifying_key())
                }
                _ => None,
            }
        }
    }

    fn id(value: &str) -> CanonicalId {
        let Ok(identifier) = CanonicalId::new(value) else {
            std::process::abort();
        };
        identifier
    }

    fn result_or_abort<T>(result: Result<T, EnvelopeError>) -> T {
        let Ok(value) = result else {
            std::process::abort();
        };
        value
    }

    fn binding() -> QuorumBinding {
        QuorumBinding {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new([3; 16]),
            workload_id: id("orders"),
            candidate_node_id: id("node-a"),
            candidate_incarnation: 7,
            epoch: 19,
            policy_hash: [5; 32],
            required_commit: 41,
            durable_commit: 41,
            state_root: [7; 32],
            lease_not_before_ms: 10_000,
            lease_expires_at_ms: 11_000,
        }
    }

    fn envelope() -> PromotionEnvelope {
        let binding = binding();
        let candidate_key = SigningKey::from_bytes(&CANDIDATE_SEED);
        let witness_key = SigningKey::from_bytes(&WITNESS_SEED);
        let candidate_vote = result_or_abort(SignedVote::sign(
            &binding,
            id("node-a"),
            id("key-1"),
            &candidate_key,
        ));
        let witness_vote = result_or_abort(SignedVote::sign(
            &binding,
            id("witness"),
            id("key-1"),
            &witness_key,
        ));
        let certificate = result_or_abort(QuorumCertificate::new(
            binding.clone(),
            2,
            vec![candidate_vote, witness_vote],
        ));
        let fence_receipt = result_or_abort(FenceReceipt::sign(
            &binding,
            None,
            id("witness"),
            id("key-1"),
            FenceMechanism::Bootstrap,
            9_995,
            [13; 32],
            &witness_key,
        ));
        PromotionEnvelope {
            protocol_version: PROTOCOL_VERSION,
            message_id: binding.message_id,
            workload_id: binding.workload_id.clone(),
            candidate_node_id: binding.candidate_node_id.clone(),
            candidate_incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            policy_hash: binding.policy_hash,
            quorum_certificate: certificate,
            fence_receipt,
            required_commit: binding.required_commit,
            durable_commit: binding.durable_commit,
            state_root: binding.state_root,
            health_attestation: HealthAttestation {
                node_id: binding.candidate_node_id.clone(),
                incarnation: binding.candidate_incarnation,
                epoch: binding.epoch,
                healthy: true,
                passed_checks: 3,
                observed_at_ms: 9_997,
                attestation_digest: [17; 32],
            },
            lease: LeaseGrant {
                holder_node_id: binding.candidate_node_id,
                incarnation: binding.candidate_incarnation,
                epoch: binding.epoch,
                not_before_ms: binding.lease_not_before_ms,
                expires_at_ms: binding.lease_expires_at_ms,
            },
        }
    }

    fn signed_envelope() -> SignedPromotionEnvelope {
        result_or_abort(SignedPromotionEnvelope::sign(
            envelope(),
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ))
    }

    #[test]
    fn canonical_encoding_is_deterministic_and_round_trips() {
        let signed = signed_envelope();
        let first = result_or_abort(signed.to_canonical_bytes());
        let second = result_or_abort(signed.to_canonical_bytes());
        assert_eq!(first, second);
        let decoded = result_or_abort(SignedPromotionEnvelope::from_canonical_bytes(&first));
        assert_eq!(decoded, signed);
        assert_eq!(result_or_abort(decoded.to_canonical_bytes()), first);
        assert_eq!(
            result_or_abort(decoded.digest()),
            result_or_abort(signed.digest())
        );
    }

    #[test]
    fn proposal_digest_is_deterministic_and_independent_of_voter_and_key() {
        let proposal = binding();
        let first = result_or_abort(proposal.proposal_digest());
        let second = result_or_abort(proposal.proposal_digest());
        assert_eq!(first, second);

        let candidate_vote = result_or_abort(SignedVote::sign(
            &proposal,
            id("node-a"),
            id("candidate-key"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        let witness_vote = result_or_abort(SignedVote::sign(
            &proposal,
            id("witness"),
            id("witness-key"),
            &SigningKey::from_bytes(&WITNESS_SEED),
        ));
        assert_ne!(candidate_vote.voter_id(), witness_vote.voter_id());
        assert_ne!(candidate_vote.key_id(), witness_vote.key_id());
        assert_eq!(result_or_abort(proposal.proposal_digest()), first);

        let mut changed = proposal;
        changed.lease_expires_at_ms = changed.lease_expires_at_ms.saturating_add(1);
        assert_ne!(result_or_abort(changed.proposal_digest()), first);
    }

    #[test]
    fn every_required_signature_verifies() {
        assert_eq!(signed_envelope().verify(&TestResolver::all()), Ok(()));
    }

    #[test]
    fn outer_signature_tamper_is_rejected() {
        let mut bytes = result_or_abort(signed_envelope().to_canonical_bytes());
        let Some(last) = bytes.last_mut() else {
            std::process::abort();
        };
        *last ^= 0x80;
        let decoded = result_or_abort(SignedPromotionEnvelope::from_canonical_bytes(&bytes));
        assert!(matches!(
            decoded.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "node-a"
        ));
    }

    #[test]
    fn vote_signature_tamper_is_rejected_after_valid_candidate_resign() {
        let mut candidate = envelope();
        let Some(vote) = candidate.quorum_certificate.votes.get_mut(0) else {
            std::process::abort();
        };
        vote.signature[0] ^= 1;
        let signed = result_or_abort(SignedPromotionEnvelope::sign(
            candidate,
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        assert!(matches!(
            signed.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "node-a"
        ));
    }

    #[test]
    fn fence_signature_tamper_is_rejected_after_valid_candidate_resign() {
        let mut candidate = envelope();
        candidate.fence_receipt.signature[0] ^= 1;
        let signed = result_or_abort(SignedPromotionEnvelope::sign(
            candidate,
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        assert!(matches!(
            signed.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "witness"
        ));
    }

    #[test]
    fn vote_cannot_be_replayed_under_a_different_message_id() {
        let mut candidate = envelope();
        candidate.message_id = MessageId::new([44; 16]);
        candidate.quorum_certificate.binding.message_id = candidate.message_id;
        let signed = result_or_abort(SignedPromotionEnvelope::sign(
            candidate,
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        assert!(matches!(
            signed.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "node-a"
        ));
    }

    #[test]
    fn previously_issued_witness_vote_cannot_certify_a_later_envelope() {
        let earlier = envelope();
        let Some(earlier_witness) = earlier
            .quorum_certificate
            .votes()
            .iter()
            .find(|vote| vote.voter_id().as_str() == "witness")
            .cloned()
        else {
            std::process::abort();
        };
        let mut later = envelope();
        later.message_id = MessageId::new([44; 16]);
        later.epoch = 20;
        later.candidate_incarnation = 8;
        later.health_attestation.epoch = 20;
        later.health_attestation.incarnation = 8;
        later.lease.epoch = 20;
        later.lease.incarnation = 8;
        later.lease.not_before_ms = 12_000;
        later.lease.expires_at_ms = 13_000;
        later.quorum_certificate.binding.message_id = later.message_id;
        later.quorum_certificate.binding.epoch = later.epoch;
        later.quorum_certificate.binding.candidate_incarnation = later.candidate_incarnation;
        later.quorum_certificate.binding.lease_not_before_ms = later.lease.not_before_ms;
        later.quorum_certificate.binding.lease_expires_at_ms = later.lease.expires_at_ms;
        let later_binding = later.quorum_certificate.binding.clone();
        let later_candidate = result_or_abort(SignedVote::sign(
            &later_binding,
            id("node-a"),
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        later.fence_receipt = result_or_abort(FenceReceipt::sign(
            &later_binding,
            None,
            id("witness"),
            id("key-1"),
            FenceMechanism::Bootstrap,
            11_995,
            [13; 32],
            &SigningKey::from_bytes(&WITNESS_SEED),
        ));
        later.quorum_certificate = result_or_abort(QuorumCertificate::new(
            later_binding,
            2,
            vec![later_candidate, earlier_witness],
        ));
        let signed = result_or_abort(SignedPromotionEnvelope::sign(
            later,
            id("key-1"),
            &SigningKey::from_bytes(&CANDIDATE_SEED),
        ));
        assert!(matches!(
            signed.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "witness"
        ));
    }

    #[test]
    fn version_downgrade_is_rejected() {
        let mut bytes = result_or_abort(envelope().to_canonical_bytes());
        let Some(version) = bytes.get_mut(8..10) else {
            std::process::abort();
        };
        version.copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            PromotionEnvelope::from_canonical_bytes(&bytes),
            Err(EnvelopeError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn malformed_truncations_are_all_rejected() {
        let bytes = result_or_abort(signed_envelope().to_canonical_bytes());
        for length in 0..bytes.len() {
            assert!(SignedPromotionEnvelope::from_canonical_bytes(&bytes[..length]).is_err());
        }
    }

    #[test]
    fn unknown_trailing_field_is_rejected() {
        let mut bytes = result_or_abort(envelope().to_canonical_bytes());
        bytes.push(0x99);
        assert_eq!(
            PromotionEnvelope::from_canonical_bytes(&bytes),
            Err(EnvelopeError::TrailingBytes(1))
        );
    }

    #[test]
    fn malformed_utf8_identifier_is_rejected() {
        let mut bytes = result_or_abort(envelope().to_canonical_bytes());
        let Some(first_workload_byte) = bytes.get_mut(28) else {
            std::process::abort();
        };
        *first_workload_byte = 0xff;
        assert_eq!(
            PromotionEnvelope::from_canonical_bytes(&bytes),
            Err(EnvelopeError::InvalidUtf8)
        );
    }

    #[test]
    fn oversized_wire_objects_are_rejected_before_parsing() {
        let bytes = vec![0; MAX_SIGNED_ENVELOPE_SIZE + 1];
        assert_eq!(
            SignedPromotionEnvelope::from_canonical_bytes(&bytes),
            Err(EnvelopeError::SizeLimitExceeded {
                actual: MAX_SIGNED_ENVELOPE_SIZE + 1,
                maximum: MAX_SIGNED_ENVELOPE_SIZE,
            })
        );
    }

    #[test]
    fn noncanonical_voter_order_is_rejected() {
        let valid = envelope().quorum_certificate;
        let mut votes = valid.votes;
        votes.reverse();
        assert_eq!(
            QuorumCertificate::new(valid.binding, valid.threshold, votes),
            Err(EnvelopeError::NonCanonicalVoterOrder)
        );
    }

    #[test]
    fn duplicate_voter_is_rejected() {
        let valid = envelope().quorum_certificate;
        let Some(first) = valid.votes.first() else {
            std::process::abort();
        };
        let duplicated = vec![(*first).clone(), (*first).clone()];
        assert_eq!(
            QuorumCertificate::new(valid.binding, 2, duplicated),
            Err(EnvelopeError::DuplicateVoter)
        );
    }

    #[test]
    fn lagging_durable_state_is_rejected() {
        let mut candidate = envelope();
        candidate.durable_commit = candidate.required_commit.saturating_sub(1);
        candidate.quorum_certificate.binding.durable_commit = candidate.durable_commit;
        assert_eq!(
            candidate.validate(),
            Err(EnvelopeError::CandidateStateBehind)
        );
    }

    #[test]
    fn retired_or_unknown_key_fails_closed() {
        let resolver = TestResolver {
            candidate: true,
            witness: false,
        };
        assert!(matches!(
            signed_envelope().verify(&resolver),
            Err(EnvelopeError::UnknownVerificationKey { principal, .. }) if principal == "witness"
        ));
    }

    #[test]
    fn signature_domains_prevent_vote_substitution_for_candidate_signature() {
        let candidate = envelope();
        let Some(vote) = candidate.quorum_certificate.votes().first() else {
            std::process::abort();
        };
        let vote_signature = *vote.signature_bytes();
        let substituted = SignedPromotionEnvelope::from_parts(
            candidate,
            id("node-a"),
            id("key-1"),
            vote_signature,
        );
        assert!(matches!(
            substituted.verify(&TestResolver::all()),
            Err(EnvelopeError::InvalidSignature { principal, .. }) if principal == "node-a"
        ));
    }

    #[test]
    fn unknown_fence_tag_is_rejected() {
        assert_eq!(
            FenceMechanism::from_tag(255),
            Err(EnvelopeError::UnknownFenceMechanism(255))
        );
    }
}
