#![allow(clippy::expect_used)]

use quorumarc_wire::{
    CanonicalId, MessageId, PROTOCOL_VERSION, ProductionQuorumCertificate, ProductionSignedVote,
    QuorumBinding, SigningKey, VerificationKeyResolver, VerifyingKey,
};

struct Resolver {
    key: VerifyingKey,
}

impl VerificationKeyResolver for Resolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        (principal.as_str() == "witness-a" && key_id.as_str() == "witness-key").then_some(self.key)
    }
}

fn id(value: &str) -> CanonicalId {
    CanonicalId::new(value).expect("id")
}

fn binding() -> QuorumBinding {
    QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new([7; 16]),
        workload_id: id("orders-api"),
        candidate_node_id: id("node-a"),
        candidate_incarnation: 3,
        epoch: 9,
        policy_hash: [11; 32],
        required_commit: 41,
        durable_commit: 41,
        state_root: [13; 32],
        lease_not_before_ms: 10_000,
        lease_expires_at_ms: 11_000,
    }
}

#[test]
fn production_vote_signature_and_certificate_bind_cluster() {
    let cluster_a = id("cluster-a");
    let cluster_b = id("cluster-b");
    let binding = binding();
    let key = SigningKey::from_bytes(&[29; 32]);
    let resolver = Resolver {
        key: key.verifying_key(),
    };
    let vote = ProductionSignedVote::sign(
        cluster_a.clone(),
        &binding,
        id("witness-a"),
        id("witness-key"),
        &key,
    )
    .expect("sign");
    assert!(vote.verify(&cluster_a, &binding, &resolver).is_ok());
    assert!(vote.verify(&cluster_b, &binding, &resolver).is_err());

    let certificate =
        ProductionQuorumCertificate::new(cluster_a.clone(), binding.clone(), 1, vec![vote.clone()])
            .expect("certificate");
    assert!(certificate.verify(&resolver).is_ok());
    assert_eq!(
        ProductionQuorumCertificate::from_canonical_bytes(
            &certificate
                .to_canonical_bytes()
                .expect("encode certificate")
        )
        .expect("decode certificate"),
        certificate
    );
    assert!(ProductionQuorumCertificate::new(cluster_b, binding, 1, vec![vote]).is_err());
}

#[test]
fn production_vote_cluster_tampering_invalidates_signature() {
    let binding = binding();
    let key = SigningKey::from_bytes(&[29; 32]);
    let resolver = Resolver {
        key: key.verifying_key(),
    };
    let vote = ProductionSignedVote::sign(
        id("cluster-a"),
        &binding,
        id("witness-a"),
        id("witness-key"),
        &key,
    )
    .expect("sign");
    let mut encoded = vote.to_canonical_bytes().expect("encode");
    let offset = encoded
        .windows(b"cluster-a".len())
        .position(|window| window == b"cluster-a")
        .expect("cluster bytes");
    encoded[offset + b"cluster-".len()] = b'b';
    let tampered = ProductionSignedVote::from_canonical_bytes(&encoded).expect("decode tampered");
    assert!(
        tampered
            .verify(&id("cluster-b"), &binding, &resolver)
            .is_err()
    );
}
