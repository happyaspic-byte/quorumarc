#![allow(clippy::expect_used)]

use std::fs;

use ed25519_dalek::SigningKey;
use quorumarc_runtime::{VoteReasonCode, WitnessPolicy};
use quorumarc_service::protocol::{
    ProductionFrame, ProductionFrameKind, ProductionRequest, ProductionVotePayload,
};
use quorumarc_service::witness::{
    CandidateCredential, ProductionVoteReply, ProductionWitnessOpenError, ProductionWitnessRuntime,
};
use quorumarc_store::{StoreIdentity, StoreRole};
use quorumarc_wire::{CanonicalId, QuorumCertificate};

fn id(value: &str) -> CanonicalId {
    CanonicalId::new(value).expect("id")
}

fn policy() -> WitnessPolicy {
    WitnessPolicy::new(
        id("witness-a"),
        id("witness-2026-01"),
        id("orders-api"),
        [23; 32],
        [id("node-a"), id("node-b")],
        5_000,
    )
    .expect("policy")
}

fn identity() -> StoreIdentity {
    StoreIdentity::new(
        "prod-cluster",
        "orders-api",
        "witness-a",
        StoreRole::Witness,
        [41; 16],
    )
    .expect("identity")
}

fn signed_vote_request(
    node_id: &str,
    key_id: &str,
    sequence: u64,
    request_id: [u8; 16],
    incarnation: u64,
    epoch: u64,
    key: &SigningKey,
) -> Vec<u8> {
    signed_vote_request_for_workload(
        "orders-api",
        node_id,
        key_id,
        sequence,
        request_id,
        incarnation,
        epoch,
        key,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_vote_request_for_workload(
    workload_id: &str,
    node_id: &str,
    key_id: &str,
    sequence: u64,
    request_id: [u8; 16],
    incarnation: u64,
    epoch: u64,
    key: &SigningKey,
) -> Vec<u8> {
    let payload = ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
        .expect("payload")
        .encode();
    ProductionFrame::sign(
        ProductionFrameKind::Request,
        ProductionRequest {
            cluster_id: "prod-cluster".to_owned(),
            workload_id: workload_id.to_owned(),
            node_id: node_id.to_owned(),
            key_id: key_id.to_owned(),
            request_id,
            sequence,
            incarnation,
            epoch,
            progress_commit: 12,
            policy_hash: [23; 32],
            payload,
        },
        key,
    )
    .expect("sign")
    .encode()
    .expect("encode")
}

#[test]
fn production_vote_runtime_signs_only_after_durable_policy_checked_vote() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-runtime-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let witness = SigningKey::from_bytes(&[29; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];

    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        witness.clone(),
        credentials.clone(),
    )
    .expect("open");
    let first = signed_vote_request("node-a", "node-a-2026-01", 1, [11; 16], 1, 1, &node_a);
    let granted = runtime.handle_vote(&first).expect("grant");
    assert_eq!(granted.code(), VoteReasonCode::GrantedDurablyRecorded);
    assert_eq!(granted.durable_generation(), Some(1));
    let encoded_reply = granted.encode().expect("encode reply");
    let decoded_reply = ProductionVoteReply::decode(&encoded_reply).expect("decode reply");
    assert_eq!(decoded_reply, granted);
    assert_eq!(decoded_reply.cluster_id(), "prod-cluster");
    assert!(
        decoded_reply
            .verify_attestation("prod-cluster", &witness.verifying_key())
            .is_ok()
    );
    assert!(
        decoded_reply
            .verify_attestation("other-cluster", &witness.verifying_key())
            .is_err()
    );
    let signed_vote = decoded_reply.signed_vote().expect("signed vote").clone();
    assert!(QuorumCertificate::new(decoded_reply.binding().clone(), 1, vec![signed_vote]).is_ok());
    assert_eq!(runtime.highest_epoch(), 1);
    assert!(!runtime.effects_open());
    drop(runtime);

    let mut resumed = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        witness,
        credentials,
    )
    .expect("resume");
    let retried = resumed.handle_vote(&first).expect("retry");
    assert_eq!(retried.code(), VoteReasonCode::GrantedAlreadyDurable);
    assert_eq!(retried.durable_generation(), Some(1));
    assert_eq!(retried.signed_vote(), granted.signed_vote());
    assert_eq!(resumed.highest_epoch(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_reused_candidate_and_witness_key() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-key-reuse-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let shared = SigningKey::from_bytes(&[29; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", shared.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];

    assert!(matches!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            shared,
            credentials,
        ),
        Err(ProductionWitnessOpenError::CredentialKeyConflict)
    ));
    assert!(!directory.join("witness-signer.identity").exists());
    assert!(!directory.join("candidate-incarnations.journal").exists());

    let node_a = SigningKey::from_bytes(&[7; 32]);
    assert!(matches!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            SigningKey::from_bytes(&[29; 32]),
            [
                CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key(),)
                    .expect("node a credential"),
                CandidateCredential::new("node-b", "node-b-2026-01", node_a.verifying_key(),)
                    .expect("node b credential"),
            ],
        ),
        Err(ProductionWitnessOpenError::CredentialKeyConflict)
    ));
    assert!(!directory.join("witness-signer.identity").exists());
    assert!(!directory.join("candidate-incarnations.journal").exists());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_unpersisted_witness_signer_rotation() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-rotation-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let first = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials.clone(),
    )
    .expect("first");
    drop(first);

    let rotated_policy = WitnessPolicy::new(
        id("witness-a"),
        id("witness-2026-02"),
        id("orders-api"),
        [23; 32],
        [id("node-a"), id("node-b")],
        5_000,
    )
    .expect("rotated policy");
    assert!(matches!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            rotated_policy,
            SigningKey::from_bytes(&[39; 32]),
            credentials,
        ),
        Err(ProductionWitnessOpenError::SignerIdentityMismatch)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn invalid_identity_attempt_does_not_pin_witness_signer() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-invalid-identity-pin-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let invalid_policy = WitnessPolicy::new(
        id("witness-x"),
        id("witness-x-2026-01"),
        id("orders-api"),
        [23; 32],
        [id("node-a"), id("node-b")],
        5_000,
    )
    .expect("invalid policy");
    assert!(matches!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            invalid_policy,
            SigningKey::from_bytes(&[39; 32]),
            credentials.clone(),
        ),
        Err(ProductionWitnessOpenError::Actor(_))
    ));

    assert!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            SigningKey::from_bytes(&[29; 32]),
            credentials,
        )
        .is_ok()
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_second_writer_on_same_store() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-owner-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let first = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials.clone(),
    )
    .expect("first");
    assert!(matches!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            SigningKey::from_bytes(&[29; 32]),
            credentials.clone(),
        ),
        Err(ProductionWitnessOpenError::OwnerLockRefused)
    ));
    drop(first);
    assert!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            SigningKey::from_bytes(&[29; 32]),
            credentials,
        )
        .is_ok()
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_candidate_incarnation_rollback_after_restart() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-incarnation-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut first = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials.clone(),
    )
    .expect("open");
    let current = signed_vote_request("node-a", "node-a-2026-01", 1, [31; 16], 10, 1, &node_a);
    assert!(first.handle_vote(&current).expect("current").is_granted());
    drop(first);

    let mut resumed = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("resume");
    let rolled_back = signed_vote_request("node-a", "node-a-2026-01", 2, [32; 16], 9, 2, &node_a);
    assert_eq!(
        resumed.handle_vote(&rolled_back),
        Err(quorumarc_service::witness::ProductionVoteError::IncarnationRollback)
    );
    assert_eq!(resumed.highest_epoch(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn policy_refusal_does_not_advance_candidate_incarnation() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-refused-incarnation-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("open");

    let refused = signed_vote_request_for_workload(
        "other-workload",
        "node-a",
        "node-a-2026-01",
        1,
        [41; 16],
        u64::MAX,
        1,
        &node_a,
    );
    assert_eq!(
        runtime
            .handle_vote(&refused)
            .expect("policy refusal")
            .code(),
        VoteReasonCode::RefusedWorkloadMismatch
    );

    let valid = signed_vote_request("node-a", "node-a-2026-01", 2, [42; 16], 10, 1, &node_a);
    assert!(
        runtime
            .handle_vote(&valid)
            .expect("valid vote")
            .is_granted()
    );
    assert_eq!(runtime.highest_epoch(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn candidate_incarnation_storage_remains_bounded_across_votes() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-incarnation-bounded-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("open");

    for epoch in 1_u64..=64 {
        let mut request_id = [0_u8; 16];
        request_id[..8].copy_from_slice(&epoch.to_be_bytes());
        let request = signed_vote_request(
            "node-a",
            "node-a-2026-01",
            epoch,
            request_id,
            epoch,
            epoch,
            &node_a,
        );
        assert!(runtime.handle_vote(&request).expect("vote").is_granted());
    }
    let size = fs::metadata(directory.join("candidate-incarnations.journal"))
        .expect("metadata")
        .len();
    assert!(
        size <= 128,
        "candidate incarnation state grew to {size} bytes"
    );
    drop(runtime);
    assert!(
        ProductionWitnessRuntime::open_vote_actor(
            &directory,
            identity(),
            policy(),
            SigningKey::from_bytes(&[29; 32]),
            [
                CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
                    .expect("node a credential"),
                CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
                    .expect("node b credential"),
            ],
        )
        .is_ok()
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_epoch_jump_without_durable_vote() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-epoch-jump-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("open");
    let jump = signed_vote_request(
        "node-a",
        "node-a-2026-01",
        1,
        [21; 16],
        1,
        u64::MAX,
        &node_a,
    );
    assert_eq!(
        runtime.handle_vote(&jump),
        Err(quorumarc_service::witness::ProductionVoteError::EpochJump)
    );
    assert_eq!(runtime.highest_epoch(), 0);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn conflicting_vote_does_not_advance_candidate_incarnation() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-conflict-incarnation-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("open");

    let first = signed_vote_request("node-a", "node-a-2026-01", 1, [51; 16], 10, 1, &node_a);
    assert!(runtime.handle_vote(&first).expect("first").is_granted());
    let conflict = signed_vote_request(
        "node-a",
        "node-a-2026-01",
        2,
        [52; 16],
        u64::MAX,
        1,
        &node_a,
    );
    assert_eq!(
        runtime.handle_vote(&conflict).expect("conflict").code(),
        VoteReasonCode::RefusedConflictSameEpoch
    );

    let next = signed_vote_request("node-a", "node-a-2026-01", 3, [53; 16], 11, 2, &node_a);
    assert!(runtime.handle_vote(&next).expect("next").is_granted());
    assert_eq!(runtime.highest_epoch(), 2);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_vote_runtime_refuses_conflicting_candidate_in_same_epoch_without_signature() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-vote-conflict-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let credentials = [
        CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
            .expect("node a credential"),
        CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
            .expect("node b credential"),
    ];
    let mut runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity(),
        policy(),
        SigningKey::from_bytes(&[29; 32]),
        credentials,
    )
    .expect("open");

    let node_a_request =
        signed_vote_request("node-a", "node-a-2026-01", 1, [11; 16], 1, 1, &node_a);
    assert!(
        runtime
            .handle_vote(&node_a_request)
            .expect("node a")
            .is_granted()
    );

    let node_b_request =
        signed_vote_request("node-b", "node-b-2026-01", 1, [12; 16], 1, 1, &node_b);
    let refused = runtime
        .handle_vote(&node_b_request)
        .expect("node b refusal");
    assert_eq!(refused.code(), VoteReasonCode::RefusedConflictSameEpoch);
    assert!(refused.signed_vote().is_none());
    assert_eq!(runtime.highest_epoch(), 1);
    assert!(!runtime.effects_open());
    let _ = fs::remove_dir_all(directory);
}
