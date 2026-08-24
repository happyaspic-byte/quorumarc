use std::panic::catch_unwind;

use quorumarc_wire::{
    CanonicalId, EnvelopeError, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant,
    MAX_ENVELOPE_SIZE, MessageId, PROTOCOL_VERSION, PromotionEnvelope, QuorumBinding,
    QuorumCertificate, SignedPromotionEnvelope, SignedVote, SigningKey, VerificationKeyResolver,
    VerifyingKey,
};

const CANDIDATE_SEED: [u8; 32] = [11; 32];
const WITNESS_SEED: [u8; 32] = [29; 32];
const CAMPAIGN_SEEDS: [u64; 8] = [
    0x0000_0000_0000_0001,
    0x0123_4567_89ab_cdef,
    0x243f_6a88_85a3_08d3,
    0x9e37_79b9_7f4a_7c15,
    0xa409_3822_299f_31d0,
    0xd1b5_4a32_d192_ed03,
    0xfedc_ba98_7654_3210,
    0xffff_ffff_ffff_ffff,
];
const STRUCTURAL_ROUNDS_PER_SEED: usize = 32;
const STRUCTURAL_CASES_PER_ROUND: usize = 13;
const AUTHENTICATED_ROUNDS_PER_SEED: usize = 64;

const MAGIC_LENGTH: usize = 8;
const VERSION_OFFSET: usize = MAGIC_LENGTH;
const LENGTH_OFFSET: usize = VERSION_OFFSET + 2;
const SIGNED_HEADER_LENGTH: usize = LENGTH_OFFSET + 4;
const INNER_MAGIC_OFFSET: usize = SIGNED_HEADER_LENGTH;
const INNER_VERSION_OFFSET: usize = INNER_MAGIC_OFFSET + MAGIC_LENGTH;

struct TestResolver;

impl VerificationKeyResolver for TestResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if key_id.as_str() != "key-1" {
            return None;
        }
        match principal.as_str() {
            "node-a" => Some(SigningKey::from_bytes(&CANDIDATE_SEED).verifying_key()),
            "witness" => Some(SigningKey::from_bytes(&WITNESS_SEED).verifying_key()),
            _ => None,
        }
    }
}

struct DeterministicRng(u64);

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() as usize) % upper
    }

    fn nonzero_byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0] | 1
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next_u64().to_le_bytes()[0];
        }
    }
}

fn canonical_id(value: &str) -> Result<CanonicalId, EnvelopeError> {
    CanonicalId::new(value)
}

fn signed_fixture() -> Result<SignedPromotionEnvelope, EnvelopeError> {
    let candidate_id = canonical_id("node-a")?;
    let witness_id = canonical_id("witness")?;
    let key_id = canonical_id("key-1")?;
    let binding = QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new([3; 16]),
        workload_id: canonical_id("orders")?,
        candidate_node_id: candidate_id.clone(),
        candidate_incarnation: 7,
        epoch: 19,
        policy_hash: [5; 32],
        required_commit: 41,
        durable_commit: 41,
        state_root: [7; 32],
        lease_not_before_ms: 10_000,
        lease_expires_at_ms: 11_000,
    };
    let candidate_key = SigningKey::from_bytes(&CANDIDATE_SEED);
    let witness_key = SigningKey::from_bytes(&WITNESS_SEED);
    let candidate_vote = SignedVote::sign(
        &binding,
        candidate_id.clone(),
        key_id.clone(),
        &candidate_key,
    )?;
    let witness_vote = SignedVote::sign(
        &binding,
        witness_id.clone(),
        key_id.clone(),
        &witness_key,
    )?;
    let quorum_certificate = QuorumCertificate::new(
        binding.clone(),
        2,
        vec![candidate_vote, witness_vote],
    )?;
    let fence_receipt = FenceReceipt::sign(
        &binding,
        None,
        witness_id,
        key_id.clone(),
        FenceMechanism::Bootstrap,
        9_995,
        [13; 32],
        &witness_key,
    )?;
    let envelope = PromotionEnvelope {
        protocol_version: PROTOCOL_VERSION,
        message_id: binding.message_id,
        workload_id: binding.workload_id.clone(),
        candidate_node_id: candidate_id.clone(),
        candidate_incarnation: binding.candidate_incarnation,
        epoch: binding.epoch,
        policy_hash: binding.policy_hash,
        quorum_certificate,
        fence_receipt,
        required_commit: binding.required_commit,
        durable_commit: binding.durable_commit,
        state_root: binding.state_root,
        health_attestation: HealthAttestation {
            node_id: candidate_id.clone(),
            incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            healthy: true,
            passed_checks: 3,
            observed_at_ms: 9_997,
            attestation_digest: [17; 32],
        },
        lease: LeaseGrant {
            holder_node_id: candidate_id,
            incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            not_before_ms: binding.lease_not_before_ms,
            expires_at_ms: binding.lease_expires_at_ms,
        },
    };
    SignedPromotionEnvelope::sign(envelope, key_id, &candidate_key)
}

fn unsupported_version(rng: &mut DeterministicRng) -> u16 {
    let random = rng.next_u64().to_le_bytes();
    let candidate = u16::from_le_bytes([random[0], random[1]]);
    if candidate == PROTOCOL_VERSION {
        PROTOCOL_VERSION.wrapping_add(1)
    } else {
        candidate
    }
}

fn corrupt_byte(bytes: &mut [u8], offset: usize, rng: &mut DeterministicRng) {
    let Some(byte) = bytes.get_mut(offset) else {
        std::process::abort();
    };
    *byte ^= rng.nonzero_byte();
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let Some(field) = bytes.get_mut(offset..offset.saturating_add(2)) else {
        std::process::abort();
    };
    field.copy_from_slice(&value.to_be_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    let Some(field) = bytes.get_mut(offset..offset.saturating_add(4)) else {
        std::process::abort();
    };
    field.copy_from_slice(&value.to_be_bytes());
}

fn assert_signed_rejected(bytes: &[u8], seed: u64, round: usize, case: &str) {
    let outcome = catch_unwind(|| SignedPromotionEnvelope::from_canonical_bytes(bytes));
    assert!(
        outcome.is_ok(),
        "signed parser panicked: seed={seed:#018x} round={round} case={case}"
    );
    if let Ok(decoded) = outcome {
        assert!(
            decoded.is_err(),
            "signed parser accepted malformed input: seed={seed:#018x} round={round} case={case}"
        );
    }
}

fn assert_unsigned_rejected(bytes: &[u8], seed: u64, round: usize, case: &str) {
    let outcome = catch_unwind(|| PromotionEnvelope::from_canonical_bytes(bytes));
    assert!(
        outcome.is_ok(),
        "unsigned parser panicked: seed={seed:#018x} round={round} case={case}"
    );
    if let Ok(decoded) = outcome {
        assert!(
            decoded.is_err(),
            "unsigned parser accepted malformed input: seed={seed:#018x} round={round} case={case}"
        );
    }
}

fn assert_not_authenticated(
    bytes: &[u8],
    resolver: &TestResolver,
    seed: u64,
    round: usize,
) {
    let outcome = catch_unwind(|| {
        SignedPromotionEnvelope::from_canonical_bytes(bytes)
            .and_then(|envelope| envelope.verify(resolver))
    });
    assert!(
        outcome.is_ok(),
        "decode/verify path panicked: seed={seed:#018x} round={round}"
    );
    if let Ok(result) = outcome {
        assert!(
            result.is_err(),
            "changed canonical bytes authenticated: seed={seed:#018x} round={round}"
        );
    }
}

#[test]
fn bounded_structural_malformed_campaign_never_panics_or_accepts() -> Result<(), EnvelopeError> {
    let signed = signed_fixture()?;
    let canonical_signed = signed.to_canonical_bytes()?;
    let canonical_unsigned = signed.envelope().to_canonical_bytes()?;
    let mut case_count = 0_usize;

    for seed in CAMPAIGN_SEEDS {
        let mut rng = DeterministicRng::new(seed);
        for round in 0..STRUCTURAL_ROUNDS_PER_SEED {
            let mut unsigned_magic = canonical_unsigned.clone();
            let unsigned_magic_byte = rng.bounded(MAGIC_LENGTH);
            corrupt_byte(&mut unsigned_magic, unsigned_magic_byte, &mut rng);
            assert_unsigned_rejected(&unsigned_magic, seed, round, "magic");
            case_count += 1;

            let mut unsigned_version = canonical_unsigned.clone();
            let version = unsupported_version(&mut rng);
            write_u16(&mut unsigned_version, VERSION_OFFSET, version);
            assert_unsigned_rejected(&unsigned_version, seed, round, "version");
            case_count += 1;

            let mut unsigned_trailing = canonical_unsigned.clone();
            let trailing_length = rng.bounded(32) + 1;
            let old_length = unsigned_trailing.len();
            unsigned_trailing.resize(old_length + trailing_length, 0);
            rng.fill(&mut unsigned_trailing[old_length..]);
            assert_unsigned_rejected(&unsigned_trailing, seed, round, "trailing");
            case_count += 1;

            let unsigned_cut = rng.bounded(canonical_unsigned.len());
            assert_unsigned_rejected(
                &canonical_unsigned[..unsigned_cut],
                seed,
                round,
                "truncation",
            );
            case_count += 1;

            let mut unsigned_garbage = vec![0_u8; rng.bounded(2_048) + MAGIC_LENGTH];
            rng.fill(&mut unsigned_garbage);
            unsigned_garbage[..MAGIC_LENGTH].fill(0);
            assert_unsigned_rejected(&unsigned_garbage, seed, round, "garbage");
            case_count += 1;

            let mut signed_magic = canonical_signed.clone();
            let signed_magic_byte = rng.bounded(MAGIC_LENGTH);
            corrupt_byte(&mut signed_magic, signed_magic_byte, &mut rng);
            assert_signed_rejected(&signed_magic, seed, round, "outer-magic");
            case_count += 1;

            let mut signed_version = canonical_signed.clone();
            let version = unsupported_version(&mut rng);
            write_u16(&mut signed_version, VERSION_OFFSET, version);
            assert_signed_rejected(&signed_version, seed, round, "outer-version");
            case_count += 1;

            let mut inner_magic = canonical_signed.clone();
            let inner_magic_byte = INNER_MAGIC_OFFSET + rng.bounded(MAGIC_LENGTH);
            corrupt_byte(&mut inner_magic, inner_magic_byte, &mut rng);
            assert_signed_rejected(&inner_magic, seed, round, "inner-magic");
            case_count += 1;

            let mut inner_version = canonical_signed.clone();
            let version = unsupported_version(&mut rng);
            write_u16(&mut inner_version, INNER_VERSION_OFFSET, version);
            assert_signed_rejected(&inner_version, seed, round, "inner-version");
            case_count += 1;

            let mut signed_trailing = canonical_signed.clone();
            let trailing_length = rng.bounded(32) + 1;
            let old_length = signed_trailing.len();
            signed_trailing.resize(old_length + trailing_length, 0);
            rng.fill(&mut signed_trailing[old_length..]);
            assert_signed_rejected(&signed_trailing, seed, round, "trailing");
            case_count += 1;

            let signed_cut = rng.bounded(canonical_signed.len());
            assert_signed_rejected(
                &canonical_signed[..signed_cut],
                seed,
                round,
                "truncation",
            );
            case_count += 1;

            let mut oversized_inner = canonical_signed.clone();
            let oversized_length = u32::try_from(MAX_ENVELOPE_SIZE)
                .map_or(u32::MAX, |maximum| maximum.saturating_add(1));
            write_u32(&mut oversized_inner, LENGTH_OFFSET, oversized_length);
            assert_signed_rejected(&oversized_inner, seed, round, "oversized-inner");
            case_count += 1;

            let mut signed_garbage = vec![0_u8; rng.bounded(2_048) + MAGIC_LENGTH];
            rng.fill(&mut signed_garbage);
            signed_garbage[..MAGIC_LENGTH].fill(0);
            assert_signed_rejected(&signed_garbage, seed, round, "garbage");
            case_count += 1;
        }
    }

    assert_eq!(
        case_count,
        CAMPAIGN_SEEDS.len() * STRUCTURAL_ROUNDS_PER_SEED * STRUCTURAL_CASES_PER_ROUND
    );
    Ok(())
}

#[test]
fn bounded_changed_byte_campaign_never_authenticates() -> Result<(), EnvelopeError> {
    let canonical_signed = signed_fixture()?.to_canonical_bytes()?;
    let resolver = TestResolver;
    let mut case_count = 0_usize;

    for seed in CAMPAIGN_SEEDS {
        let mut rng = DeterministicRng::new(seed);
        for round in 0..AUTHENTICATED_ROUNDS_PER_SEED {
            let mut changed = canonical_signed.clone();
            let offset = rng.bounded(changed.len());
            corrupt_byte(&mut changed, offset, &mut rng);
            assert_not_authenticated(&changed, &resolver, seed, round);
            case_count += 1;
        }
    }

    assert_eq!(
        case_count,
        CAMPAIGN_SEEDS.len() * AUTHENTICATED_ROUNDS_PER_SEED
    );
    Ok(())
}
