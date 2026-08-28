use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::adapters::{
    AdapterError, FenceAdapter, FenceEvidence, FenceRequest, SignedFenceReceipt,
};

const FENCE_RECEIPT_DOMAIN: &[u8] = b"quorumarc/fence-receipt/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedfishPowerState {
    On,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedfishBackendError {
    PermissionDenied,
    UnknownSystem,
    Io,
}

pub trait RedfishBackend {
    fn observe(&mut self) -> Result<RedfishPowerState, RedfishBackendError>;
    fn power_off(&mut self) -> Result<(), RedfishBackendError>;
}

/// Authoritative Redfish BMC fencing adapter.
#[derive(Debug)]
pub struct LinuxRedfishFenceAdapter<B> {
    target: String,
    system_url: String,
    backend: B,
}

impl<B: RedfishBackend> LinuxRedfishFenceAdapter<B> {
    pub fn new(
        target: impl Into<String>,
        system_url: impl Into<String>,
        backend: B,
    ) -> Result<Self, AdapterError> {
        let target = target.into();
        let system_url = system_url.into();

        if target.is_empty() || !system_url.starts_with("https://") || system_url.len() > 256 {
            return Err(AdapterError::WrongTarget);
        }

        Ok(Self {
            target,
            system_url,
            backend,
        })
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Issues a cryptographic fence receipt only after independent read-back proves Off.
    pub fn signed_receipt(
        &mut self,
        evidence: &FenceEvidence,
        signing_key: &SigningKey,
    ) -> Result<SignedFenceReceipt, AdapterError> {
        self.verify(evidence)?;
        let digest = fence_receipt_digest(evidence);
        let signature = signing_key.sign(&digest).to_bytes();
        Ok(SignedFenceReceipt::from_parts(
            evidence.target.clone(),
            evidence.outlet.clone(),
            evidence.challenge,
            digest,
            signature,
        ))
    }
}

impl<B: RedfishBackend> FenceAdapter for LinuxRedfishFenceAdapter<B> {
    fn fence(&mut self, request: FenceRequest<'_>) -> Result<FenceEvidence, AdapterError> {
        if request.target != self.target || request.expected_outlet != self.system_url {
            return Err(AdapterError::WrongTarget);
        }

        match self.backend.observe() {
            Ok(RedfishPowerState::Off) => {}
            Ok(RedfishPowerState::On) => {
                self.backend
                    .power_off()
                    .map_err(|_error| AdapterError::EffectNotClosed)?;
            }
            Err(_error) => return Err(AdapterError::EffectNotClosed),
        }

        Ok(FenceEvidence {
            target: self.target.clone(),
            outlet: self.system_url.clone(),
            challenge: request.challenge,
        })
    }

    fn verify(&mut self, evidence: &FenceEvidence) -> Result<(), AdapterError> {
        if evidence.target != self.target || evidence.outlet != self.system_url {
            return Err(AdapterError::WrongTarget);
        }

        match self.backend.observe() {
            Ok(RedfishPowerState::Off) => Ok(()),
            Ok(RedfishPowerState::On) => Err(AdapterError::ReadBackMismatch),
            Err(_error) => Err(AdapterError::EffectNotClosed),
        }
    }
}

fn fence_receipt_digest(evidence: &FenceEvidence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FENCE_RECEIPT_DOMAIN);
    hasher.update(evidence.target.as_bytes());
    hasher.update([0]);
    hasher.update(evidence.outlet.as_bytes());
    hasher.update([0]);
    hasher.update(evidence.challenge);
    hasher.finalize().into()
}
