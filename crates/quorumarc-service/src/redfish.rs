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

/// Native Redfish BMC command execution backend using curl over HTTPS.
#[derive(Clone, Debug)]
pub struct NativeRedfishBackend {
    curl_path: std::path::PathBuf,
    system_url: String,
    ca_cert_path: Option<std::path::PathBuf>,
    auth_config_path: Option<std::path::PathBuf>,
    timeout_secs: u32,
}

impl NativeRedfishBackend {
    pub fn new(
        system_url: impl Into<String>,
        ca_cert_path: Option<std::path::PathBuf>,
        auth_config_path: Option<std::path::PathBuf>,
        timeout_secs: u32,
    ) -> Result<Self, RedfishBackendError> {
        let system_url = system_url.into();
        if !system_url.starts_with("https://") {
            return Err(RedfishBackendError::PermissionDenied);
        }
        let timeout_secs = if timeout_secs == 0 {
            5
        } else {
            timeout_secs.min(30)
        };
        for candidate in ["/usr/bin/curl", "/bin/curl"] {
            let path = std::path::Path::new(candidate);
            if path.is_file() {
                return Ok(Self {
                    curl_path: path.to_path_buf(),
                    system_url,
                    ca_cert_path,
                    auth_config_path,
                    timeout_secs,
                });
            }
        }
        Err(RedfishBackendError::Io)
    }

    fn base_curl_command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.curl_path);
        let timeout_str = self.timeout_secs.to_string();
        cmd.args([
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.3",
            "--max-time",
            &timeout_str,
        ]);
        if let Some(ca) = &self.ca_cert_path {
            cmd.arg("--cacert").arg(ca);
        }
        if let Some(auth) = &self.auth_config_path {
            cmd.arg("--config").arg(auth);
        }
        cmd
    }
}

impl RedfishBackend for NativeRedfishBackend {
    fn observe(&mut self) -> Result<RedfishPowerState, RedfishBackendError> {
        let mut cmd = self.base_curl_command();
        cmd.args(["-H", "Accept: application/json", &self.system_url]);
        let output = cmd.output().map_err(|_error| RedfishBackendError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("401") || stderr.contains("403") {
                return Err(RedfishBackendError::PermissionDenied);
            }
            if stderr.contains("404") {
                return Err(RedfishBackendError::UnknownSystem);
            }
            return Err(RedfishBackendError::Io);
        }
        let body = String::from_utf8_lossy(&output.stdout);
        parse_redfish_power_state(&body)
    }

    fn power_off(&mut self) -> Result<(), RedfishBackendError> {
        let reset_url = format!(
            "{}/Actions/ComputerSystem.Reset",
            self.system_url.trim_end_matches('/')
        );
        let mut cmd = self.base_curl_command();
        cmd.args([
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            "{\"ResetType\":\"ForceOff\"}",
            &reset_url,
        ]);
        let output = cmd.output().map_err(|_error| RedfishBackendError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("401") || stderr.contains("403") {
                return Err(RedfishBackendError::PermissionDenied);
            }
            return Err(RedfishBackendError::Io);
        }
        Ok(())
    }
}

pub fn parse_redfish_power_state(body: &str) -> Result<RedfishPowerState, RedfishBackendError> {
    if let Some((_, after)) = body.split_once("\"PowerState\"") {
        if let Some((_, val_part)) = after.split_once(':') {
            let trimmed = val_part.trim_start().trim_start_matches('"');
            if trimmed.starts_with("Off") {
                return Ok(RedfishPowerState::Off);
            }
            if trimmed.starts_with("On") || trimmed.starts_with("PoweringOff") {
                return Ok(RedfishPowerState::On);
            }
        }
    }
    Err(RedfishBackendError::UnknownSystem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redfish_payloads_correctly() {
        let off_json = r#"{"@odata.id":"/redfish/v1/Systems/1","PowerState":"Off","Status":{"State":"Enabled"}}"#;
        assert_eq!(
            parse_redfish_power_state(off_json),
            Ok(RedfishPowerState::Off)
        );

        let on_json = r#"{"@odata.id":"/redfish/v1/Systems/1","PowerState":"On"}"#;
        assert_eq!(
            parse_redfish_power_state(on_json),
            Ok(RedfishPowerState::On)
        );

        let invalid = r#"{"@odata.id":"/redfish/v1/Systems/1"}"#;
        assert_eq!(
            parse_redfish_power_state(invalid),
            Err(RedfishBackendError::UnknownSystem)
        );
    }
}
