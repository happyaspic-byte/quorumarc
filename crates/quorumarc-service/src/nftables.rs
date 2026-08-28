use crate::adapters::{AdapterError, CloseReason, EffectAdapter};

pub const QUORUMARC_NFT_COMMENT_PREFIX: &str = "quorumarc:effect-gate:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NftRuleOwnership {
    Owned { epoch: u64 },
    Foreign,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftRuleObservation {
    pub table: String,
    pub chain: String,
    pub handle: u64,
    pub ownership: NftRuleOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NftBackendError {
    PermissionDenied,
    TableOrChainNotFound,
    Conflict,
    ReadBackFailed,
    Io,
}

pub trait NftBackend {
    fn observe(
        &mut self,
        table: &str,
        chain: &str,
    ) -> Result<Option<NftRuleObservation>, NftBackendError>;
    fn add(&mut self, observation: &NftRuleObservation) -> Result<(), NftBackendError>;
    fn delete(&mut self, observation: &NftRuleObservation) -> Result<(), NftBackendError>;
}

/// Fail-closed Linux nftables forward/input gate adapter.
#[derive(Debug)]
pub struct LinuxNftablesEffectAdapter<B> {
    workload_id: String,
    node_id: String,
    table: String,
    chain: String,
    last_epoch: u64,
    active_epoch: Option<u64>,
    backend: B,
}

impl<B: NftBackend> LinuxNftablesEffectAdapter<B> {
    pub fn new(
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        table: impl Into<String>,
        chain: impl Into<String>,
        backend: B,
    ) -> Result<Self, AdapterError> {
        let workload_id = workload_id.into();
        let node_id = node_id.into();
        let table = table.into();
        let chain = chain.into();

        if workload_id.is_empty()
            || node_id.is_empty()
            || !is_valid_nft_identifier(&table)
            || !is_valid_nft_identifier(&chain)
        {
            return Err(AdapterError::WrongTarget);
        }

        Ok(Self {
            workload_id,
            node_id,
            table,
            chain,
            last_epoch: 0,
            active_epoch: None,
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

    #[must_use]
    pub fn ownership_tag(&self) -> String {
        format!("{QUORUMARC_NFT_COMMENT_PREFIX}{}", self.node_id)
    }

    /// Verifies that no nftables rule exists for this table/chain on daemon boot.
    pub fn verify_kernel_closed(&mut self) -> Result<(), AdapterError> {
        let observation = self
            .backend
            .observe(&self.table, &self.chain)
            .map_err(|_error| AdapterError::EffectNotClosed)?;
        if observation.is_some() {
            return Err(AdapterError::ReadBackMismatch);
        }
        Ok(())
    }
}

impl<B: NftBackend> EffectAdapter for LinuxNftablesEffectAdapter<B> {
    fn verify_closed(&self) -> Result<(), AdapterError> {
        if self.active_epoch.is_some() {
            return Err(AdapterError::EffectNotClosed);
        }
        Ok(())
    }

    fn open(&mut self, _workload: &str, _epoch: u64) -> Result<(), AdapterError> {
        Err(AdapterError::ReceiptRequired)
    }

    fn open_with_receipt(
        &mut self,
        workload: &str,
        epoch: u64,
        receipt_digest: [u8; 32],
    ) -> Result<(), AdapterError> {
        if workload != self.workload_id {
            return Err(AdapterError::WrongTarget);
        }
        if epoch == 0 || receipt_digest.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::ReceiptRequired);
        }
        if let Some(active) = self.active_epoch {
            if active == epoch {
                return Ok(());
            }
            return Err(AdapterError::EffectNotClosed);
        }
        if epoch <= self.last_epoch {
            return Err(AdapterError::StaleEpoch);
        }

        let existing = self
            .backend
            .observe(&self.table, &self.chain)
            .map_err(|_error| AdapterError::EffectNotClosed)?;

        if let Some(obs) = existing {
            match obs.ownership {
                NftRuleOwnership::Owned { epoch: obs_epoch } if obs_epoch == epoch => {
                    self.active_epoch = Some(epoch);
                    self.last_epoch = epoch;
                    return Ok(());
                }
                _ => return Err(AdapterError::ReadBackMismatch),
            }
        }

        let target = NftRuleObservation {
            table: self.table.clone(),
            chain: self.chain.clone(),
            handle: 0,
            ownership: NftRuleOwnership::Owned { epoch },
        };

        if self.backend.add(&target).is_err() {
            self.active_epoch = None;
            return Err(AdapterError::EffectNotClosed);
        }

        match self.backend.observe(&self.table, &self.chain) {
            Ok(Some(obs)) => match obs.ownership {
                NftRuleOwnership::Owned { epoch: obs_epoch } if obs_epoch == epoch => {
                    self.active_epoch = Some(epoch);
                    self.last_epoch = epoch;
                    Ok(())
                }
                _ => {
                    let _ = self.backend.delete(&target);
                    self.active_epoch = None;
                    Err(AdapterError::EffectNotClosed)
                }
            },
            _ => {
                let _ = self.backend.delete(&target);
                self.active_epoch = None;
                Err(AdapterError::EffectNotClosed)
            }
        }
    }

    fn close(&mut self, _reason: CloseReason) -> Result<(), AdapterError> {
        let existing = self
            .backend
            .observe(&self.table, &self.chain)
            .map_err(|_error| AdapterError::EffectNotClosed)?;

        if let Some(obs) = existing {
            if matches!(obs.ownership, NftRuleOwnership::Owned { .. }) {
                self.backend
                    .delete(&obs)
                    .map_err(|_error| AdapterError::EffectNotClosed)?;

                match self.backend.observe(&self.table, &self.chain) {
                    Ok(None) => {}
                    _ => return Err(AdapterError::EffectNotClosed),
                }
            } else {
                return Err(AdapterError::ReadBackMismatch);
            }
        }

        self.active_epoch = None;
        Ok(())
    }
}

fn is_valid_nft_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Native Linux nftables command execution backend.
#[derive(Clone, Debug)]
pub struct NativeNftBackend {
    binary_path: std::path::PathBuf,
    node_id: String,
}

impl NativeNftBackend {
    pub fn new(node_id: impl Into<String>) -> Result<Self, NftBackendError> {
        let node_id = node_id.into();
        if node_id.is_empty() {
            return Err(NftBackendError::PermissionDenied);
        }
        for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
            let path = std::path::Path::new(candidate);
            if path.is_file() {
                return Ok(Self {
                    binary_path: path.to_path_buf(),
                    node_id,
                });
            }
        }
        Err(NftBackendError::TableOrChainNotFound)
    }

    fn tag_for_epoch(&self, epoch: u64) -> String {
        format!("{QUORUMARC_NFT_COMMENT_PREFIX}{}:{epoch}", self.node_id)
    }
}

impl NftBackend for NativeNftBackend {
    fn observe(
        &mut self,
        table: &str,
        chain: &str,
    ) -> Result<Option<NftRuleObservation>, NftBackendError> {
        if !is_valid_nft_identifier(table) || !is_valid_nft_identifier(chain) {
            return Err(NftBackendError::TableOrChainNotFound);
        }
        let output = std::process::Command::new(&self.binary_path)
            .args(["-a", "list", "chain", "inet", table, chain])
            .output()
            .map_err(|_error| NftBackendError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file or directory") {
                return Err(NftBackendError::TableOrChainNotFound);
            }
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                return Err(NftBackendError::PermissionDenied);
            }
            return Err(NftBackendError::Io);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_nft_chain_output(&stdout, &self.node_id, table, chain)
    }

    fn add(&mut self, observation: &NftRuleObservation) -> Result<(), NftBackendError> {
        let epoch = match observation.ownership {
            NftRuleOwnership::Owned { epoch } => epoch,
            NftRuleOwnership::Foreign => return Err(NftBackendError::Conflict),
        };
        let comment = self.tag_for_epoch(epoch);
        let output = std::process::Command::new(&self.binary_path)
            .args([
                "add",
                "rule",
                "inet",
                &observation.table,
                &observation.chain,
                "accept",
                "comment",
                &comment,
            ])
            .output()
            .map_err(|_error| NftBackendError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                return Err(NftBackendError::PermissionDenied);
            }
            return Err(NftBackendError::Conflict);
        }
        Ok(())
    }

    fn delete(&mut self, observation: &NftRuleObservation) -> Result<(), NftBackendError> {
        if matches!(observation.ownership, NftRuleOwnership::Foreign) {
            return Err(NftBackendError::Conflict);
        }
        if observation.handle == 0 {
            return Err(NftBackendError::ReadBackFailed);
        }
        let handle_str = observation.handle.to_string();
        let output = std::process::Command::new(&self.binary_path)
            .args([
                "delete",
                "rule",
                "inet",
                &observation.table,
                &observation.chain,
                "handle",
                &handle_str,
            ])
            .output()
            .map_err(|_error| NftBackendError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                return Err(NftBackendError::PermissionDenied);
            }
            return Err(NftBackendError::Io);
        }
        Ok(())
    }
}

pub fn parse_nft_chain_output(
    stdout: &str,
    expected_node_id: &str,
    table: &str,
    chain: &str,
) -> Result<Option<NftRuleObservation>, NftBackendError> {
    let mut matched = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("# handle ") {
            continue;
        }
        let Some((_, handle_part)) = trimmed.split_once("# handle ") else {
            continue;
        };
        let handle = handle_part
            .split_whitespace()
            .next()
            .and_then(|h| h.parse::<u64>().ok())
            .ok_or(NftBackendError::ReadBackFailed)?;

        let ownership = if let Some((_, comment_part)) = trimmed.split_once("comment \"") {
            if let Some((comment, _)) = comment_part.split_once('"') {
                if let Some(rest) = comment.strip_prefix(QUORUMARC_NFT_COMMENT_PREFIX) {
                    if let Some((node, epoch_str)) = rest.split_once(':') {
                        if node == expected_node_id {
                            if let Ok(epoch) = epoch_str.parse::<u64>() {
                                NftRuleOwnership::Owned { epoch }
                            } else {
                                NftRuleOwnership::Foreign
                            }
                        } else {
                            NftRuleOwnership::Foreign
                        }
                    } else {
                        NftRuleOwnership::Foreign
                    }
                } else {
                    NftRuleOwnership::Foreign
                }
            } else {
                NftRuleOwnership::Foreign
            }
        } else {
            NftRuleOwnership::Foreign
        };

        if matched.is_some() {
            return Err(NftBackendError::ReadBackFailed);
        }
        matched = Some(NftRuleObservation {
            table: table.to_owned(),
            chain: chain.to_owned(),
            handle,
            ownership,
        });
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn parses_nft_output_correctly() {
        let output = r#"
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        accept comment "quorumarc:effect-gate:node-a:2" # handle 12
    }
}
"#;
        let obs = parse_nft_chain_output(output, "node-a", "filter", "forward")
            .expect("parse")
            .expect("some");
        assert_eq!(obs.handle, 12);
        assert_eq!(obs.ownership, NftRuleOwnership::Owned { epoch: 2 });

        let foreign_node = parse_nft_chain_output(output, "node-b", "filter", "forward")
            .expect("parse")
            .expect("some");
        assert_eq!(foreign_node.ownership, NftRuleOwnership::Foreign);
    }
}
