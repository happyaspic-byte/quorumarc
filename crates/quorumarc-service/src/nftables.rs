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
