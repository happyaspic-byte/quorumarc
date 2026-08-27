use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Strict production cluster configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProductionConfig {
    schema_version: String,
    cluster_id: String,
    node_id: String,
    workload_id: String,
    role: String,
    listen: SocketAddr,
    witness: SocketAddr,
    store_dir: PathBuf,
    signing_key: PathBuf,
    #[serde(default)]
    automatic_promotion: bool,
    fence: FenceConfig,
    workload: WorkloadConfig,
    effect: EffectConfig,
    members: Vec<MemberConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FenceConfig {
    mechanism: String,
    profile: String,
    #[serde(default)]
    read_back: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    unit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EffectConfig {
    vip: String,
    interface: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemberConfig {
    pub id: String,
    pub role: String,
    pub address: SocketAddr,
    pub failure_domain: String,
}

/// Typed production-configuration refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    UnknownField(String),
    DuplicateField(String),
    PathMustBeAbsolute(String),
    AutomaticPromotionRequiresAuthoritativeFence,
    FenceReadBackRequired,
    FailureDomainNotIndependent,
    WitnessFailureDomainNotIndependent,
    InvalidValue(String),
    MissingField(String),
    TomlError(String),
}

impl ConfigError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnknownField(_) => "CONFIG_UNKNOWN_FIELD",
            Self::DuplicateField(_) => "CONFIG_DUPLICATE_FIELD",
            Self::PathMustBeAbsolute(_) => "CONFIG_PATH_NOT_ABSOLUTE",
            Self::AutomaticPromotionRequiresAuthoritativeFence => {
                "AUTOMATIC_PROMOTION_REQUIRES_AUTHORITATIVE_FENCE"
            }
            Self::FenceReadBackRequired => "FENCE_READ_BACK_REQUIRED",
            Self::FailureDomainNotIndependent => "FAILURE_DOMAIN_NOT_INDEPENDENT",
            Self::WitnessFailureDomainNotIndependent => "WITNESS_FAILURE_DOMAIN_NOT_INDEPENDENT",
            Self::InvalidValue(_) => "CONFIG_INVALID_VALUE",
            Self::MissingField(_) => "CONFIG_MISSING_FIELD",
            Self::TomlError(_) => "CONFIG_TOML_INVALID",
        }
    }
}

impl ProductionConfig {
    /// Parses and strictly validates a production TOML configuration.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|error| {
            let message = error.to_string();
            if message.contains("unknown field") {
                ConfigError::UnknownField(message)
            } else if message.contains("duplicate key") {
                ConfigError::DuplicateField(message)
            } else if message.contains("missing field") {
                ConfigError::MissingField(message)
            } else {
                ConfigError::TomlError(message)
            }
        })?;

        if config.schema_version != "1" {
            return Err(ConfigError::InvalidValue("schema_version".to_owned()));
        }
        if !config.store_dir.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute("store_dir".to_owned()));
        }
        if !config.signing_key.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute("signing_key".to_owned()));
        }
        if config.members.len() != 3 {
            return Err(ConfigError::InvalidValue(
                "cluster must declare exactly 3 members".to_owned(),
            ));
        }
        if config.automatic_promotion
            && config.fence.mechanism != "hardware-power"
            && config.fence.mechanism != "storage-reservation"
        {
            return Err(ConfigError::AutomaticPromotionRequiresAuthoritativeFence);
        }
        if config.automatic_promotion && !config.fence.read_back {
            return Err(ConfigError::FenceReadBackRequired);
        }
        let failure_domains: BTreeSet<_> = config
            .members
            .iter()
            .map(|member| member.failure_domain.as_str())
            .collect();
        if failure_domains.len() != config.members.len() {
            return Err(ConfigError::FailureDomainNotIndependent);
        }

        let data_hosts: BTreeSet<_> = config
            .members
            .iter()
            .filter(|member| member.role == "data")
            .map(|member| member.address.ip())
            .collect();
        if data_hosts.contains(&config.witness.ip()) {
            return Err(ConfigError::WitnessFailureDomainNotIndependent);
        }

        Ok(config)
    }

    /// Cluster identity.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// Static membership.
    #[must_use]
    pub fn members(&self) -> &[MemberConfig] {
        &self.members
    }

    /// Whether automatic promotion is requested after fence eligibility.
    #[must_use]
    pub const fn automatic_promotion(&self) -> bool {
        self.automatic_promotion
    }

    /// External effects remain closed until later milestones.
    #[must_use]
    pub const fn effect_gate_state(&self) -> &'static str {
        "closed"
    }
}
