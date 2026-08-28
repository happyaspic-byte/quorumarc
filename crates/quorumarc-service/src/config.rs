use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use rustix::fs::{FlockOperation, OFlags, flock};
use rustls::pki_types::ServerName;
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
    store_id: String,
    signing_key: PathBuf,
    key_id: String,
    policy_hash: String,
    max_lease_duration_ms: u64,
    #[serde(default)]
    automatic_promotion: bool,
    #[serde(default = "default_log_level")]
    log_level: String,
    tls: TlsConfig,
    fence: FenceConfig,
    workload: WorkloadConfig,
    effect: EffectConfig,
    members: Vec<MemberConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    certificate_chain: PathBuf,
    private_key: PathBuf,
    trusted_roots: PathBuf,
    server_name: String,
    io_timeout_ms: u64,
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
    pub key_id: String,
    pub public_key: PathBuf,
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
    ReservedWitnessHost,
    InvalidTopology,
    LocalIdentityMismatch,
    WitnessEndpointMismatch,
    StoreUnavailable,
    SigningKeyUnavailable,
    OwnerLockRefused,
    UnsafeReload,
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
            Self::ReservedWitnessHost => "RESERVED_WITNESS_HOST",
            Self::InvalidTopology => "CONFIG_INVALID_TOPOLOGY",
            Self::LocalIdentityMismatch => "CONFIG_LOCAL_IDENTITY_MISMATCH",
            Self::WitnessEndpointMismatch => "CONFIG_WITNESS_ENDPOINT_MISMATCH",
            Self::StoreUnavailable => "CONFIG_STORE_UNAVAILABLE",
            Self::SigningKeyUnavailable => "CONFIG_SIGNING_KEY_UNAVAILABLE",
            Self::OwnerLockRefused => "OWNER_LOCK_REFUSED",
            Self::UnsafeReload => "CONFIG_UNSAFE_RELOAD",
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
        if !matches!(
            config.log_level.as_str(),
            "error" | "warn" | "info" | "debug"
        ) {
            return Err(ConfigError::InvalidValue("log_level".to_owned()));
        }
        if !config.store_dir.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute("store_dir".to_owned()));
        }
        if decode_hex::<16>(&config.store_id).is_none() {
            return Err(ConfigError::InvalidValue("store_id".to_owned()));
        }
        if !config.signing_key.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute("signing_key".to_owned()));
        }
        if !valid_identifier(&config.key_id) {
            return Err(ConfigError::InvalidValue("key_id".to_owned()));
        }
        if decode_policy_hash(&config.policy_hash).is_none() {
            return Err(ConfigError::InvalidValue("policy_hash".to_owned()));
        }
        if config.max_lease_duration_ms == 0 {
            return Err(ConfigError::InvalidValue(
                "max_lease_duration_ms".to_owned(),
            ));
        }
        if !config.tls.certificate_chain.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute(
                "tls.certificate_chain".to_owned(),
            ));
        }
        if !config.tls.private_key.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute(
                "tls.private_key".to_owned(),
            ));
        }
        if !config.tls.trusted_roots.is_absolute() {
            return Err(ConfigError::PathMustBeAbsolute(
                "tls.trusted_roots".to_owned(),
            ));
        }
        if !(1_000..=120_000).contains(&config.tls.io_timeout_ms) {
            return Err(ConfigError::InvalidValue("tls.io_timeout_ms".to_owned()));
        }
        if ServerName::try_from(config.tls.server_name.as_str()).is_err()
            || config.tls.server_name.parse::<IpAddr>().is_ok()
            || config.tls.server_name.is_empty()
            || config
                .tls
                .server_name
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ConfigError::InvalidValue("tls.server_name".to_owned()));
        }
        if !valid_effect_vip(&config.effect.vip) {
            return Err(ConfigError::InvalidValue("effect.vip".to_owned()));
        }
        if !valid_interface_name(&config.effect.interface) {
            return Err(ConfigError::InvalidValue("effect.interface".to_owned()));
        }
        if config.members.len() != 3 {
            return Err(ConfigError::InvalidValue(
                "cluster must declare exactly 3 members".to_owned(),
            ));
        }
        if config.role != "data" && config.role != "witness" {
            return Err(ConfigError::InvalidTopology);
        }
        let data_count = config
            .members
            .iter()
            .filter(|member| member.role == "data")
            .count();
        let witness_count = config
            .members
            .iter()
            .filter(|member| member.role == "witness")
            .count();
        if data_count != 2
            || witness_count != 1
            || config
                .members
                .iter()
                .any(|member| member.role != "data" && member.role != "witness")
        {
            return Err(ConfigError::InvalidTopology);
        }
        let member_ids: BTreeSet<_> = config
            .members
            .iter()
            .map(|member| member.id.as_str())
            .collect();
        let member_addresses: BTreeSet<_> =
            config.members.iter().map(|member| member.address).collect();
        let member_key_ids: BTreeSet<_> = config
            .members
            .iter()
            .map(|member| member.key_id.as_str())
            .collect();
        let member_public_keys: BTreeSet<_> = config
            .members
            .iter()
            .map(|member| member.public_key.as_path())
            .collect();
        if member_ids.len() != config.members.len()
            || member_addresses.len() != config.members.len()
            || member_key_ids.len() != config.members.len()
            || member_public_keys.len() != config.members.len()
            || config.members.iter().any(|member| {
                !valid_identifier(&member.id)
                    || !valid_identifier(&member.key_id)
                    || !member.public_key.is_absolute()
            })
        {
            return Err(ConfigError::InvalidTopology);
        }
        let Some(local) = config
            .members
            .iter()
            .find(|member| member.id == config.node_id)
        else {
            return Err(ConfigError::LocalIdentityMismatch);
        };
        if local.role != config.role
            || local.address != config.listen
            || local.key_id != config.key_id
        {
            return Err(ConfigError::LocalIdentityMismatch);
        }
        let Some(witness_member) = config
            .members
            .iter()
            .find(|member| member.role == "witness")
        else {
            return Err(ConfigError::InvalidTopology);
        };
        if witness_member.address != config.witness {
            return Err(ConfigError::WitnessEndpointMismatch);
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
            .map(|member| canonical_ip(member.address.ip()))
            .collect();
        if data_hosts.len() != data_count {
            return Err(ConfigError::InvalidTopology);
        }
        if data_hosts.contains(&canonical_ip(config.witness.ip())) {
            return Err(ConfigError::WitnessFailureDomainNotIndependent);
        }
        let reserved_witness = IpAddr::V4(Ipv4Addr::new(172, 30, 1, 84));
        if canonical_ip(config.witness.ip()) == reserved_witness
            || config.members.iter().any(|member| {
                member.role == "witness" && canonical_ip(member.address.ip()) == reserved_witness
            })
        {
            return Err(ConfigError::ReservedWitnessHost);
        }

        Ok(config)
    }

    /// Verifies local store and private-key prerequisites without reading key material.
    pub fn verify_local_prerequisites(&self) -> Result<(), ConfigError> {
        let store = std::fs::symlink_metadata(&self.store_dir)
            .map_err(|_error| ConfigError::StoreUnavailable)?;
        if !store.file_type().is_dir()
            || store.file_type().is_symlink()
            || store.permissions().mode() & 0o077 != 0
        {
            return Err(ConfigError::StoreUnavailable);
        }

        let mut key = OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&self.signing_key)
            .map_err(|_error| ConfigError::SigningKeyUnavailable)?;
        let metadata = key
            .metadata()
            .map_err(|_error| ConfigError::SigningKeyUnavailable)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::SigningKeyUnavailable);
        }
        let mut seed = [0_u8; 33];
        let read = key
            .read(&mut seed)
            .map_err(|_error| ConfigError::SigningKeyUnavailable)?;
        if read != 32 || seed[..32].iter().all(|byte| *byte == 0) {
            return Err(ConfigError::SigningKeyUnavailable);
        }
        let extra = key
            .read(&mut seed[32..])
            .map_err(|_error| ConfigError::SigningKeyUnavailable)?;
        if extra != 0 {
            return Err(ConfigError::SigningKeyUnavailable);
        }
        Ok(())
    }

    /// Acquires an exclusive process lock on the local store directory.
    pub fn acquire_store_lock(&self) -> Result<StoreLock, ConfigError> {
        self.verify_local_prerequisites()?;
        let path = self.store_dir.join(".quorumarc.owner");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|_error| ConfigError::OwnerLockRefused)?;
        let metadata = file
            .metadata()
            .map_err(|_error| ConfigError::OwnerLockRefused)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::OwnerLockRefused);
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_error| ConfigError::OwnerLockRefused)?;
        file.set_len(0)
            .and_then(|()| write!(file, "role={} pid={}", self.role, std::process::id()))
            .and_then(|()| file.sync_all())
            .map_err(|_error| ConfigError::OwnerLockRefused)?;
        Ok(StoreLock { _file: file })
    }

    /// Reloads only non-safety fields after a complete re-parse.
    pub fn reload(&self, text: &str) -> Result<Self, ConfigError> {
        let candidate = Self::parse(text)?;
        let mut comparable = candidate.clone();
        comparable.log_level = self.log_level.clone();
        if comparable != *self {
            return Err(ConfigError::UnsafeReload);
        }
        Ok(candidate)
    }

    /// Cluster identity.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// Local node identity.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Protected workload identity.
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// Local application signing seed path.
    #[must_use]
    pub fn signing_key(&self) -> &std::path::Path {
        &self.signing_key
    }

    /// Local declared role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        decode_policy_hash(&self.policy_hash).unwrap_or([0; 32])
    }

    #[must_use]
    pub const fn max_lease_duration_ms(&self) -> u64 {
        self.max_lease_duration_ms
    }

    /// Local durable store directory.
    #[must_use]
    pub fn store_dir(&self) -> &std::path::Path {
        &self.store_dir
    }

    #[must_use]
    pub fn store_id(&self) -> [u8; 16] {
        decode_hex::<16>(&self.store_id).unwrap_or([0; 16])
    }

    /// Static membership.
    #[must_use]
    pub fn members(&self) -> &[MemberConfig] {
        &self.members
    }

    /// Local TLS certificate chain path.
    #[must_use]
    pub fn tls_certificate_chain(&self) -> &std::path::Path {
        &self.tls.certificate_chain
    }

    /// Local TLS private key path.
    #[must_use]
    pub fn tls_private_key(&self) -> &std::path::Path {
        &self.tls.private_key
    }

    /// Trusted peer root certificate bundle path.
    #[must_use]
    pub fn tls_trusted_roots(&self) -> &std::path::Path {
        &self.tls.trusted_roots
    }

    /// Expected DNS identity of the Witness server.
    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        &self.tls.server_name
    }

    #[must_use]
    pub const fn tls_io_timeout_ms(&self) -> u64 {
        self.tls.io_timeout_ms
    }

    /// Whether automatic promotion is requested after fence eligibility.
    #[must_use]
    pub const fn automatic_promotion(&self) -> bool {
        self.automatic_promotion
    }

    /// Operational log verbosity. Changing this never opens effects.
    #[must_use]
    pub fn log_level(&self) -> &str {
        &self.log_level
    }

    /// Configured authoritative fence mechanism.
    #[must_use]
    pub fn fence_mechanism(&self) -> &str {
        &self.fence.mechanism
    }

    /// Configured fence profile identity.
    #[must_use]
    pub fn fence_profile(&self) -> &str {
        &self.fence.profile
    }

    /// Whether independent fence read-back is required.
    #[must_use]
    pub const fn fence_read_back(&self) -> bool {
        self.fence.read_back
    }

    #[must_use]
    pub fn effect_vip(&self) -> &str {
        &self.effect.vip
    }

    #[must_use]
    pub fn effect_interface(&self) -> &str {
        &self.effect.interface
    }

    /// External effects remain closed until later milestones.
    #[must_use]
    pub const fn effect_gate_state(&self) -> &'static str {
        "closed"
    }
}

/// Exclusive store ownership released when dropped.
#[derive(Debug)]
pub struct StoreLock {
    _file: File,
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn valid_effect_vip(value: &str) -> bool {
    let Some((address, prefix)) = value.rsplit_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn decode_policy_hash(value: &str) -> Option<[u8; 32]> {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2) || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2])?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    if decoded.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
