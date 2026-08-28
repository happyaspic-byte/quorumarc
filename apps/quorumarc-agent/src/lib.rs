//! Safe-default Gate 1A laboratory node command line.
//!
//! This binary can inspect durable authority state and signed promotion
//! envelopes, but inspection never grants authority. The current laboratory
//! agent intentionally has no adapter capable of opening external effects.
//! `run` remains fail-closed after successful consistency inspection because
//! trusted time, fencing, lease activation, and an enforced EffectGate control
//! plane are not implemented by this laboratory binary.

#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use quorumarc_store::{
    AuthoritySnapshot, AuthorityState, Corruption, StoreIdentity, StorePaths, StoreRole,
};
use quorumarc_wire::{
    CanonicalId, MAX_SIGNED_ENVELOPE_SIZE, SignedPromotionEnvelope, VerificationKeyResolver,
    VerifyingKey,
};

const EXIT_NOT_READY: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_DATA: u8 = 65;
const EXIT_MISSING: u8 = 66;
const EXIT_IO: u8 = 74;
const EXIT_CONFIG: u8 = 78;
const MAX_CONFIG_SIZE: usize = 65_536;
const MAX_STORE_SNAPSHOT_SIZE: usize = 1_048_576;

/// Captured command output and its portable process exit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliReport {
    stdout: Vec<String>,
    stderr: Vec<String>,
    exit_code: u8,
}

impl CliReport {
    /// Structured standard-output records.
    #[must_use]
    pub fn stdout(&self) -> &[String] {
        &self.stdout
    }

    /// Structured refusal and usage records.
    #[must_use]
    pub fn stderr(&self) -> &[String] {
        &self.stderr
    }

    /// Zero on a successful safe operation, non-zero on a refusal or error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_code
    }

    fn output(line: String) -> Self {
        Self {
            stdout: vec![line],
            stderr: Vec::new(),
            exit_code: 0,
        }
    }

    fn diagnostic(line: String, code: u8) -> Self {
        Self {
            stdout: vec![line],
            stderr: Vec::new(),
            exit_code: code,
        }
    }

    fn refusal(
        event: &'static str,
        reason: &'static str,
        detail: impl Into<String>,
        code: u8,
    ) -> Self {
        let fields = [
            ("event", event.to_owned()),
            ("status", "refused".to_owned()),
            ("reason_code", reason.to_owned()),
            ("effect_gate", "closed".to_owned()),
            ("authority", "denied".to_owned()),
            ("detail", detail.into()),
        ];
        Self {
            stdout: Vec::new(),
            stderr: vec![json_record(&fields)],
            exit_code: code,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Command {
    Status { config: Option<PathBuf> },
    Run(RunOptions),
    Health { config: Option<PathBuf> },
    ValidateConfig { config: Option<PathBuf> },
    Daemon(DaemonOptions),
    ExportSupportBundle { config: Option<PathBuf> },
    InspectProof(ProofOptions),
    InspectStore { store: PathBuf },
    SimulateFailure { scenario: Scenario, seed: u64 },
    Help,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RunOptions {
    config: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DaemonOptions {
    config: Option<PathBuf>,
    status_socket: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ProofOptions {
    proof: Option<PathBuf>,
    keys: Vec<KeyEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    ClockRollback,
    Duplicate,
    Delay,
    Partition,
    Reorder,
    StoreError,
}

impl Scenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "clock-rollback" => Some(Self::ClockRollback),
            "duplicate" => Some(Self::Duplicate),
            "delay" => Some(Self::Delay),
            "partition" => Some(Self::Partition),
            "reorder" => Some(Self::Reorder),
            "store-error" => Some(Self::StoreError),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ClockRollback => "clock-rollback",
            Self::Duplicate => "duplicate",
            Self::Delay => "delay",
            Self::Partition => "partition",
            Self::Reorder => "reorder",
            Self::StoreError => "store-error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeRole {
    Data,
    Witness,
}

impl NodeRole {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "data" => Some(Self::Data),
            "witness" => Some(Self::Witness),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Witness => "witness",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentConfig {
    node_id: CanonicalId,
    workload_id: CanonicalId,
    role: NodeRole,
    store_dir: Option<PathBuf>,
    proof_path: Option<PathBuf>,
    automatic_promotion: bool,
    keys: Vec<KeyEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyEntry {
    principal: CanonicalId,
    key_id: CanonicalId,
    key: VerifyingKey,
}

#[derive(Clone, Debug, Default)]
struct KeyResolver {
    entries: Vec<KeyEntry>,
}

impl VerificationKeyResolver for KeyResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        self.entries
            .iter()
            .find(|entry| entry.principal == *principal && entry.key_id == *key_id)
            .map(|entry| entry.key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Failure {
    reason: &'static str,
    detail: String,
    exit_code: u8,
}

impl Failure {
    fn new(reason: &'static str, detail: impl Into<String>, exit_code: u8) -> Self {
        Self {
            reason,
            detail: detail.into(),
            exit_code,
        }
    }
}

/// Parses and executes one agent invocation. Arguments exclude the program name.
#[must_use]
pub fn execute<I, S>(arguments: I) -> CliReport
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let command = match parse_command(&arguments) {
        Ok(command) => command,
        Err(failure) => {
            return CliReport::refusal(
                "command",
                failure.reason,
                failure.detail,
                failure.exit_code,
            );
        }
    };
    match command {
        Command::Status { config } => status(config.as_deref()),
        Command::Run(options) => run(options),
        Command::Health { config } => health(config.as_deref()),
        Command::ValidateConfig { config } => validate_config(config.as_deref()),
        Command::Daemon(options) => daemon(options),
        Command::ExportSupportBundle { config } => export_support_bundle(config.as_deref()),
        Command::InspectProof(options) => inspect_proof(options),
        Command::InspectStore { store } => inspect_store(&store),
        Command::SimulateFailure { scenario, seed } => simulate_failure(scenario, seed),
        Command::Help => help(),
    }
}

fn parse_command(arguments: &[OsString]) -> Result<Command, Failure> {
    let Some(raw_command) = arguments.first() else {
        return Ok(Command::Status { config: None });
    };
    let command = utf8_argument(raw_command, "command")?;
    let options = &arguments[1..];
    match command {
        "status" => Ok(Command::Status {
            config: parse_single_path_option(options, "--config")?,
        }),
        "run" => parse_run_options(options).map(Command::Run),
        "health" => Ok(Command::Health {
            config: parse_single_path_option(options, "--config")?,
        }),
        "validate-config" => Ok(Command::ValidateConfig {
            config: parse_single_path_option(options, "--config")?,
        }),
        "daemon" => parse_daemon_options(options).map(Command::Daemon),
        "export-support-bundle" => Ok(Command::ExportSupportBundle {
            config: parse_single_path_option(options, "--config")?,
        }),
        "inspect-proof" => parse_proof_options(options).map(Command::InspectProof),
        "inspect-store" => {
            let store = parse_single_path_option(options, "--store")?.ok_or_else(|| {
                Failure::new(
                    "STORE_REQUIRED",
                    "inspect-store requires --store",
                    EXIT_MISSING,
                )
            })?;
            Ok(Command::InspectStore { store })
        }
        "simulate-failure" => parse_simulation_options(options),
        "--help" | "-h" | "help" => {
            if options.is_empty() {
                Ok(Command::Help)
            } else {
                Err(Failure::new(
                    "UNEXPECTED_ARGUMENT",
                    "help takes no arguments",
                    EXIT_USAGE,
                ))
            }
        }
        "activate" | "promote" => Err(Failure::new(
            "DIRECT_ACTIVATION_FORBIDDEN",
            "direct activation bypasses durable proof validation",
            EXIT_CONFIG,
        )),
        _ => Err(Failure::new(
            "UNKNOWN_COMMAND",
            format!("unknown command: {command}"),
            EXIT_USAGE,
        )),
    }
}

fn parse_single_path_option(
    options: &[OsString],
    expected: &'static str,
) -> Result<Option<PathBuf>, Failure> {
    if options.is_empty() {
        return Ok(None);
    }
    if options.len() != 2 || options[0] != OsStr::new(expected) {
        return Err(Failure::new(
            "UNEXPECTED_ARGUMENT",
            format!("only {expected} PATH is accepted"),
            EXIT_USAGE,
        ));
    }
    Ok(Some(nonempty_path(&options[1], expected)?))
}

fn parse_run_options(options: &[OsString]) -> Result<RunOptions, Failure> {
    let mut parsed = RunOptions::default();
    let mut index = 0;
    while index < options.len() {
        let option = utf8_argument(&options[index], "run option")?;
        index = index.saturating_add(1);
        let value = options.get(index).ok_or_else(|| {
            Failure::new(
                "OPTION_VALUE_MISSING",
                format!("{option} requires a value"),
                EXIT_USAGE,
            )
        })?;
        match option {
            "--config" => set_path_once(&mut parsed.config, value, option)?,
            _ => {
                return Err(Failure::new(
                    "UNEXPECTED_ARGUMENT",
                    format!("unknown run option: {option}"),
                    EXIT_USAGE,
                ));
            }
        }
        index = index.saturating_add(1);
    }
    Ok(parsed)
}

fn parse_daemon_options(options: &[OsString]) -> Result<DaemonOptions, Failure> {
    let mut parsed = DaemonOptions::default();
    let mut index = 0;
    while index < options.len() {
        let option = utf8_argument(&options[index], "daemon option")?;
        index = index.saturating_add(1);
        let value = options.get(index).ok_or_else(|| {
            Failure::new(
                "OPTION_VALUE_MISSING",
                format!("{option} requires a value"),
                EXIT_USAGE,
            )
        })?;
        match option {
            "--config" => set_path_once(&mut parsed.config, value, option)?,
            "--status-socket" => set_path_once(&mut parsed.status_socket, value, option)?,
            _ => {
                return Err(Failure::new(
                    "UNEXPECTED_ARGUMENT",
                    format!("unknown daemon option: {option}"),
                    EXIT_USAGE,
                ));
            }
        }
        index = index.saturating_add(1);
    }
    Ok(parsed)
}

fn parse_proof_options(options: &[OsString]) -> Result<ProofOptions, Failure> {
    let mut parsed = ProofOptions::default();
    let mut index = 0;
    while index < options.len() {
        let option = utf8_argument(&options[index], "inspect-proof option")?;
        index = index.saturating_add(1);
        let value = options.get(index).ok_or_else(|| {
            Failure::new(
                "OPTION_VALUE_MISSING",
                format!("{option} requires a value"),
                EXIT_USAGE,
            )
        })?;
        match option {
            "--proof" => set_path_once(&mut parsed.proof, value, option)?,
            "--key" => {
                let entry = parse_key_spec(utf8_argument(value, option)?)?;
                push_unique_key(&mut parsed.keys, entry)?;
            }
            _ => {
                return Err(Failure::new(
                    "UNEXPECTED_ARGUMENT",
                    format!("unknown inspect-proof option: {option}"),
                    EXIT_USAGE,
                ));
            }
        }
        index = index.saturating_add(1);
    }
    Ok(parsed)
}

fn parse_simulation_options(options: &[OsString]) -> Result<Command, Failure> {
    let mut scenario = Scenario::Partition;
    let mut seed = 1_u64;
    let mut saw_scenario = false;
    let mut saw_seed = false;
    let mut index = 0;
    while index < options.len() {
        let option = utf8_argument(&options[index], "simulate-failure option")?;
        index = index.saturating_add(1);
        let value = options.get(index).ok_or_else(|| {
            Failure::new(
                "OPTION_VALUE_MISSING",
                format!("{option} requires a value"),
                EXIT_USAGE,
            )
        })?;
        match option {
            "--scenario" if !saw_scenario => {
                let value = utf8_argument(value, option)?;
                scenario = Scenario::parse(value).ok_or_else(|| {
                    Failure::new(
                        "UNKNOWN_FAILURE_SCENARIO",
                        format!("unsupported failure scenario: {value}"),
                        EXIT_USAGE,
                    )
                })?;
                saw_scenario = true;
            }
            "--seed" if !saw_seed => {
                let value = utf8_argument(value, option)?;
                seed = value.parse::<u64>().map_err(|error| {
                    Failure::new(
                        "INVALID_SEED",
                        format!("seed must be an unsigned integer: {error}"),
                        EXIT_USAGE,
                    )
                })?;
                saw_seed = true;
            }
            "--scenario" | "--seed" => {
                return Err(Failure::new(
                    "DUPLICATE_OPTION",
                    format!("{option} was supplied more than once"),
                    EXIT_USAGE,
                ));
            }
            _ => {
                return Err(Failure::new(
                    "UNEXPECTED_ARGUMENT",
                    format!("unknown simulate-failure option: {option}"),
                    EXIT_USAGE,
                ));
            }
        }
        index = index.saturating_add(1);
    }
    Ok(Command::SimulateFailure { scenario, seed })
}

fn utf8_argument<'a>(argument: &'a OsStr, field: &str) -> Result<&'a str, Failure> {
    argument.to_str().ok_or_else(|| {
        Failure::new(
            "NON_UTF8_ARGUMENT",
            format!("{field} must be valid UTF-8"),
            EXIT_USAGE,
        )
    })
}

fn nonempty_path(argument: &OsStr, option: &str) -> Result<PathBuf, Failure> {
    if argument.is_empty() {
        return Err(Failure::new(
            "EMPTY_PATH",
            format!("{option} path is empty"),
            EXIT_USAGE,
        ));
    }
    Ok(PathBuf::from(argument))
}

fn set_path_once(target: &mut Option<PathBuf>, value: &OsStr, option: &str) -> Result<(), Failure> {
    if target.is_some() {
        return Err(Failure::new(
            "DUPLICATE_OPTION",
            format!("{option} was supplied more than once"),
            EXIT_USAGE,
        ));
    }
    *target = Some(nonempty_path(value, option)?);
    Ok(())
}

fn status(config_path: Option<&Path>) -> CliReport {
    let Some(path) = config_path else {
        let fields = safe_state_fields("status", "safe-default", "CONFIG_MISSING_SAFE_DEFAULT");
        return CliReport::output(json_record(&fields));
    };
    match load_config(path) {
        Ok(config) => {
            let reason = if config.automatic_promotion {
                "CONFIGURED_NOT_AUTHORIZED"
            } else {
                "AUTOMATIC_PROMOTION_DISABLED"
            };
            let fields = [
                ("event", "status".to_owned()),
                ("status", "safe-default".to_owned()),
                ("reason_code", reason.to_owned()),
                ("node_id", config.node_id.as_str().to_owned()),
                ("workload_id", config.workload_id.as_str().to_owned()),
                ("role", config.role.as_str().to_owned()),
                (
                    "automatic_promotion",
                    config.automatic_promotion.to_string(),
                ),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::output(json_record(&fields))
        }
        Err(failure) => {
            let fields = [
                ("event", "status".to_owned()),
                ("status", "safe-degraded".to_owned()),
                ("reason_code", failure.reason.to_owned()),
                ("ready", "false".to_owned()),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
                ("detail", failure.detail),
            ];
            CliReport::output(json_record(&fields))
        }
    }
}

fn health(config_path: Option<&Path>) -> CliReport {
    let Some(path) = config_path else {
        let fields = safe_state_fields("health", "safe-degraded", "CONFIG_MISSING_SAFE_DEFAULT");
        return CliReport::diagnostic(json_record(&fields), EXIT_NOT_READY);
    };
    let config = match load_config(path) {
        Ok(config) => config,
        Err(failure) => {
            let fields = [
                ("event", "health".to_owned()),
                ("status", "safe-degraded".to_owned()),
                ("reason_code", failure.reason.to_owned()),
                ("ready", "false".to_owned()),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
                ("detail", failure.detail),
            ];
            return CliReport::diagnostic(json_record(&fields), EXIT_NOT_READY);
        }
    };
    match inspect_material_consistency(&config) {
        Ok(summary) => {
            let fields = [
                ("event", "health".to_owned()),
                ("status", "safe-degraded".to_owned()),
                (
                    "reason_code",
                    "ACTIVATION_CONTROL_PLANE_UNAVAILABLE".to_owned(),
                ),
                ("node_id", config.node_id.as_str().to_owned()),
                ("epoch", summary.epoch.to_string()),
                ("incarnation", summary.incarnation.to_string()),
                ("ready", "false".to_owned()),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::diagnostic(json_record(&fields), EXIT_NOT_READY)
        }
        Err(failure) => {
            let fields = [
                ("event", "health".to_owned()),
                ("status", "safe-degraded".to_owned()),
                ("reason_code", failure.reason.to_owned()),
                ("node_id", config.node_id.as_str().to_owned()),
                ("ready", "false".to_owned()),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
                ("detail", failure.detail),
            ];
            CliReport::diagnostic(json_record(&fields), EXIT_NOT_READY)
        }
    }
}

fn validate_config(config_path: Option<&Path>) -> CliReport {
    let Some(path) = config_path else {
        return CliReport::refusal(
            "validate-config",
            "CONFIG_REQUIRED",
            "validate-config requires an explicit --config file",
            EXIT_CONFIG,
        );
    };
    let bytes = match read_bounded(path, MAX_CONFIG_SIZE, "CONFIG") {
        Ok(bytes) => bytes,
        Err(failure) => {
            return CliReport::refusal(
                "validate-config",
                failure.reason,
                failure.detail,
                failure.exit_code,
            );
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            return CliReport::refusal(
                "validate-config",
                "CONFIG_INVALID_UTF8",
                error.to_string(),
                EXIT_CONFIG,
            );
        }
    };
    match quorumarc_service::config::ProductionConfig::parse(&text) {
        Ok(config) => {
            let fields = [
                ("event", "validate-config".to_owned()),
                ("status", "valid-effect-closed".to_owned()),
                ("reason_code", "CONFIG_VALID_EFFECT_CLOSED".to_owned()),
                ("cluster_id", config.cluster_id().to_owned()),
                ("members", config.members().len().to_string()),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::output(json_record(&fields))
        }
        Err(error) => CliReport::refusal(
            "validate-config",
            error.reason_code(),
            format!("{error:?}"),
            EXIT_CONFIG,
        ),
    }
}

fn daemon(options: DaemonOptions) -> CliReport {
    let Some(path) = options.config.as_deref() else {
        return CliReport::refusal(
            "daemon",
            "CONFIG_REQUIRED",
            "daemon requires an explicit --config file",
            EXIT_CONFIG,
        );
    };
    let bytes = match read_bounded(path, MAX_CONFIG_SIZE, "CONFIG") {
        Ok(bytes) => bytes,
        Err(failure) => {
            return CliReport::refusal("daemon", failure.reason, failure.detail, failure.exit_code);
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            return CliReport::refusal(
                "daemon",
                "CONFIG_INVALID_UTF8",
                error.to_string(),
                EXIT_CONFIG,
            );
        }
    };
    match quorumarc_service::config::ProductionConfig::parse(&text) {
        Ok(config) => {
            if config.role() != "data" {
                return CliReport::refusal(
                    "daemon",
                    "AGENT_ROLE_MISMATCH",
                    "agent daemon requires local role=data",
                    EXIT_CONFIG,
                );
            }
            let _store_lock = match config.acquire_store_lock() {
                Ok(lock) => lock,
                Err(error) => {
                    return CliReport::refusal(
                        "daemon",
                        error.reason_code(),
                        "local store ownership or signing key prerequisites are unavailable",
                        EXIT_CONFIG,
                    );
                }
            };
            let candidate_control =
                match quorumarc_service::witness_client::ProductionCandidateControl::from_config(
                    &config,
                ) {
                    Ok(control) => control,
                    Err(error) => {
                        let reason = match error {
                        quorumarc_service::witness_client::CandidateControlError::KeyMaterial => {
                            "CANDIDATE_KEY_MATERIAL_INVALID"
                        }
                        _ => "WITNESS_CONFIG_INVALID",
                    };
                        return CliReport::refusal(
                            "daemon",
                            reason,
                            "candidate key material or declared Witness configuration is invalid",
                            EXIT_CONFIG,
                        );
                    }
                };
            let clock = match quorumarc_service::clock::BootClock::open_system() {
                Ok(clock) => clock,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "BOOT_CLOCK_UNAVAILABLE",
                        "cannot bind CLOCK_BOOTTIME to kernel boot identity",
                        EXIT_CONFIG,
                    );
                }
            };
            if let Err(error) = clock.bind_store(config.store_dir()) {
                let reason = match error {
                    quorumarc_service::clock::BootClockError::BootChanged => {
                        "BOOT_IDENTITY_CHANGED"
                    }
                    _ => "BOOT_CLOCK_UNAVAILABLE",
                };
                return CliReport::refusal(
                    "daemon",
                    reason,
                    "stored boot identity disagrees with the current kernel boot",
                    EXIT_CONFIG,
                );
            }
            let boot_id = clock.boot_id().to_owned();
            let status = quorumarc_service::operations::StatusHandle::new(
                quorumarc_service::operations::NodeStatusReport::new(
                    &config,
                    &boot_id,
                    clock.now_ms(),
                    None,
                ),
            );
            let backend = match quorumarc_service::linux_vip::NetlinkVipBackend::connect() {
                Ok(backend) => backend,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "EFFECT_ADAPTER_UNAVAILABLE",
                        "cannot connect the production Netlink VIP adapter",
                        EXIT_CONFIG,
                    );
                }
            };
            let mut adapter = match quorumarc_service::linux_vip::LinuxVipEffectAdapter::new(
                config.workload_id(),
                config.node_id(),
                config.effect_vip(),
                config.effect_interface(),
                backend,
            ) {
                Ok(adapter) => adapter,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "EFFECT_ADAPTER_CONFIG_INVALID",
                        "cannot bind the configured Linux VIP target",
                        EXIT_CONFIG,
                    );
                }
            };
            if adapter.verify_kernel_closed().is_err() {
                return CliReport::refusal(
                    "daemon",
                    "EFFECT_ADAPTER_NOT_CLOSED",
                    "configured VIP is already present or could not be verified absent",
                    EXIT_CONFIG,
                );
            }
            let mut node =
                match quorumarc_service::node::ProductionNode::from_effect_adapter(adapter) {
                    Ok(node) => node,
                    Err(_error) => {
                        return CliReport::refusal(
                            "daemon",
                            "EFFECT_ADAPTER_NOT_CLOSED",
                            "production effect adapter did not verify closed",
                            EXIT_CONFIG,
                        );
                    }
                };
            let shutdown = quorumarc_service::signal::ShutdownToken::new();
            let reload = shutdown.reload_token();
            let _signal_guard = match shutdown.register_process_signals() {
                Ok(guard) => guard,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "SIGNAL_HANDLER_REGISTRATION_FAILED",
                        "cannot install SIGHUP/SIGTERM/SIGINT handlers",
                        EXIT_CONFIG,
                    );
                }
            };
            let status_server = match options.status_socket.as_deref() {
                Some(socket) => {
                    match quorumarc_service::operations::LocalStatusServer::bind_shared(
                        socket,
                        status.clone(),
                    ) {
                        Ok(server) => Some(server),
                        Err(_error) => {
                            return CliReport::refusal(
                                "daemon",
                                "STATUS_SOCKET_BIND_FAILED",
                                "cannot bind a new read-only status socket",
                                EXIT_CONFIG,
                            );
                        }
                    }
                }
                None => None,
            };
            let watchdog =
                match quorumarc_service::watchdog::SystemdWatchdog::from_environment_variables(
                    std::env::var("NOTIFY_SOCKET").ok().as_deref(),
                    std::env::var("WATCHDOG_USEC").ok().as_deref(),
                ) {
                    Ok(watchdog) => watchdog,
                    Err(_error) => {
                        return CliReport::refusal(
                            "daemon",
                            "WATCHDOG_CONFIGURATION_INVALID",
                            "cannot configure fail-closed systemd watchdog pings",
                            EXIT_CONFIG,
                        );
                    }
                };
            let config_path = path.to_path_buf();
            let reload_status = status.clone();
            let reload_worker = match std::thread::Builder::new()
                .name("quorumarc-agent-reload".to_owned())
                .spawn(move || {
                    quorumarc_service::reload::run_reload_loop(
                        &config_path,
                        config,
                        "data",
                        &reload_status,
                        &boot_id,
                        || clock.now_ms(),
                        &reload,
                    );
                }) {
                Ok(worker) => worker,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "RELOAD_WORKER_START_FAILED",
                        "cannot start fail-closed configuration reload worker",
                        EXIT_CONFIG,
                    );
                }
            };
            let status_worker = match status_server {
                Some(server) => {
                    let worker_shutdown = shutdown.clone();
                    match std::thread::Builder::new()
                        .name("quorumarc-agent-status".to_owned())
                        .spawn(move || server.serve_until(&worker_shutdown))
                    {
                        Ok(worker) => Some(worker),
                        Err(_error) => {
                            shutdown.request();
                            let _ = reload_worker.join();
                            return CliReport::refusal(
                                "daemon",
                                "STATUS_WORKER_START_FAILED",
                                "cannot start read-only status worker",
                                EXIT_CONFIG,
                            );
                        }
                    }
                }
                None => None,
            };
            let watchdog_worker = match watchdog {
                Some(watchdog) => {
                    let worker_shutdown = shutdown.clone();
                    match std::thread::Builder::new()
                        .name("quorumarc-agent-watchdog".to_owned())
                        .spawn(move || watchdog.run_until(&worker_shutdown))
                    {
                        Ok(worker) => Some(worker),
                        Err(_error) => {
                            shutdown.request();
                            if let Some(worker) = status_worker {
                                let _ = worker.join();
                            }
                            let _ = reload_worker.join();
                            return CliReport::refusal(
                                "daemon",
                                "WATCHDOG_WORKER_START_FAILED",
                                "cannot start fail-closed watchdog worker",
                                EXIT_CONFIG,
                            );
                        }
                    }
                }
                None => None,
            };
            let candidate_status = status.clone();
            let candidate_shutdown = shutdown.clone();
            let (suspicion_sender, suspicion_receiver) = std::sync::mpsc::sync_channel::<(
                quorumarc_service::candidate_loop::CandidateFailure,
                quorumarc_service::protocol::ProductionRequest,
            )>(16);
            let _suspicion_trigger = suspicion_sender;
            let candidate_worker = match std::thread::Builder::new()
                .name("quorumarc-agent-candidate".to_owned())
                .spawn(move || {
                    let mut candidate =
                        quorumarc_service::candidate_loop::CandidateControlLoop::with_status(
                            candidate_control,
                            candidate_status,
                        );
                    while !candidate_shutdown.is_requested() {
                        match suspicion_receiver.recv_timeout(std::time::Duration::from_millis(100))
                        {
                            Ok((failure, request)) => {
                                let _ =
                                    candidate.run_bounded(failure, request, &candidate_shutdown);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                candidate.wait_until_shutdown(&candidate_shutdown);
                                break;
                            }
                        }
                    }
                    candidate.wait_until_shutdown(&candidate_shutdown);
                }) {
                Ok(worker) => worker,
                Err(_error) => {
                    shutdown.request();
                    if let Some(worker) = status_worker {
                        let _ = worker.join();
                    }
                    if let Some(worker) = watchdog_worker {
                        let _ = worker.join();
                    }
                    let _ = reload_worker.join();
                    return CliReport::refusal(
                        "daemon",
                        "CANDIDATE_WORKER_START_FAILED",
                        "cannot start bounded candidate control worker",
                        EXIT_CONFIG,
                    );
                }
            };
            let report = node.run_until_shutdown(&shutdown);
            let _ = candidate_worker.join();
            if let Some(worker) = status_worker {
                let _ = worker.join();
            }
            if let Some(worker) = watchdog_worker {
                let _ = worker.join();
            }
            let _ = reload_worker.join();
            let report = match report {
                Ok(report) => report,
                Err(_error) => {
                    return CliReport::refusal(
                        "daemon",
                        "EFFECT_ADAPTER_CLOSE_UNVERIFIED",
                        "shutdown could not verify that the production VIP is absent",
                        EXIT_IO,
                    );
                }
            };
            let fields = [
                ("event", "daemon".to_owned()),
                ("status", "stopped-effect-closed".to_owned()),
                ("reason_code", "DAEMON_STOPPED_EFFECT_CLOSED".to_owned()),
                ("initial", format!("{:?}", report.initial)),
                ("final_state", format!("{:?}", report.final_state)),
                ("ever_authority_ready", report.ever_ready.to_string()),
                ("effect_gate", node.effect_gate_state().to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::output(json_record(&fields))
        }
        Err(error) => CliReport::refusal(
            "daemon",
            error.reason_code(),
            format!("{error:?}"),
            EXIT_CONFIG,
        ),
    }
}

fn export_support_bundle(config_path: Option<&Path>) -> CliReport {
    let Some(path) = config_path else {
        return CliReport::refusal(
            "export-support-bundle",
            "CONFIG_REQUIRED",
            "export-support-bundle requires an explicit --config file",
            EXIT_CONFIG,
        );
    };
    let bytes = match read_bounded(path, MAX_CONFIG_SIZE, "CONFIG") {
        Ok(bytes) => bytes,
        Err(failure) => {
            return CliReport::refusal(
                "export-support-bundle",
                failure.reason,
                failure.detail,
                failure.exit_code,
            );
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            return CliReport::refusal(
                "export-support-bundle",
                "CONFIG_INVALID_UTF8",
                error.to_string(),
                EXIT_CONFIG,
            );
        }
    };
    match quorumarc_service::config::ProductionConfig::parse(&text) {
        Ok(config) => {
            let (boot_id, uptime_ms) = match quorumarc_service::clock::BootClock::open_system() {
                Ok(clock) => (clock.boot_id().to_owned(), clock.now_ms()),
                Err(_error) => {
                    return CliReport::refusal(
                        "export-support-bundle",
                        "BOOT_CLOCK_UNAVAILABLE",
                        "cannot bind CLOCK_BOOTTIME to kernel boot identity",
                        EXIT_CONFIG,
                    );
                }
            };
            let bundle = quorumarc_service::operations::export_support_bundle(
                &config, boot_id, uptime_ms, None,
            );
            let fields = [
                ("event", "export-support-bundle".to_owned()),
                ("status", "exported-redacted".to_owned()),
                ("reason_code", "SUPPORT_BUNDLE_REDACTED".to_owned()),
                ("cluster_id", bundle.cluster_id().to_owned()),
                ("members", bundle.members_count().to_string()),
                ("manifest", bundle.manifest_json().to_owned()),
                ("digest", hex_encode(&bundle.bundle_digest())),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::output(json_record(&fields))
        }
        Err(error) => CliReport::refusal(
            "export-support-bundle",
            error.reason_code(),
            format!("{error:?}"),
            EXIT_CONFIG,
        ),
    }
}

fn run(options: RunOptions) -> CliReport {
    let Some(config_path) = options.config.as_deref() else {
        return CliReport::refusal(
            "run",
            "CONFIG_REQUIRED",
            "run requires an explicit --config file",
            EXIT_CONFIG,
        );
    };
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(failure) => {
            return CliReport::refusal("run", failure.reason, failure.detail, failure.exit_code);
        }
    };
    if config.role != NodeRole::Data {
        return CliReport::refusal(
            "run",
            "WITNESS_ROLE_FORBIDDEN",
            "the node agent cannot run a witness workload or become a candidate",
            EXIT_CONFIG,
        );
    }
    let summary = match inspect_material_consistency(&config) {
        Ok(summary) => summary,
        Err(failure) => {
            return CliReport::refusal("run", failure.reason, failure.detail, failure.exit_code);
        }
    };
    let promotion_mode = if config.automatic_promotion {
        "enabled-in-config"
    } else {
        "disabled-in-config"
    };
    CliReport::refusal(
        "run",
        "ACTIVATION_CONTROL_PLANE_UNAVAILABLE",
        format!(
            "material inspection passed for epoch {} incarnation {} commit {}, including proposal and final envelope digests; automatic promotion is {promotion_mode}, but trusted time, fencing, lease activation, and an enforced EffectGate control plane are unavailable",
            summary.epoch, summary.incarnation, summary.commit_index
        ),
        EXIT_CONFIG,
    )
}

fn inspect_proof(options: ProofOptions) -> CliReport {
    let Some(path) = options.proof.as_deref() else {
        return CliReport::refusal(
            "inspect-proof",
            "PROOF_REQUIRED",
            "inspect-proof requires --proof",
            EXIT_MISSING,
        );
    };
    let signed = match read_signed_proof(path) {
        Ok(signed) => signed,
        Err(failure) => {
            return CliReport::refusal(
                "inspect-proof",
                failure.reason,
                failure.detail,
                failure.exit_code,
            );
        }
    };
    let digest = match signed.digest() {
        Ok(digest) => digest,
        Err(error) => {
            return CliReport::refusal(
                "inspect-proof",
                "PROOF_DIGEST_FAILED",
                error.to_string(),
                EXIT_DATA,
            );
        }
    };
    let envelope = signed.envelope();
    let (status, reason, verification) = if options.keys.is_empty() {
        (
            "structurally-valid-untrusted",
            "KEY_RESOLVER_MISSING",
            "not-performed",
        )
    } else {
        let resolver = KeyResolver {
            entries: options.keys,
        };
        if let Err(error) = signed.verify(&resolver) {
            return CliReport::refusal(
                "inspect-proof",
                "PROOF_SIGNATURE_INVALID",
                error.to_string(),
                EXIT_DATA,
            );
        }
        ("verified-for-inspection", "INSPECTION_ONLY", "verified")
    };
    let fields = [
        ("event", "inspect-proof".to_owned()),
        ("status", status.to_owned()),
        ("reason_code", reason.to_owned()),
        ("signature_verification", verification.to_owned()),
        ("candidate", envelope.candidate_node_id.as_str().to_owned()),
        ("workload_id", envelope.workload_id.as_str().to_owned()),
        ("epoch", envelope.epoch.to_string()),
        ("incarnation", envelope.candidate_incarnation.to_string()),
        ("required_commit", envelope.required_commit.to_string()),
        ("durable_commit", envelope.durable_commit.to_string()),
        ("digest", hex_encode(&digest)),
        ("effect_gate", "closed".to_owned()),
        ("authority", "denied".to_owned()),
    ];
    CliReport::output(json_record(&fields))
}

fn inspect_store(path: &Path) -> CliReport {
    match recover_store_snapshot(path) {
        Ok(recovered) => {
            let state = &recovered.state;
            let vote_epoch = state
                .last_vote()
                .map_or_else(|| "none".to_owned(), |vote| vote.epoch().to_string());
            let promotion_epoch = state.last_promotion().map_or_else(
                || "none".to_owned(),
                |promotion| promotion.epoch().to_string(),
            );
            let state_root = state
                .state_root()
                .map_or_else(|| "none".to_owned(), |root| hex_encode(root.as_bytes()));
            let fields = [
                ("event", "inspect-store".to_owned()),
                ("status", "recovered-safe-view".to_owned()),
                ("reason_code", "STORE_RECOVERED".to_owned()),
                ("cluster_id", recovered.identity.cluster_id().to_owned()),
                ("workload_id", recovered.identity.workload_id().to_owned()),
                ("node_id", recovered.identity.node_id().to_owned()),
                ("store_role", recovered.identity.role().to_string()),
                ("store_id", hex_encode(recovered.identity.store_id())),
                ("generation", recovered.generation.to_string()),
                ("highest_epoch", state.highest_epoch().to_string()),
                ("incarnation", state.incarnation().to_string()),
                ("commit_index", state.commit_index().to_string()),
                ("state_root", state_root),
                ("last_vote_epoch", vote_epoch),
                ("last_promotion_epoch", promotion_epoch),
                (
                    "activation_receipt",
                    if state.activation_receipt().is_some() {
                        "present"
                    } else {
                        "none"
                    }
                    .to_owned(),
                ),
                ("effect_gate", "closed".to_owned()),
                ("authority", "denied".to_owned()),
            ];
            CliReport::output(json_record(&fields))
        }
        Err(failure) => CliReport::refusal(
            "inspect-store",
            failure.reason,
            failure.detail,
            failure.exit_code,
        ),
    }
}

fn simulate_failure(scenario: Scenario, seed: u64) -> CliReport {
    let trace = deterministic_trace(seed, scenario);
    let fields = [
        ("event", "simulate-failure".to_owned()),
        ("status", "simulated".to_owned()),
        ("reason_code", "SIMULATION_NO_EFFECTS".to_owned()),
        ("scope", "lab-only".to_owned()),
        ("scenario", scenario.as_str().to_owned()),
        ("seed", seed.to_string()),
        ("trace", format!("{trace:016x}")),
        ("effect_gate", "closed".to_owned()),
        ("authority", "denied".to_owned()),
    ];
    CliReport::output(json_record(&fields))
}

fn help() -> CliReport {
    let fields = [
        ("event", "help".to_owned()),
        ("status", "ok".to_owned()),
        (
            "usage",
            "quorumarc-agent <status|run|health|validate-config|daemon|export-support-bundle|inspect-proof|inspect-store|simulate-failure> [--config PATH] [--status-socket PATH] [options]"
                .to_owned(),
        ),
        ("effect_gate", "closed".to_owned()),
    ];
    CliReport::output(json_record(&fields))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaterialSummary {
    epoch: u64,
    incarnation: u64,
    commit_index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveredAuthority {
    identity: StoreIdentity,
    state: AuthorityState,
    generation: u64,
}

fn inspect_material_consistency(config: &AgentConfig) -> Result<MaterialSummary, Failure> {
    let store_path = config.store_dir.as_deref().ok_or_else(|| {
        Failure::new(
            "STORE_REQUIRED",
            "no durable store is configured",
            EXIT_CONFIG,
        )
    })?;
    let proof_path = config.proof_path.as_deref().ok_or_else(|| {
        Failure::new(
            "PROOF_REQUIRED",
            "no promotion proof is configured",
            EXIT_CONFIG,
        )
    })?;
    let recovered = recover_store_snapshot(store_path)?;
    if recovered.identity.role() != StoreRole::DataNode {
        return Err(Failure::new(
            "STORE_ROLE_MISMATCH",
            "durable store identity is not a data-node store",
            EXIT_DATA,
        ));
    }
    if recovered.identity.node_id() != config.node_id.as_str() {
        return Err(Failure::new(
            "STORE_NODE_MISMATCH",
            "durable store identity does not match the configured node",
            EXIT_DATA,
        ));
    }
    if recovered.identity.workload_id() != config.workload_id.as_str() {
        return Err(Failure::new(
            "STORE_WORKLOAD_MISMATCH",
            "durable store identity does not match the configured workload",
            EXIT_DATA,
        ));
    }
    let signed = read_signed_proof(proof_path)?;
    if config.keys.is_empty() {
        return Err(Failure::new(
            "KEY_RESOLVER_REQUIRED",
            "signed proof verification requires configured public keys",
            EXIT_CONFIG,
        ));
    }
    let resolver = KeyResolver {
        entries: config.keys.clone(),
    };
    signed
        .verify(&resolver)
        .map_err(|error| Failure::new("PROOF_SIGNATURE_INVALID", error.to_string(), EXIT_DATA))?;
    let envelope = signed.envelope();
    if envelope.candidate_node_id != config.node_id {
        return Err(Failure::new(
            "CANDIDATE_NODE_MISMATCH",
            "proof candidate does not match the configured node",
            EXIT_DATA,
        ));
    }
    if envelope.workload_id != config.workload_id {
        return Err(Failure::new(
            "WORKLOAD_MISMATCH",
            "proof workload does not match the configured workload",
            EXIT_DATA,
        ));
    }
    let state = &recovered.state;
    if state.incarnation() != envelope.candidate_incarnation {
        return Err(Failure::new(
            "INCARNATION_MISMATCH",
            "durable incarnation does not match the proof",
            EXIT_DATA,
        ));
    }
    if state.highest_epoch() != envelope.epoch {
        return Err(Failure::new(
            "EPOCH_MISMATCH",
            "highest durable epoch does not match the proof",
            EXIT_DATA,
        ));
    }
    let vote = state.last_vote().ok_or_else(|| {
        Failure::new(
            "DURABLE_VOTE_MISSING",
            "store has no vote for the inspected promotion",
            EXIT_DATA,
        )
    })?;
    if vote.epoch() != envelope.epoch || vote.candidate() != envelope.candidate_node_id.as_str() {
        return Err(Failure::new(
            "DURABLE_VOTE_MISMATCH",
            "durable vote epoch or candidate does not match the proof",
            EXIT_DATA,
        ));
    }
    let promotion = state.last_promotion().ok_or_else(|| {
        Failure::new(
            "DURABLE_PROMOTION_MISSING",
            "store has no matching durable promotion",
            EXIT_DATA,
        )
    })?;
    if promotion.epoch() != envelope.epoch
        || promotion.lease().not_before_ms() != envelope.lease.not_before_ms
        || promotion.lease().expires_at_ms() != envelope.lease.expires_at_ms
        || promotion.commit_index() != envelope.durable_commit
        || promotion.state_root().as_bytes() != &envelope.state_root
    {
        return Err(Failure::new(
            "DURABLE_PROMOTION_MISMATCH",
            "durable promotion epoch, lease, commit, or state root does not match the proof",
            EXIT_DATA,
        ));
    }
    if state.commit_index() != envelope.durable_commit
        || state.state_root().map(|root| *root.as_bytes()) != Some(envelope.state_root)
    {
        return Err(Failure::new(
            "DURABLE_STATE_MISMATCH",
            "durable commit index or state root does not match the proof",
            EXIT_DATA,
        ));
    }
    let proposal_digest = envelope
        .quorum_certificate
        .binding
        .proposal_digest()
        .map_err(|error| Failure::new("PROPOSAL_DIGEST_FAILED", error.to_string(), EXIT_DATA))?;
    let final_digest = signed
        .digest()
        .map_err(|error| Failure::new("PROOF_DIGEST_FAILED", error.to_string(), EXIT_DATA))?;
    verify_material_digests(
        vote.proposal_digest(),
        promotion.proposal_digest(),
        promotion.signed_envelope_digest(),
        &proposal_digest,
        &final_digest,
    )?;
    Ok(MaterialSummary {
        epoch: envelope.epoch,
        incarnation: envelope.candidate_incarnation,
        commit_index: envelope.durable_commit,
    })
}

fn verify_material_digests(
    durable_vote_proposal: &[u8; 32],
    durable_promotion_proposal: &[u8; 32],
    durable_signed_envelope: &[u8; 32],
    computed_proposal: &[u8; 32],
    computed_signed_envelope: &[u8; 32],
) -> Result<(), Failure> {
    if durable_vote_proposal != computed_proposal || durable_promotion_proposal != computed_proposal
    {
        return Err(Failure::new(
            "PROPOSAL_BINDING_DIGEST_MISMATCH",
            "durable vote or promotion proposal digest does not match the canonical quorum binding",
            EXIT_DATA,
        ));
    }
    if durable_signed_envelope != computed_signed_envelope {
        return Err(Failure::new(
            "FINAL_ENVELOPE_DIGEST_MISMATCH",
            "durable signed-envelope digest does not match the inspected proof",
            EXIT_DATA,
        ));
    }
    Ok(())
}

fn recover_store_snapshot(path: &Path) -> Result<RecoveredAuthority, Failure> {
    let source = StorePaths::new(path);
    let bytes = read_bounded(source.committed(), MAX_STORE_SNAPSHOT_SIZE, "STORE")?;
    let snapshot = AuthoritySnapshot::decode(&bytes).map_err(map_store_corruption)?;
    Ok(RecoveredAuthority {
        identity: snapshot.identity().clone(),
        state: snapshot.state().clone(),
        generation: snapshot.generation(),
    })
}

fn map_store_corruption(corruption: Corruption) -> Failure {
    Failure::new("STORE_CORRUPT", corruption.to_string(), EXIT_DATA)
}

fn read_signed_proof(path: &Path) -> Result<SignedPromotionEnvelope, Failure> {
    let bytes = read_bounded(path, MAX_SIGNED_ENVELOPE_SIZE, "PROOF")?;
    SignedPromotionEnvelope::from_canonical_bytes(&bytes)
        .map_err(|error| Failure::new("PROOF_MALFORMED", error.to_string(), EXIT_DATA))
}

fn load_config(path: &Path) -> Result<AgentConfig, Failure> {
    let bytes = read_bounded(path, MAX_CONFIG_SIZE, "CONFIG")?;
    let text = String::from_utf8(bytes).map_err(|error| {
        Failure::new(
            "CONFIG_INVALID_UTF8",
            format!("configuration is not UTF-8: {error}"),
            EXIT_CONFIG,
        )
    })?;
    let base = match path.parent() {
        Some(parent) => parent,
        None => Path::new("."),
    };
    parse_config_text(&text, base)
}

fn read_bounded(path: &Path, maximum: usize, prefix: &'static str) -> Result<Vec<u8>, Failure> {
    let file = fs::File::open(path).map_err(|error| {
        let (reason, exit_code) = if error.kind() == std::io::ErrorKind::NotFound {
            match prefix {
                "CONFIG" => ("CONFIG_MISSING", EXIT_MISSING),
                "PROOF" => ("PROOF_MISSING", EXIT_MISSING),
                "STORE" => ("STORE_MISSING", EXIT_MISSING),
                _ => ("INPUT_MISSING", EXIT_MISSING),
            }
        } else {
            ("INPUT_OPEN_FAILED", EXIT_IO)
        };
        Failure::new(reason, error.to_string(), exit_code)
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::new("INPUT_METADATA_FAILED", error.to_string(), EXIT_IO))?;
    if !metadata.is_file() {
        return Err(Failure::new(
            "INPUT_INVALID_TYPE",
            "input must be a regular file",
            EXIT_DATA,
        ));
    }
    let size = usize::try_from(metadata.len()).map_err(|error| {
        Failure::new(
            "INPUT_TOO_LARGE",
            format!("input size cannot be represented: {error}"),
            EXIT_DATA,
        )
    })?;
    if size > maximum {
        return Err(Failure::new(
            "INPUT_TOO_LARGE",
            format!("input is {size} bytes; maximum is {maximum}"),
            EXIT_DATA,
        ));
    }
    let limit = u64::try_from(maximum)
        .map_err(|error| {
            Failure::new(
                "INPUT_LIMIT_INVALID",
                format!("input limit cannot be represented: {error}"),
                EXIT_DATA,
            )
        })?
        .saturating_add(1);
    let mut reader = file.take(limit);
    let mut bytes = Vec::with_capacity(size.min(maximum));
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::new("INPUT_READ_FAILED", error.to_string(), EXIT_IO))?;
    if bytes.len() > maximum {
        return Err(Failure::new(
            "INPUT_TOO_LARGE",
            format!("input grew beyond the {maximum}-byte limit while reading"),
            EXIT_DATA,
        ));
    }
    Ok(bytes)
}

fn parse_config_text(text: &str, base: &Path) -> Result<AgentConfig, Failure> {
    let mut node_id = None;
    let mut workload_id = None;
    let mut role = None;
    let mut store_dir = None;
    let mut proof_path = None;
    let mut automatic_promotion = false;
    let mut saw_automatic_promotion = false;
    let mut keys = Vec::new();

    for (offset, raw_line) in text.lines().enumerate() {
        let line_number = offset.saturating_add(1);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, raw_value) = line
            .split_once('=')
            .ok_or_else(|| config_error(line_number, "expected name = value"))?;
        let name = name.trim();
        let raw_value = raw_value.trim();
        match name {
            "node_id" => {
                let value = parse_quoted(raw_value, line_number)?;
                let parsed = CanonicalId::new(value).map_err(|error| {
                    config_error(line_number, format!("invalid node_id: {error}"))
                })?;
                set_once(&mut node_id, parsed, line_number, name)?;
            }
            "workload_id" => {
                let value = parse_quoted(raw_value, line_number)?;
                let parsed = CanonicalId::new(value).map_err(|error| {
                    config_error(line_number, format!("invalid workload_id: {error}"))
                })?;
                set_once(&mut workload_id, parsed, line_number, name)?;
            }
            "role" => {
                let value = parse_quoted(raw_value, line_number)?;
                let parsed = NodeRole::parse(&value)
                    .ok_or_else(|| config_error(line_number, "role must be data or witness"))?;
                set_once(&mut role, parsed, line_number, name)?;
            }
            "store_dir" => {
                let value = parse_quoted(raw_value, line_number)?;
                let path = resolve_config_path(base, &value, line_number, name)?;
                set_once(&mut store_dir, path, line_number, name)?;
            }
            "proof_path" => {
                let value = parse_quoted(raw_value, line_number)?;
                let path = resolve_config_path(base, &value, line_number, name)?;
                set_once(&mut proof_path, path, line_number, name)?;
            }
            "automatic_promotion" => {
                if saw_automatic_promotion {
                    return Err(config_error(line_number, "duplicate automatic_promotion"));
                }
                automatic_promotion = match raw_value {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(config_error(
                            line_number,
                            "automatic_promotion must be true or false",
                        ));
                    }
                };
                saw_automatic_promotion = true;
            }
            "verification_key" => {
                let value = parse_quoted(raw_value, line_number)?;
                let entry = parse_key_spec(&value)
                    .map_err(|failure| config_error(line_number, failure.detail))?;
                push_unique_key(&mut keys, entry)
                    .map_err(|failure| config_error(line_number, failure.detail))?;
            }
            _ => {
                return Err(config_error(
                    line_number,
                    format!("unknown configuration field: {name}"),
                ));
            }
        }
    }

    Ok(AgentConfig {
        node_id: node_id.ok_or_else(|| config_error(0, "node_id is required"))?,
        workload_id: workload_id.ok_or_else(|| config_error(0, "workload_id is required"))?,
        role: role.ok_or_else(|| config_error(0, "role is required"))?,
        store_dir,
        proof_path,
        automatic_promotion,
        keys,
    })
}

fn parse_quoted(raw: &str, line: usize) -> Result<String, Failure> {
    let Some(inner) = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(config_error(line, "string values must use double quotes"));
    };
    if inner.is_empty() {
        return Err(config_error(line, "string value cannot be empty"));
    }
    if inner.contains('"') || inner.contains('\\') || inner.chars().any(char::is_control) {
        return Err(config_error(
            line,
            "quoted strings cannot contain quotes, escapes, or control characters",
        ));
    }
    Ok(inner.to_owned())
}

fn resolve_config_path(
    base: &Path,
    value: &str,
    line: usize,
    name: &str,
) -> Result<PathBuf, Failure> {
    let path = PathBuf::from(value);
    if value.is_empty() {
        return Err(config_error(line, format!("{name} cannot be empty")));
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(base.join(path))
    }
}

fn set_once<T>(target: &mut Option<T>, value: T, line: usize, name: &str) -> Result<(), Failure> {
    if target.is_some() {
        return Err(config_error(line, format!("duplicate {name}")));
    }
    *target = Some(value);
    Ok(())
}

fn config_error(line: usize, detail: impl Into<String>) -> Failure {
    let detail = detail.into();
    let message = if line == 0 {
        detail
    } else {
        format!("line {line}: {detail}")
    };
    Failure::new("CONFIG_INVALID", message, EXIT_CONFIG)
}

fn parse_key_spec(value: &str) -> Result<KeyEntry, Failure> {
    let mut parts = value.split(':');
    let principal = parts.next();
    let key_id = parts.next();
    let encoded = parts.next();
    if principal.is_none() || key_id.is_none() || encoded.is_none() || parts.next().is_some() {
        return Err(Failure::new(
            "KEY_SPEC_INVALID",
            "verification key must be principal:key-id:64-hex-public-key",
            EXIT_CONFIG,
        ));
    }
    let (Some(principal), Some(key_id), Some(encoded)) = (principal, key_id, encoded) else {
        return Err(Failure::new(
            "KEY_SPEC_INVALID",
            "verification key must be principal:key-id:64-hex-public-key",
            EXIT_CONFIG,
        ));
    };
    let principal = CanonicalId::new(principal).map_err(|error| {
        Failure::new(
            "KEY_SPEC_INVALID",
            format!("invalid key principal: {error}"),
            EXIT_CONFIG,
        )
    })?;
    let key_id = CanonicalId::new(key_id).map_err(|error| {
        Failure::new(
            "KEY_SPEC_INVALID",
            format!("invalid key identifier: {error}"),
            EXIT_CONFIG,
        )
    })?;
    let bytes = decode_hex_32(encoded).ok_or_else(|| {
        Failure::new(
            "KEY_SPEC_INVALID",
            "public verification key must contain exactly 64 hexadecimal characters",
            EXIT_CONFIG,
        )
    })?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
        Failure::new(
            "KEY_SPEC_INVALID",
            format!("invalid Ed25519 public key: {error}"),
            EXIT_CONFIG,
        )
    })?;
    Ok(KeyEntry {
        principal,
        key_id,
        key,
    })
}

fn push_unique_key(entries: &mut Vec<KeyEntry>, entry: KeyEntry) -> Result<(), Failure> {
    if entries
        .iter()
        .any(|existing| existing.principal == entry.principal && existing.key_id == entry.key_id)
    {
        return Err(Failure::new(
            "DUPLICATE_VERIFICATION_KEY",
            format!(
                "duplicate verification key identity {}:{}",
                entry.principal, entry.key_id
            ),
            EXIT_CONFIG,
        ));
    }
    entries.push(entry);
    Ok(())
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn deterministic_trace(seed: u64, scenario: Scenario) -> u64 {
    let scenario_tag = match scenario {
        Scenario::ClockRollback => 1_u64,
        Scenario::Duplicate => 2,
        Scenario::Delay => 3,
        Scenario::Partition => 4,
        Scenario::Reorder => 5,
        Scenario::StoreError => 6,
    };
    let mut value = seed ^ scenario_tag.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn safe_state_fields(
    event: &'static str,
    status: &'static str,
    reason: &'static str,
) -> [(&'static str, String); 6] {
    [
        ("event", event.to_owned()),
        ("status", status.to_owned()),
        ("reason_code", reason.to_owned()),
        ("ready", "false".to_owned()),
        ("effect_gate", "closed".to_owned()),
        ("authority", "denied".to_owned()),
    ]
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn json_record(fields: &[(&str, String)]) -> String {
    let mut output = String::from("{");
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(name);
        output.push_str("\":\"");
        push_json_escaped(&mut output, value);
        output.push('"');
    }
    output.push('}');
    output
}

fn push_json_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => output.push('?'),
            printable => output.push(printable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn contains_reason(report: &CliReport, reason: &str) -> bool {
        report
            .stdout()
            .iter()
            .chain(report.stderr().iter())
            .any(|line| line.contains(reason))
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "quorumarc-agent-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn verification_key_spec(principal: &str, key_id: &str, seed: u8) -> String {
        let key = quorumarc_wire::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        format!("{principal}:{key_id}:{}", hex_encode(&key))
    }

    #[test]
    fn no_arguments_reports_closed_safe_default() {
        let report = execute(Vec::<String>::new());
        assert_eq!(report.exit_code(), 0);
        assert!(contains_reason(&report, "CONFIG_MISSING_SAFE_DEFAULT"));
        assert!(report.stdout()[0].contains("\"effect_gate\":\"closed\""));
        assert!(report.stdout()[0].contains("\"authority\":\"denied\""));
    }

    #[test]
    fn run_requires_explicit_configuration() {
        let report = execute(["run"]);
        assert_eq!(report.exit_code(), EXIT_CONFIG);
        assert!(contains_reason(&report, "CONFIG_REQUIRED"));
    }

    #[test]
    fn validate_config_requires_explicit_configuration() {
        let report = execute(["validate-config"]);
        assert_eq!(report.exit_code(), EXIT_CONFIG);
        assert!(contains_reason(&report, "CONFIG_REQUIRED"));
        assert!(contains_reason(&report, "effect_gate"));
    }

    #[test]
    fn daemon_requires_explicit_production_configuration() {
        let report = execute(["daemon"]);
        assert_eq!(report.exit_code(), EXIT_CONFIG);
        assert!(contains_reason(&report, "CONFIG_REQUIRED"));
        assert!(contains_reason(&report, "\"effect_gate\":\"closed\""));
    }

    #[test]
    fn validate_config_refuses_shared_witness_automatic_promotion() {
        let directory = temporary_directory("shared-witness");
        if fs::create_dir_all(&directory).is_err() {
            std::process::abort();
        }
        let path = directory.join("cluster.conf");
        let text = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.22:7602"
store_dir = "/var/lib/quorumarc/authority"
store_id = "07070707070707070707070707070707"
signing_key = "/etc/quorumarc/node-a.seed"
key_id = "node-a-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = true

[tls]
certificate_chain = "/etc/quorumarc/tls/node-a.crt"
private_key = "/etc/quorumarc/tls/node-a.key"
trusted_roots = "/etc/quorumarc/tls/ca.crt"
server_name = "witness.example.internal"
io_timeout_ms = 5000

[fence]
mechanism = "hardware-power"
profile = "pdu-a"
read_back = true

[workload]
unit = "orders-api.service"

[effect]
vip = "172.30.1.100/24"
interface = "enp1s0"

[[members]]
id = "node-a"
role = "data"
address = "172.30.1.22:7601"
failure_domain = "power-a"
key_id = "node-a-2026-01"
public_key = "/etc/quorumarc/keys/node-a.pub"

[[members]]
id = "node-b"
role = "data"
address = "172.30.1.21:7601"
failure_domain = "power-b"
key_id = "node-b-2026-01"
public_key = "/etc/quorumarc/keys/node-b.pub"

[[members]]
id = "witness-a"
role = "witness"
address = "172.30.1.22:7602"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "/etc/quorumarc/keys/witness-a.pub"
"#;
        if fs::write(&path, text).is_err() {
            std::process::abort();
        }
        let report = execute([
            OsString::from("validate-config"),
            OsString::from("--config"),
            path.as_os_str().to_owned(),
        ]);
        assert_eq!(report.exit_code(), EXIT_CONFIG);
        assert!(contains_reason(
            &report,
            "WITNESS_FAILURE_DOMAIN_NOT_INDEPENDENT"
        ));
        assert!(contains_reason(&report, "\"effect_gate\":\"closed\""));
        let _cleanup_result = fs::remove_dir_all(directory);
    }

    #[test]
    fn health_is_never_ready_without_configuration() {
        let report = execute(["health"]);
        assert_eq!(report.exit_code(), EXIT_NOT_READY);
        assert!(report.stdout()[0].contains("\"ready\":\"false\""));
        assert!(report.stdout()[0].contains("\"effect_gate\":\"closed\""));
    }

    #[test]
    fn direct_activation_is_forbidden() {
        let report = execute(["activate"]);
        assert_eq!(report.exit_code(), EXIT_CONFIG);
        assert!(contains_reason(&report, "DIRECT_ACTIVATION_FORBIDDEN"));
    }

    #[test]
    fn duplicate_trust_anchor_identity_is_rejected_independent_of_order() {
        let first = verification_key_spec("node-a", "key-1", 11);
        let second = verification_key_spec("node-a", "key-1", 17);
        let options = vec![
            OsString::from("--key"),
            OsString::from(&first),
            OsString::from("--key"),
            OsString::from(&second),
        ];
        let cli_result = parse_proof_options(&options);
        assert!(matches!(
            cli_result,
            Err(failure) if failure.reason == "DUPLICATE_VERIFICATION_KEY"
        ));

        let config = format!(
            "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\nverification_key = \"{first}\"\nverification_key = \"{second}\"\n"
        );
        let config_result = parse_config_text(&config, Path::new("."));
        assert!(matches!(
            config_result,
            Err(failure)
                if failure.reason == "CONFIG_INVALID"
                    && failure.detail.contains("duplicate verification key identity")
        ));
    }

    #[test]
    fn proposal_and_final_digest_bindings_are_checked_independently() {
        assert!(verify_material_digests(&[5; 32], &[5; 32], &[9; 32], &[5; 32], &[9; 32],).is_ok());

        let proposal_mismatch =
            verify_material_digests(&[5; 32], &[7; 32], &[9; 32], &[5; 32], &[9; 32]);
        assert!(matches!(
            proposal_mismatch,
            Err(Failure {
                reason: "PROPOSAL_BINDING_DIGEST_MISMATCH",
                exit_code: EXIT_DATA,
                ..
            })
        ));

        let final_mismatch =
            verify_material_digests(&[5; 32], &[5; 32], &[7; 32], &[5; 32], &[9; 32]);
        assert!(matches!(
            final_mismatch,
            Err(Failure {
                reason: "FINAL_ENVELOPE_DIGEST_MISMATCH",
                exit_code: EXIT_DATA,
                ..
            })
        ));
    }

    #[test]
    fn configuration_defaults_automatic_promotion_to_false() {
        let text = r#"
            node_id = "node-a"
            workload_id = "orders"
            role = "data"
            store_dir = "state"
            proof_path = "promotion.bin"
        "#;
        let result = parse_config_text(text, Path::new("/lab"));
        let Ok(config) = result else {
            std::process::abort();
        };
        assert!(!config.automatic_promotion);
        assert_eq!(config.store_dir, Some(PathBuf::from("/lab/state")));
        assert_eq!(config.proof_path, Some(PathBuf::from("/lab/promotion.bin")));
    }

    #[test]
    fn material_validation_refuses_missing_store_and_proof() {
        let without_store = r#"
            node_id = "node-a"
            workload_id = "orders"
            role = "data"
        "#;
        let Ok(config) = parse_config_text(without_store, Path::new("/lab")) else {
            std::process::abort();
        };
        assert!(matches!(
            inspect_material_consistency(&config),
            Err(Failure {
                reason: "STORE_REQUIRED",
                ..
            })
        ));

        let without_proof = r#"
            node_id = "node-a"
            workload_id = "orders"
            role = "data"
            store_dir = "state"
        "#;
        let Ok(config) = parse_config_text(without_proof, Path::new("/lab")) else {
            std::process::abort();
        };
        assert!(matches!(
            inspect_material_consistency(&config),
            Err(Failure {
                reason: "PROOF_REQUIRED",
                ..
            })
        ));
    }

    #[test]
    fn unknown_configuration_field_is_rejected() {
        let text = r#"
            node_id = "node-a"
            workload_id = "orders"
            role = "data"
            surprise = "unexpected"
        "#;
        let error = parse_config_text(text, Path::new("/lab"));
        assert!(matches!(
            error,
            Err(Failure {
                reason: "CONFIG_INVALID",
                ..
            })
        ));
    }

    #[test]
    fn missing_proof_path_is_a_stable_refusal() {
        let report = execute(["inspect-proof"]);
        assert_eq!(report.exit_code(), EXIT_MISSING);
        assert!(contains_reason(&report, "PROOF_REQUIRED"));
    }

    #[test]
    fn failure_simulation_is_deterministic_and_cannot_open_effects() {
        let arguments = [
            "simulate-failure",
            "--scenario",
            "clock-rollback",
            "--seed",
            "42",
        ];
        let first = execute(arguments);
        let second = execute(arguments);
        assert_eq!(first, second);
        assert_eq!(first.exit_code(), 0);
        assert!(contains_reason(&first, "SIMULATION_NO_EFFECTS"));
        assert!(first.stdout()[0].contains("\"effect_gate\":\"closed\""));
        assert!(first.stdout()[0].contains("\"authority\":\"denied\""));
    }

    #[test]
    fn duplicate_path_option_is_rejected() {
        let report = execute(["run", "--config", "a", "--config", "b"]);
        assert_eq!(report.exit_code(), EXIT_USAGE);
        assert!(contains_reason(&report, "DUPLICATE_OPTION"));
    }

    #[test]
    fn run_rejects_command_line_trust_anchor_override() {
        let report = execute(["run", "--config", "agent.conf", "--key", "untrusted"]);
        assert_eq!(report.exit_code(), EXIT_USAGE);
        assert!(contains_reason(&report, "UNEXPECTED_ARGUMENT"));
    }

    #[test]
    fn corrupt_store_is_fail_closed() {
        let directory = temporary_directory("corrupt-store");
        if fs::create_dir_all(&directory).is_err() {
            std::process::abort();
        }
        if fs::write(directory.join("authority.journal"), b"truncated").is_err() {
            std::process::abort();
        }
        if fs::write(directory.join("authority.journal.tmp"), b"must-remain").is_err() {
            std::process::abort();
        }
        let report = execute([
            OsString::from("inspect-store"),
            OsString::from("--store"),
            directory.as_os_str().to_owned(),
        ]);
        assert_eq!(report.exit_code(), EXIT_DATA);
        assert!(contains_reason(&report, "STORE_CORRUPT"));
        assert!(report.stderr()[0].contains("\"effect_gate\":\"closed\""));
        assert!(report.stderr()[0].contains("\"authority\":\"denied\""));
        assert!(directory.join("authority.journal.tmp").is_file());
        let _cleanup_result = fs::remove_dir_all(directory);
    }
}
