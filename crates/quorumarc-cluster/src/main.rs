use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use quorumarc_cluster::{
    BootstrapConfig, ClusterError, FaultProxyConfig, LifecycleNodeConfig, LifecycleNodeId,
    LifecycleStoreFault, LifecycleWitnessConfig, PeerConfig, SelfTestConfig, WitnessConfig,
    lifecycle_policy_hash, run_bootstrap, run_self_test, serve_fault_proxy, serve_lifecycle_node,
    serve_lifecycle_witness, serve_peer, serve_witness,
};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("event=cluster_refusal {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<String>) -> Result<(), ClusterError> {
    let Some(mode) = arguments.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    let rest = arguments
        .get(1..)
        .ok_or_else(|| cli_error("invalid arguments"))?;
    match mode {
        "help" | "--help" | "-h" => {
            if !rest.is_empty() {
                return Err(cli_error("help takes no options"));
            }
            print_help();
            Ok(())
        }
        "version" | "--version" | "-V" => {
            if !rest.is_empty() {
                return Err(cli_error("version takes no options"));
            }
            println!("quorumarc-cluster {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "peer" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--wal",
                    "--signing-key",
                    "--candidate-public-key",
                    "--max-connections",
                    "--timeout-ms",
                ],
                &[],
            )?;
            serve_peer(PeerConfig {
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                wal_path: options.path("--wal")?,
                signing_key_file: options.path("--signing-key")?,
                candidate_public_key_file: options.path("--candidate-public-key")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
            })
        }
        "witness" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--store",
                    "--signing-key",
                    "--candidate-public-key",
                    "--max-connections",
                    "--timeout-ms",
                ],
                &[],
            )?;
            serve_witness(WitnessConfig {
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                store_directory: options.path("--store")?,
                signing_key_file: options.path("--signing-key")?,
                candidate_public_key_file: options.path("--candidate-public-key")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
            })
        }
        "lifecycle-node" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--node",
                    "--listen",
                    "--ready-file",
                    "--wal",
                    "--store",
                    "--signing-key",
                    "--witness-public-key",
                    "--controller-public-key",
                    "--witness",
                    "--max-connections",
                    "--timeout-ms",
                    "--policy-byte",
                    "--store-fault",
                ],
                &["--allow-lifecycle-lab"],
            )?;
            require_lifecycle_opt_in(&options)?;
            let policy_hash = [options.u8_or("--policy-byte", lifecycle_policy_hash()[0])?; 32];
            serve_lifecycle_node(LifecycleNodeConfig {
                node_id: LifecycleNodeId::parse(options.value("--node")?)?,
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                wal_path: options.path("--wal")?,
                store_directory: options.path("--store")?,
                signing_key_file: options.path("--signing-key")?,
                witness_public_key_file: options.path("--witness-public-key")?,
                controller_public_key_file: options.path("--controller-public-key")?,
                witness_address: options.socket("--witness")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                policy_hash,
                store_fault: parse_store_fault(options.optional_value("--store-fault"))?,
            })
        }
        "lifecycle-witness" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--store",
                    "--signing-key",
                    "--node-a-public-key",
                    "--node-b-public-key",
                    "--max-connections",
                    "--timeout-ms",
                    "--policy-byte",
                ],
                &["--allow-lifecycle-lab"],
            )?;
            require_lifecycle_opt_in(&options)?;
            let policy_hash = [options.u8_or("--policy-byte", lifecycle_policy_hash()[0])?; 32];
            serve_lifecycle_witness(LifecycleWitnessConfig {
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                store_directory: options.path("--store")?,
                signing_key_file: options.path("--signing-key")?,
                node_a_public_key_file: options.path("--node-a-public-key")?,
                node_b_public_key_file: options.path("--node-b-public-key")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                policy_hash,
            })
        }
        "fault-proxy" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--upstream",
                    "--mode-file",
                    "--max-connections",
                    "--timeout-ms",
                ],
                &["--allow-lifecycle-lab"],
            )?;
            require_lifecycle_opt_in(&options)?;
            serve_fault_proxy(FaultProxyConfig {
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                upstream: options.socket("--upstream")?,
                mode_file: options.path("--mode-file")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
            })
        }
        "bootstrap" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--peer",
                    "--witness",
                    "--local-wal",
                    "--store",
                    "--signing-key",
                    "--peer-public-key",
                    "--witness-public-key",
                    "--timeout-ms",
                ],
                &["--allow-lab-genesis"],
            )?;
            if !options.flag("--allow-lab-genesis") {
                return Err(ClusterError::new(
                    "LAB_GENESIS_DISABLED",
                    "bootstrap requires explicit --allow-lab-genesis",
                ));
            }
            let report = run_bootstrap(BootstrapConfig {
                peer_address: options.socket("--peer")?,
                witness_address: options.socket("--witness")?,
                local_wal_path: options.path("--local-wal")?,
                store_directory: options.path("--store")?,
                candidate_signing_key_file: options.path("--signing-key")?,
                peer_public_key_file: options.path("--peer-public-key")?,
                witness_public_key_file: options.path("--witness-public-key")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                allow_lab_genesis: true,
            })?;
            println!(
                "code={} commit_index={} value={} effects={} store_generation={} promotion_digest={}",
                report.reason_code,
                report.commit_index,
                report.value,
                report.effect_count,
                report.store_generation,
                encode_hex(&report.promotion_digest)
            );
            Ok(())
        }
        "self-test" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &["--root", "--timeout-ms", "--startup-timeout-ms"],
                &["--allow-lab-genesis", "--keep-state"],
            )?;
            if !options.flag("--allow-lab-genesis") {
                return Err(ClusterError::new(
                    "LAB_GENESIS_DISABLED",
                    "self-test requires explicit --allow-lab-genesis",
                ));
            }
            let mut config = SelfTestConfig::current_executable()?;
            config.root_directory = options.optional_path("--root");
            config.io_timeout = Duration::from_millis(options.u64_or("--timeout-ms", 3_000)?);
            config.startup_timeout =
                Duration::from_millis(options.u64_or("--startup-timeout-ms", 5_000)?);
            config.keep_state = options.flag("--keep-state");
            config.allow_lab_genesis = true;
            let report = run_self_test(config)?;
            println!(
                "code={} topology=three-process commit_index={} value={} effects={} candidate_store_generation={} witness_store_generation={} elapsed_ms={} state_retained={}",
                report.reason_code,
                report.commit_index,
                report.value,
                report.effect_count,
                report.candidate_store_generation,
                report.witness_store_generation,
                report.elapsed_ms,
                report.state_retained,
            );
            if let Some(path) = report.state_directory {
                println!("event=self_test_state path={}", path.display());
            }
            Ok(())
        }
        _ => Err(cli_error("unknown mode")),
    }
}

fn print_help() {
    println!(
        "quorumarc-cluster {}\n\nUSAGE:\n  quorumarc-cluster self-test --allow-lab-genesis [--root PATH] [--keep-state] [--timeout-ms N] [--startup-timeout-ms N]\n  quorumarc-cluster peer <required options>\n  quorumarc-cluster witness <required options>\n  quorumarc-cluster bootstrap <required options> --allow-lab-genesis\n  quorumarc-cluster lifecycle-node <required options> --allow-lifecycle-lab\n  quorumarc-cluster lifecycle-witness <required options> --allow-lifecycle-lab\n  quorumarc-cluster fault-proxy <required options> --allow-lifecycle-lab\n\nSAFE QUICK CHECK:\n  quorumarc-cluster self-test --allow-lab-genesis\n\nThe cluster modes are bounded localhost Gate 1A laboratory functions.\nThe lifecycle and fault-proxy modes are bounded safety tests, not an autonomous\nproduction failover controller, trusted time source, or physical fence.",
        env!("CARGO_PKG_VERSION")
    );
}

struct Options {
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, ClusterError> {
        let mut values = Vec::new();
        let mut flags = Vec::new();
        let mut index = 0_usize;
        while index < arguments.len() {
            let argument = arguments
                .get(index)
                .ok_or_else(|| cli_error("argument index invalid"))?;
            if argument == "--allow-lab-genesis"
                || argument == "--keep-state"
                || argument == "--allow-lifecycle-lab"
            {
                if flags.iter().any(|value| value == argument) {
                    return Err(cli_error("duplicate flag"));
                }
                flags.push(argument.clone());
                index = index.saturating_add(1);
                continue;
            }
            if !argument.starts_with("--") {
                return Err(cli_error("positional arguments are not accepted"));
            }
            let value_index = index
                .checked_add(1)
                .ok_or_else(|| cli_error("argument index overflow"))?;
            let value = arguments
                .get(value_index)
                .ok_or_else(|| cli_error("option is missing a value"))?;
            if value.starts_with("--") {
                return Err(cli_error("option is missing a value"));
            }
            if values.iter().any(|(key, _)| key == argument) {
                return Err(cli_error("duplicate option"));
            }
            values.push((argument.clone(), value.clone()));
            index = index.saturating_add(2);
        }
        Ok(Self { values, flags })
    }

    fn value(&self, name: &str) -> Result<&str, ClusterError> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| cli_error(format!("missing required option {name}")))
    }

    fn path(&self, name: &str) -> Result<PathBuf, ClusterError> {
        Ok(PathBuf::from(self.value(name)?))
    }

    fn optional_path(&self, name: &str) -> Option<PathBuf> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| PathBuf::from(value))
    }

    fn optional_value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn socket(&self, name: &str) -> Result<SocketAddr, ClusterError> {
        SocketAddr::from_str(self.value(name)?)
            .map_err(|error| cli_error(format!("invalid {name}: {error}")))
    }

    fn u64(&self, name: &str) -> Result<u64, ClusterError> {
        self.value(name)?
            .parse::<u64>()
            .map_err(|error| cli_error(format!("invalid {name}: {error}")))
            .and_then(|value| {
                if value == 0 {
                    Err(cli_error(format!("{name} must be non-zero")))
                } else {
                    Ok(value)
                }
            })
    }

    fn u64_or(&self, name: &str, default: u64) -> Result<u64, ClusterError> {
        if self.values.iter().any(|(key, _)| key == name) {
            self.u64(name)
        } else {
            Ok(default)
        }
    }

    fn u8_or(&self, name: &str, default: u8) -> Result<u8, ClusterError> {
        let value = if self.values.iter().any(|(key, _)| key == name) {
            self.u64(name)?
        } else {
            u64::from(default)
        };
        u8::try_from(value).map_err(|_| cli_error(format!("{name} must be at most 255")))
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }

    fn ensure_allowed(&self, values: &[&str], flags: &[&str]) -> Result<(), ClusterError> {
        if let Some((unknown, _)) = self
            .values
            .iter()
            .find(|(name, _)| !values.iter().any(|allowed| name == allowed))
        {
            return Err(cli_error(format!("unknown option {unknown}")));
        }
        if let Some(unknown) = self
            .flags
            .iter()
            .find(|name| !flags.iter().any(|allowed| name == allowed))
        {
            return Err(cli_error(format!("unknown flag {unknown}")));
        }
        Ok(())
    }
}

fn cli_error(detail: impl Into<String>) -> ClusterError {
    ClusterError::new("CLI_INVALID", detail)
}

fn require_lifecycle_opt_in(options: &Options) -> Result<(), ClusterError> {
    if options.flag("--allow-lifecycle-lab") {
        Ok(())
    } else {
        Err(ClusterError::new(
            "LIFECYCLE_LAB_DISABLED",
            "lifecycle service requires explicit --allow-lifecycle-lab",
        ))
    }
}

fn parse_store_fault(value: Option<&str>) -> Result<LifecycleStoreFault, ClusterError> {
    match value {
        None | Some("none") => Ok(LifecycleStoreFault::None),
        Some("promotion-write") => Ok(LifecycleStoreFault::PromotionWriteError),
        Some("promotion-partial") => Ok(LifecycleStoreFault::PromotionPartialWrite),
        Some(_) => Err(cli_error(
            "--store-fault must be none, promotion-write, or promotion-partial",
        )),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn mode_rejects_unknown_key_value_option() {
        let options = Options::parse(&[
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--evil".to_owned(),
            "value".to_owned(),
        ])
        .expect("parse option syntax");
        let error = options
            .ensure_allowed(&["--listen"], &[])
            .expect_err("unknown option must fail");
        assert_eq!(error.reason_code(), "CLI_INVALID");
    }

    #[test]
    fn no_arguments_and_help_are_safe_successes() {
        run(Vec::new()).expect("no-argument help must succeed");
        run(vec!["--help".to_owned()]).expect("explicit help must succeed");
        run(vec!["--version".to_owned()]).expect("version must succeed");
    }

    #[test]
    fn help_and_version_reject_options() {
        let help =
            run(vec!["help".to_owned(), "--evil".to_owned()]).expect_err("help option must fail");
        let version = run(vec!["version".to_owned(), "extra".to_owned()])
            .expect_err("version option must fail");
        assert_eq!(help.reason_code(), "CLI_INVALID");
        assert_eq!(version.reason_code(), "CLI_INVALID");
    }
}
