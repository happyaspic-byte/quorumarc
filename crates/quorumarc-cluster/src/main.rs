use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use quorumarc_cluster::{
    BootstrapConfig, ClusterError, ContinuousClient, ContinuousPrimaryConfig,
    ContinuousReplicaConfig, ContinuousSubmitOutcome, FaultProxyConfig, LabBindPolicy,
    LifecycleControllerConfig, LifecycleNodeConfig, LifecycleNodeId, LifecycleProgressContract,
    LifecycleStoreFault, LifecycleWitnessConfig, PeerConfig, SelfTestConfig, WitnessConfig,
    default_progress_contract, lifecycle_policy_hash, load_private_seed, load_public_key,
    run_bootstrap, run_lifecycle_controller, run_self_test, serve_continuous_primary,
    serve_continuous_replica, serve_fault_proxy, serve_lifecycle_node, serve_lifecycle_witness,
    serve_peer, serve_witness,
};
use quorumarc_rpo0::{CounterOperation, OperationId};

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
                    "--required-commit",
                    "--state-root-hex",
                    "--expected-peer-ip",
                ],
                &["--allow-lifecycle-lab", "--allow-private-lan-lab"],
            )?;
            require_lifecycle_opt_in(&options)?;
            let policy_hash = [options.u8_or("--policy-byte", lifecycle_policy_hash()[0])?; 32];
            serve_lifecycle_node(LifecycleNodeConfig {
                node_id: LifecycleNodeId::parse(options.value("--node")?)?,
                bind_policy: lifecycle_bind_policy(&options)?,
                expected_peer_ips: expected_peer_ips(&options)?,
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
                progress_contract: progress_contract(&options)?,
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
                    "--required-commit",
                    "--state-root-hex",
                    "--expected-peer-ip",
                ],
                &["--allow-lifecycle-lab", "--allow-private-lan-lab"],
            )?;
            require_lifecycle_opt_in(&options)?;
            let policy_hash = [options.u8_or("--policy-byte", lifecycle_policy_hash()[0])?; 32];
            serve_lifecycle_witness(LifecycleWitnessConfig {
                bind_policy: lifecycle_bind_policy(&options)?,
                expected_peer_ips: expected_peer_ips(&options)?,
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                store_directory: options.path("--store")?,
                signing_key_file: options.path("--signing-key")?,
                node_a_public_key_file: options.path("--node-a-public-key")?,
                node_b_public_key_file: options.path("--node-b-public-key")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                policy_hash,
                progress_contract: progress_contract(&options)?,
            })
        }
        "lifecycle-controller" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--node-a",
                    "--node-b",
                    "--node-a-public-key",
                    "--node-b-public-key",
                    "--controller-signing-key",
                    "--trace-file",
                    "--failure-threshold",
                    "--max-promotions",
                    "--logical-step-ms",
                    "--poll-ms",
                    "--observation-timeout-ms",
                    "--authority-timeout-ms",
                    "--max-runtime-ms",
                    "--required-commit",
                    "--state-root-hex",
                    "--retry-operation-byte",
                    "--retry-expected-commit",
                    "--retry-increment",
                ],
                &[
                    "--allow-lifecycle-lab",
                    "--allow-private-lan-lab",
                    "--emit-test-effect",
                ],
            )?;
            require_lifecycle_opt_in(&options)?;
            let report = run_lifecycle_controller(LifecycleControllerConfig {
                bind_policy: lifecycle_bind_policy(&options)?,
                node_a_address: options.socket("--node-a")?,
                node_b_address: options.socket("--node-b")?,
                node_a_public_key_file: options.path("--node-a-public-key")?,
                node_b_public_key_file: options.path("--node-b-public-key")?,
                controller_signing_key_file: options.path("--controller-signing-key")?,
                trace_file: options.path("--trace-file")?,
                failure_threshold: options.u32("--failure-threshold")?,
                max_promotions: options.u64("--max-promotions")?,
                logical_step_ms: options.u64("--logical-step-ms")?,
                poll_interval: Duration::from_millis(options.u64("--poll-ms")?),
                observation_timeout: Duration::from_millis(
                    options.u64("--observation-timeout-ms")?,
                ),
                authority_timeout: Duration::from_millis(options.u64("--authority-timeout-ms")?),
                max_runtime: Duration::from_millis(options.u64("--max-runtime-ms")?),
                progress_contract: progress_contract(&options)?,
                emit_test_effect: options.flag("--emit-test-effect"),
                successor_retry: successor_retry(&options)?,
            })?;
            println!(
                "code=LIFECYCLE_CONTROLLER_COMPLETE promotions={} final_active={} final_epoch={} effects={} elapsed_ms={} final_failure_detection_ms={} final_lease_wait_ms={} final_promotion_ms={} final_effect_ms={}",
                report.promotions,
                report.final_active.as_str(),
                report.final_epoch,
                report.final_effect_count,
                report.elapsed_ms,
                report.final_failure_detection_ms,
                report.final_lease_wait_ms,
                report.final_promotion_ms,
                report.final_effect_ms
            );
            Ok(())
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
                &["--allow-lifecycle-lab", "--allow-private-lan-lab"],
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
        "continuous-replica" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--wal",
                    "--signing-key",
                    "--primary-public-key",
                    "--max-connections",
                    "--timeout-ms",
                    "--policy-byte",
                    "--expected-peer-ip",
                ],
                &["--allow-continuous-rpo0-lab", "--allow-private-lan-lab"],
            )?;
            if !options.flag("--allow-continuous-rpo0-lab") {
                return Err(cli_error(
                    "continuous replica requires --allow-continuous-rpo0-lab",
                ));
            }
            serve_continuous_replica(ContinuousReplicaConfig {
                bind_policy: continuous_bind_policy(&options)?,
                expected_primary_ips: expected_peer_ips(&options)?,
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                wal_path: options.path("--wal")?,
                signing_key_file: options.path("--signing-key")?,
                primary_public_key_file: options.path("--primary-public-key")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                policy_hash: [options.u8("--policy-byte")?; 32],
            })
        }
        "continuous-primary" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--listen",
                    "--ready-file",
                    "--wal",
                    "--signing-key",
                    "--client-public-key",
                    "--replica-public-key",
                    "--replica",
                    "--max-connections",
                    "--timeout-ms",
                    "--policy-byte",
                    "--expected-peer-ip",
                ],
                &["--allow-continuous-rpo0-lab", "--allow-private-lan-lab"],
            )?;
            if !options.flag("--allow-continuous-rpo0-lab") {
                return Err(cli_error(
                    "continuous primary requires --allow-continuous-rpo0-lab",
                ));
            }
            serve_continuous_primary(ContinuousPrimaryConfig {
                bind_policy: continuous_bind_policy(&options)?,
                expected_client_ips: expected_peer_ips(&options)?,
                listen: options.socket("--listen")?,
                ready_file: options.path("--ready-file")?,
                wal_path: options.path("--wal")?,
                signing_key_file: options.path("--signing-key")?,
                client_public_key_file: options.path("--client-public-key")?,
                replica_public_key_file: options.path("--replica-public-key")?,
                replica_address: options.socket("--replica")?,
                max_connections: options.u64("--max-connections")?,
                io_timeout: Duration::from_millis(options.u64("--timeout-ms")?),
                policy_hash: [options.u8("--policy-byte")?; 32],
            })
        }
        "continuous-submit" => {
            let options = Options::parse(rest)?;
            options.ensure_allowed(
                &[
                    "--primary",
                    "--primary-public-key",
                    "--client-signing-key",
                    "--operation-byte",
                    "--expected-commit",
                    "--increment",
                    "--timeout-ms",
                    "--policy-byte",
                ],
                &["--allow-continuous-rpo0-lab", "--allow-private-lan-lab"],
            )?;
            if !options.flag("--allow-continuous-rpo0-lab") {
                println!("code=CONTINUOUS_LAB_DISABLED");
                return Err(cli_error(
                    "continuous submit requires --allow-continuous-rpo0-lab",
                ));
            }
            let mut client = ContinuousClient::new_with_policy(
                options.socket("--primary")?,
                continuous_bind_policy(&options)?,
                load_public_key(&options.path("--primary-public-key")?)?,
                load_private_seed(&options.path("--client-signing-key")?)?,
                Duration::from_millis(options.u64("--timeout-ms")?),
                [options.u8("--policy-byte")?; 32],
            );
            let operation = CounterOperation {
                id: OperationId::new([options.u8("--operation-byte")?; 16]),
                expected_commit_index: options.u64_any("--expected-commit")?,
                increment: options.u64_any("--increment")?,
            };
            match client.apply(operation) {
                ContinuousSubmitOutcome::Acknowledged {
                    operation_id,
                    commit_index,
                    value,
                    state_root,
                } => {
                    println!(
                        "code=CONTINUOUS_ACKNOWLEDGED operation_id={operation_id} commit_index={commit_index} value={value} state_root={}",
                        encode_hex(&state_root)
                    );
                    Ok(())
                }
                ContinuousSubmitOutcome::Refused(error) => {
                    println!("code=CONTINUOUS_REFUSED");
                    Err(error)
                }
                ContinuousSubmitOutcome::Unknown(error) => {
                    println!("code=CONTINUOUS_UNKNOWN");
                    Err(error)
                }
                ContinuousSubmitOutcome::NotSubmitted(error) => {
                    println!("code=CONTINUOUS_NOT_SUBMITTED");
                    Err(error)
                }
            }
        }
        _ => Err(cli_error("unknown mode")),
    }
}

fn print_help() {
    println!(
        "quorumarc-cluster {}\n\nUSAGE:\n  quorumarc-cluster self-test --allow-lab-genesis [--root PATH] [--keep-state] [--timeout-ms N] [--startup-timeout-ms N]\n  quorumarc-cluster peer <required options>\n  quorumarc-cluster witness <required options>\n  quorumarc-cluster bootstrap <required options> --allow-lab-genesis\n  quorumarc-cluster lifecycle-node <required options> --allow-lifecycle-lab\n  quorumarc-cluster lifecycle-witness <required options> --allow-lifecycle-lab\n  quorumarc-cluster lifecycle-controller <required options> --allow-lifecycle-lab\n  quorumarc-cluster fault-proxy <required options> --allow-lifecycle-lab\n  quorumarc-cluster continuous-replica <required options> --allow-continuous-rpo0-lab\n  quorumarc-cluster continuous-primary <required options> --allow-continuous-rpo0-lab\n  quorumarc-cluster continuous-submit <required options> --allow-continuous-rpo0-lab\n\nSAFE QUICK CHECK:\n  quorumarc-cluster self-test --allow-lab-genesis\n\nThe cluster modes are bounded localhost Gate 1A laboratory functions.\nThe continuous modes are a fixed-primary two-copy counter slice without\nlifecycle authority, failover, fencing, or physical independence. They are not\na production RPO-0 or HA claim. The lifecycle controller and fault-proxy modes\nare bounded safety tests, not a production failure detector, trusted time\nsource, or physical fence.",
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
                || argument == "--allow-continuous-rpo0-lab"
                || argument == "--allow-lifecycle-lab"
                || argument == "--allow-private-lan-lab"
                || argument == "--emit-test-effect"
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

    fn u64_any(&self, name: &str) -> Result<u64, ClusterError> {
        self.value(name)?
            .parse::<u64>()
            .map_err(|error| cli_error(format!("invalid {name}: {error}")))
    }

    fn u64(&self, name: &str) -> Result<u64, ClusterError> {
        self.u64_any(name)
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

    fn u32(&self, name: &str) -> Result<u32, ClusterError> {
        u32::try_from(self.u64(name)?)
            .map_err(|_| cli_error(format!("{name} must be at most 4294967295")))
    }

    fn u8(&self, name: &str) -> Result<u8, ClusterError> {
        u8::try_from(self.u64(name)?).map_err(|_| cli_error(format!("{name} must be at most 255")))
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

fn continuous_bind_policy(options: &Options) -> Result<LabBindPolicy, ClusterError> {
    LabBindPolicy::from_flags(
        options.flag("--allow-continuous-rpo0-lab"),
        options.flag("--allow-private-lan-lab"),
    )
}

fn lifecycle_bind_policy(options: &Options) -> Result<LabBindPolicy, ClusterError> {
    LabBindPolicy::from_flags(
        options.flag("--allow-lifecycle-lab"),
        options.flag("--allow-private-lan-lab"),
    )
}

fn expected_peer_ips(options: &Options) -> Result<Vec<std::net::IpAddr>, ClusterError> {
    match options.optional_value("--expected-peer-ip") {
        Some(value) => value
            .split(',')
            .map(|item| {
                item.parse::<std::net::IpAddr>()
                    .map_err(|error| cli_error(format!("invalid --expected-peer-ip: {error}")))
            })
            .collect(),
        None => Ok(Vec::new()),
    }
}

fn successor_retry(options: &Options) -> Result<Option<CounterOperation>, ClusterError> {
    match (
        options.optional_value("--retry-operation-byte"),
        options.optional_value("--retry-expected-commit"),
        options.optional_value("--retry-increment"),
    ) {
        (None, None, None) => Ok(None),
        (Some(id), Some(expected), Some(increment)) => Ok(Some(CounterOperation {
            id: OperationId::new(
                [id.parse::<u8>()
                    .map_err(|error| cli_error(format!("invalid retry operation: {error}")))?;
                    16],
            ),
            expected_commit_index: expected
                .parse::<u64>()
                .map_err(|error| cli_error(format!("invalid retry expected commit: {error}")))?,
            increment: increment
                .parse::<u64>()
                .map_err(|error| cli_error(format!("invalid retry increment: {error}")))?,
        })),
        _ => Err(cli_error(
            "retry operation byte, expected commit, and increment must be supplied together",
        )),
    }
}

fn progress_contract(options: &Options) -> Result<LifecycleProgressContract, ClusterError> {
    match (
        options.optional_value("--required-commit"),
        options.optional_value("--state-root-hex"),
    ) {
        (None, None) => default_progress_contract(),
        (Some(commit), Some(root)) => {
            let required_commit = commit
                .parse::<u64>()
                .map_err(|error| cli_error(format!("invalid --required-commit: {error}")))?;
            LifecycleProgressContract::new(required_commit, decode_hex_32(root)?)
        }
        _ => Err(cli_error(
            "--required-commit and --state-root-hex must be supplied together",
        )),
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], ClusterError> {
    if value.len() != 64 {
        return Err(cli_error(
            "state root must be exactly 64 lowercase hex characters",
        ));
    }
    let mut decoded = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, ClusterError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(cli_error("state root must use lowercase hexadecimal")),
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
