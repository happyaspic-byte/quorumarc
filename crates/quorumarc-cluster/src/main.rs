use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use quorumarc_cluster::{
    BootstrapConfig, ClusterError, PeerConfig, WitnessConfig, run_bootstrap, serve_peer,
    serve_witness,
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
        return Err(cli_error("missing mode: peer, witness, or bootstrap"));
    };
    let rest = arguments
        .get(1..)
        .ok_or_else(|| cli_error("invalid arguments"))?;
    match mode {
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
        _ => Err(cli_error("unknown mode")),
    }
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
            if argument == "--allow-lab-genesis" {
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
}
