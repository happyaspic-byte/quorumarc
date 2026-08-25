use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_agent::{CliReport, execute};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-agent-matrix-{label}-{}-{sequence}",
            std::process::id()
        ));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

fn output(report: &CliReport) -> String {
    report
        .stdout()
        .iter()
        .chain(report.stderr())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn with_path(command: &str, option: &str, path: &Path) -> CliReport {
    execute(vec![
        OsString::from(command),
        OsString::from(option),
        path.as_os_str().to_owned(),
    ])
}

fn assert_closed(report: &CliReport) {
    let text = output(report);
    assert!(text.contains("\"effect_gate\":\"closed\""));
    assert!(text.contains("\"authority\":\"denied\""));
}

#[test]
fn malformed_command_matrix_is_typed_and_fail_closed() {
    let cases = [
        (vec!["unknown"], "UNKNOWN_COMMAND"),
        (vec!["help", "extra"], "UNEXPECTED_ARGUMENT"),
        (vec!["run", "--config"], "OPTION_VALUE_MISSING"),
        (
            vec!["simulate-failure", "--scenario", "unknown"],
            "UNKNOWN_FAILURE_SCENARIO",
        ),
        (
            vec!["simulate-failure", "--seed", "not-a-number"],
            "INVALID_SEED",
        ),
        (
            vec!["simulate-failure", "--seed", "1", "--seed", "2"],
            "DUPLICATE_OPTION",
        ),
    ];

    for (arguments, reason) in cases {
        let report = execute(arguments);
        assert_ne!(report.exit_code(), 0);
        assert!(output(&report).contains(reason));
        assert_closed(&report);
    }
}

#[test]
fn malformed_configuration_matrix_never_reaches_material_inspection() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new("bad-config")?;
    let path = directory.path().join("agent.conf");
    let cases = [
        "workload_id = \"orders\"\nrole = \"data\"\n",
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"candidate\"\n",
        "node_id = node-a\nworkload_id = \"orders\"\nrole = \"data\"\n",
        "node_id = \"node-a\"\nnode_id = \"node-b\"\nworkload_id = \"orders\"\nrole = \"data\"\n",
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\nautomatic_promotion = yes\n",
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\nunknown = \"field\"\n",
    ];

    for config in cases {
        fs::write(&path, config)?;
        let report = with_path("run", "--config", &path);
        assert_ne!(report.exit_code(), 0);
        assert!(output(&report).contains("CONFIG_INVALID"));
        assert_closed(&report);
    }
    Ok(())
}

#[test]
fn run_refuses_each_missing_authority_prerequisite() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("prerequisites")?;
    let config = directory.path().join("agent.conf");

    let missing_config = execute(["run"]);
    assert!(output(&missing_config).contains("CONFIG_REQUIRED"));
    assert_closed(&missing_config);

    fs::write(
        &config,
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"witness\"\n",
    )?;
    let witness_role = with_path("run", "--config", &config);
    assert!(output(&witness_role).contains("WITNESS_ROLE_FORBIDDEN"));
    assert_closed(&witness_role);

    fs::write(
        &config,
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\n",
    )?;
    let no_store = with_path("run", "--config", &config);
    assert!(output(&no_store).contains("STORE_REQUIRED"));
    assert_closed(&no_store);

    fs::write(
        &config,
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\nstore_dir = \"state\"\nproof_path = \"proof.bin\"\n",
    )?;
    let missing_store = with_path("run", "--config", &config);
    assert!(output(&missing_store).contains("STORE_MISSING"));
    assert_closed(&missing_store);
    Ok(())
}

#[test]
fn bounded_inputs_reject_directories_oversize_and_malformed_bytes() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("bounded-input")?;

    let directory_as_config = with_path("run", "--config", directory.path());
    assert!(output(&directory_as_config).contains("INPUT_INVALID_TYPE"));
    assert_closed(&directory_as_config);

    let oversized = directory.path().join("oversized.conf");
    let file = fs::File::create(&oversized)?;
    file.set_len(65_537)?;
    let oversized_report = with_path("run", "--config", &oversized);
    assert!(output(&oversized_report).contains("INPUT_TOO_LARGE"));
    assert_closed(&oversized_report);

    let malformed = directory.path().join("proof.bin");
    fs::write(&malformed, b"not-a-canonical-envelope")?;
    let malformed_report = with_path("inspect-proof", "--proof", &malformed);
    assert!(output(&malformed_report).contains("PROOF_MALFORMED"));
    assert_closed(&malformed_report);
    Ok(())
}

#[test]
fn status_with_automatic_promotion_enabled_still_denies_authority() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("status")?;
    let config = directory.path().join("agent.conf");
    fs::write(
        &config,
        "node_id = \"node-a\"\nworkload_id = \"orders\"\nrole = \"data\"\nautomatic_promotion = true\n",
    )?;

    let report = with_path("status", "--config", &config);
    assert_eq!(report.exit_code(), 0);
    assert!(output(&report).contains("CONFIGURED_NOT_AUTHORIZED"));
    assert!(output(&report).contains("\"automatic_promotion\":\"true\""));
    assert_closed(&report);
    Ok(())
}

#[test]
fn every_failure_simulation_is_deterministic_and_effect_free() {
    let scenarios = [
        "clock-rollback",
        "duplicate",
        "delay",
        "partition",
        "reorder",
        "store-error",
    ];
    let mut traces = Vec::new();
    for scenario in scenarios {
        let arguments = ["simulate-failure", "--scenario", scenario, "--seed", "1234"];
        let first = execute(arguments);
        let second = execute(arguments);
        assert_eq!(first, second);
        assert_eq!(first.exit_code(), 0);
        assert!(output(&first).contains("SIMULATION_NO_EFFECTS"));
        assert_closed(&first);
        traces.push(output(&first));
    }
    traces.sort();
    traces.dedup();
    assert_eq!(traces.len(), scenarios.len());
}

#[test]
fn missing_and_corrupt_store_inspection_are_closed_refusals() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("store")?;

    let missing = with_path("inspect-store", "--store", directory.path());
    assert!(output(&missing).contains("STORE_MISSING"));
    assert_closed(&missing);

    fs::write(directory.path().join("authority.journal"), b"truncated")?;
    let corrupt = with_path("inspect-store", "--store", directory.path());
    assert!(output(&corrupt).contains("STORE_CORRUPT"));
    assert_closed(&corrupt);
    Ok(())
}
