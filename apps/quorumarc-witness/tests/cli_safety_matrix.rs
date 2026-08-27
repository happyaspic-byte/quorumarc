use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_store::{DurableAuthorityStore, FileBackend, StoreIdentity, StoreRole};
use quorumarc_wire::MAX_SIGNED_ENVELOPE_SIZE;
use quorumarc_witness::execute;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-witness-matrix-{label}-{}-{sequence}",
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

fn invoke(arguments: Vec<String>) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(arguments, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn path_arguments(command: &str, option: &str, path: &Path) -> Vec<String> {
    vec![
        command.to_owned(),
        option.to_owned(),
        path.to_string_lossy().into_owned(),
    ]
}

#[test]
fn syntax_errors_and_direct_authority_commands_are_refused() {
    let usage_cases = [
        arguments(&["unknown"]),
        arguments(&["status", "--config"]),
        arguments(&["status", "--proof", "ignored"]),
        arguments(&["inspect-store", "--store", "a", "--store", "b"]),
        arguments(&["help", "--store", "ignored"]),
    ];
    for case in usage_cases {
        let (code, _, stderr) = invoke(case);
        assert_eq!(code, 2);
        assert!(stderr.contains("CLI_USAGE_ERROR"));
    }

    for command in ["vote", "certify"] {
        let (code, stdout, stderr) = invoke(arguments(&[command]));
        assert_eq!(code, 78);
        assert!(stdout.is_empty());
        assert!(stderr.contains("VOTE_REFUSED_DIRECT_CLI_DISABLED"));
        assert!(stderr.contains("voting=disabled"));
    }
}

#[test]
fn readiness_ladder_never_enables_voting() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("readiness")?;
    let config = directory.path().join("witness.toml");
    let key = directory.path().join("witness.key");
    let store = directory.path().join("store");
    fs::write(&config, b"lab-config")?;
    fs::write(&key, b"lab-key")?;
    fs::create_dir_all(&store)?;

    let stages = [
        (arguments(&["run"]), "RUN_REFUSED_CONFIG_NOT_CONFIGURED"),
        (
            vec![
                "run".to_owned(),
                "--config".to_owned(),
                config.to_string_lossy().into_owned(),
            ],
            "RUN_REFUSED_KEY_NOT_CONFIGURED",
        ),
        (
            vec![
                "run".to_owned(),
                "--config".to_owned(),
                config.to_string_lossy().into_owned(),
                "--key".to_owned(),
                key.to_string_lossy().into_owned(),
            ],
            "RUN_REFUSED_STORE_NOT_CONFIGURED",
        ),
        (
            vec![
                "run".to_owned(),
                "--config".to_owned(),
                config.to_string_lossy().into_owned(),
                "--key".to_owned(),
                key.to_string_lossy().into_owned(),
                "--store".to_owned(),
                store.to_string_lossy().into_owned(),
            ],
            "RUN_REFUSED_AUTHENTICATED_PROTOCOL_UNAVAILABLE",
        ),
    ];
    for (case, reason) in stages {
        let (code, stdout, stderr) = invoke(case);
        assert_eq!(code, 78);
        assert!(stdout.is_empty());
        assert!(stderr.contains(reason));
        assert!(stderr.contains("voting=disabled"));
    }

    let health_arguments = vec![
        "health".to_owned(),
        "--config".to_owned(),
        config.to_string_lossy().into_owned(),
        "--key".to_owned(),
        key.to_string_lossy().into_owned(),
        "--store".to_owned(),
        store.to_string_lossy().into_owned(),
    ];
    let (code, stdout, stderr) = invoke(health_arguments);
    assert_eq!(code, 1);
    assert!(stdout.contains("healthy=false"));
    assert!(stdout.contains("ready=false"));
    assert!(stdout.contains("voting=false"));
    assert!(stdout.contains("WITNESS_HEALTH_SERVICE_NOT_IMPLEMENTED"));
    assert!(stderr.is_empty());
    Ok(())
}

#[test]
fn proof_inspection_rejects_missing_wrong_type_oversize_and_malformed() -> Result<(), Box<dyn Error>>
{
    let directory = TestDirectory::new("proof")?;

    let missing = directory.path().join("missing.bin");
    let (code, _, stderr) = invoke(path_arguments("inspect-proof", "--proof", &missing));
    assert_eq!(code, 66);
    assert!(stderr.contains("PROOF_FILE_MISSING"));

    let (code, _, stderr) = invoke(path_arguments("inspect-proof", "--proof", directory.path()));
    assert_eq!(code, 65);
    assert!(stderr.contains("PROOF_INVALID_FILE_TYPE"));

    let oversized = directory.path().join("oversized.bin");
    let file = fs::File::create(&oversized)?;
    file.set_len(u64::try_from(MAX_SIGNED_ENVELOPE_SIZE)?.saturating_add(1))?;
    let (code, _, stderr) = invoke(path_arguments("inspect-proof", "--proof", &oversized));
    assert_eq!(code, 65);
    assert!(stderr.contains("PROOF_TOO_LARGE"));

    let malformed = directory.path().join("malformed.bin");
    fs::write(&malformed, b"not-a-canonical-envelope")?;
    let (code, stdout, stderr) = invoke(path_arguments("inspect-proof", "--proof", &malformed));
    assert_eq!(code, 65);
    assert!(stdout.is_empty());
    assert!(stderr.contains("PROOF_MALFORMED"));
    assert!(stderr.contains("verified=false"));
    Ok(())
}

#[test]
fn store_inspection_is_read_only_and_corruption_is_never_authority() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("store")?;
    let store_path = directory.path().join("authority");
    fs::create_dir_all(&store_path)?;

    let (empty_code, empty_stdout, empty_stderr) =
        invoke(path_arguments("inspect-store", "--store", &store_path));
    assert_eq!(empty_code, 0);
    assert!(empty_stdout.contains("authority=false"));
    assert!(empty_stdout.contains("WITNESS_STORE_NO_COMMITTED_FRAME"));
    assert!(empty_stderr.is_empty());

    let identity = StoreIdentity::new(
        "cluster-a",
        "orders",
        "witness",
        StoreRole::Witness,
        [97; 16],
    )?;
    let mut store = DurableAuthorityStore::open_in(&store_path, identity, FileBackend)?;
    store.allocate_incarnation(4)?;
    fs::write(store.paths().temporary(), b"live-writer-staging")?;
    let (code, stdout, stderr) = invoke(path_arguments("inspect-store", "--store", &store_path));
    assert_eq!(code, 0);
    assert!(stdout.contains("store=recovered"));
    assert!(stdout.contains("authority=false"));
    assert!(stdout.contains("cluster_id=cluster-a"));
    assert!(stdout.contains("workload_id=orders"));
    assert!(stdout.contains("node_id=witness"));
    assert!(stdout.contains("store_role=witness"));
    assert!(stdout.contains("incarnation=4"));
    assert!(stderr.is_empty());
    assert_eq!(fs::read(store.paths().temporary())?, b"live-writer-staging");
    drop(store);

    fs::write(store_path.join("authority.journal"), b"truncated")?;
    let (code, stdout, stderr) = invoke(path_arguments("inspect-store", "--store", &store_path));
    assert_eq!(code, 65);
    assert!(stdout.is_empty());
    assert!(stderr.contains("WITNESS_STORE_CORRUPT"));
    assert!(stderr.contains("authority=false"));
    Ok(())
}

struct RefusingWriter;

impl Write for RefusingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "deterministic output failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failure_returns_io_exit_instead_of_semantic_success() {
    let mut stderr = Vec::new();
    let code = execute(["status"], &mut RefusingWriter, &mut stderr);
    assert_eq!(code, 74);
    assert!(String::from_utf8_lossy(&stderr).contains("CLI_OUTPUT_IO_ERROR"));
}
