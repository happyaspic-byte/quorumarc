//! Safe-default Gate 1A lab witness command line.
//!
//! Diagnostics are available without configuration, but this crate does not
//! expose a voting network service. `run`, `vote`, and `certify` therefore
//! refuse with stable reason text. Parsing a proof is not signature
//! verification, and inspecting a store is not authority.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_runtime::{FrameCodec, FrameReasonCode};
use quorumarc_store::{
    AuthorityState, DurableAuthorityStore, FileBackend, StoreError, StorePaths,
};
use quorumarc_wire::{MAX_SIGNED_ENVELOPE_SIZE, SignedPromotionEnvelope};

const EXIT_NOT_READY: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_DATA: u8 = 65;
const EXIT_MISSING: u8 = 66;
const EXIT_SOFTWARE: u8 = 70;
const EXIT_IO: u8 = 74;
const EXIT_UNAVAILABLE: u8 = 78;
const MAX_STORE_SNAPSHOT_SIZE: usize = 1_048_576;
const SNAPSHOT_ATTEMPTS: u8 = 32;
static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

const REASON_CONFIG_MISSING: &str = "RUN_REFUSED_CONFIG_NOT_CONFIGURED";
const REASON_KEY_MISSING: &str = "RUN_REFUSED_KEY_NOT_CONFIGURED";
const REASON_STORE_MISSING: &str = "RUN_REFUSED_STORE_NOT_CONFIGURED";
const REASON_PROTOCOL_UNAVAILABLE: &str = "RUN_REFUSED_AUTHENTICATED_PROTOCOL_UNAVAILABLE";
const REASON_DIRECT_VOTE_DISABLED: &str = "VOTE_REFUSED_DIRECT_CLI_DISABLED";

/// Parsed command selected by the operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Report configuration presence without opening authority state.
    Status,
    /// Refused until an authenticated service protocol is implemented.
    Run,
    /// Report readiness without granting authority.
    Health,
    /// Strictly parse a signed-envelope file without claiming verification.
    InspectProof,
    /// Recover and display a configured durable store.
    InspectStore,
    /// Run a deterministic malformed-frame fail-closed self-test.
    SimulateFailure,
    /// Direct voting is deliberately unavailable.
    Vote,
    /// Print command help.
    Help,
}

/// Parsed command-line options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cli {
    command: Command,
    config: Option<PathBuf>,
    key: Option<PathBuf>,
    store: Option<PathBuf>,
    proof: Option<PathBuf>,
}

impl Cli {
    /// Selected command.
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }
}

impl Command {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Run => "run",
            Self::Health => "health",
            Self::InspectProof => "inspect-proof",
            Self::InspectStore => "inspect-store",
            Self::SimulateFailure => "simulate-failure",
            Self::Vote => "vote",
            Self::Help => "help",
        }
    }
}

/// Parses command arguments without reading files or environment secrets.
pub fn parse_args<I, S>(arguments: I) -> Result<Cli, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let first = arguments
        .next()
        .map_or_else(|| String::from("status"), std::convert::identity);
    let command = match first.as_str() {
        "status" => Command::Status,
        "run" => Command::Run,
        "health" => Command::Health,
        "inspect-proof" => Command::InspectProof,
        "inspect-store" => Command::InspectStore,
        "simulate-failure" => Command::SimulateFailure,
        "vote" | "certify" => Command::Vote,
        "help" | "--help" | "-h" => Command::Help,
        unknown => return Err(CliError::UnknownCommand(unknown.to_owned())),
    };

    let mut cli = Cli {
        command,
        config: None,
        key: None,
        store: None,
        proof: None,
    };
    while let Some(option) = arguments.next() {
        if !option_allowed(command, &option) {
            return Err(CliError::OptionNotAllowed {
                command: command.as_str(),
                option,
            });
        }
        let target = match option.as_str() {
            "--config" => &mut cli.config,
            "--key" => &mut cli.key,
            "--store" => &mut cli.store,
            "--proof" => &mut cli.proof,
            unknown => return Err(CliError::UnknownOption(unknown.to_owned())),
        };
        if target.is_some() {
            return Err(CliError::DuplicateOption(option));
        }
        let Some(value) = arguments.next() else {
            return Err(CliError::MissingOptionValue(option));
        };
        *target = Some(PathBuf::from(value));
    }
    Ok(cli)
}

fn option_allowed(command: Command, option: &str) -> bool {
    match command {
        Command::Status | Command::Run | Command::Health => {
            matches!(option, "--config" | "--key" | "--store")
        }
        Command::InspectProof => option == "--proof",
        Command::InspectStore => option == "--store",
        Command::SimulateFailure | Command::Vote | Command::Help => false,
    }
}

/// Executes one command and returns its portable process exit code.
pub fn execute<I, S, O, E>(arguments: I, stdout: &mut O, stderr: &mut E) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    O: Write,
    E: Write,
{
    let cli = match parse_args(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let result = writeln!(stderr, "reason=CLI_USAGE_ERROR detail={error}");
            return write_error_exit(result, EXIT_USAGE);
        }
    };
    match cli.command {
        Command::Status => status(&cli, stdout, stderr),
        Command::Run => run(&cli, stderr),
        Command::Health => health(&cli, stdout, stderr),
        Command::InspectProof => inspect_proof(&cli, stdout, stderr),
        Command::InspectStore => inspect_store(&cli, stdout, stderr),
        Command::SimulateFailure => simulate_failure(stdout, stderr),
        Command::Vote => {
            let result = writeln!(
                stderr,
                "refused=true reason={REASON_DIRECT_VOTE_DISABLED} mode=lab"
            );
            write_error_exit(result, EXIT_UNAVAILABLE)
        }
        Command::Help => help(stdout, stderr),
    }
}

fn status<O: Write, E: Write>(cli: &Cli, stdout: &mut O, stderr: &mut E) -> u8 {
    let result = writeln!(
        stdout,
        "component=quorumarc-witness gate=1A mode=lab voting=disabled config_present={} key_present={} store_present={} reason=WITNESS_SAFE_DEFAULT",
        path_is_file(cli.config.as_deref()),
        path_is_file(cli.key.as_deref()),
        path_is_directory(cli.store.as_deref()),
    );
    write_exit(result, stderr)
}

fn run<E: Write>(cli: &Cli, stderr: &mut E) -> u8 {
    let reason = if !path_is_file(cli.config.as_deref()) {
        REASON_CONFIG_MISSING
    } else if !path_is_file(cli.key.as_deref()) {
        REASON_KEY_MISSING
    } else if !path_is_directory(cli.store.as_deref()) {
        REASON_STORE_MISSING
    } else {
        REASON_PROTOCOL_UNAVAILABLE
    };
    let result = writeln!(
        stderr,
        "refused=true reason={reason} mode=lab voting=disabled"
    );
    write_error_exit(result, EXIT_UNAVAILABLE)
}

fn health<O: Write, E: Write>(cli: &Cli, stdout: &mut O, stderr: &mut E) -> u8 {
    let reason = if !path_is_file(cli.config.as_deref()) {
        "WITNESS_HEALTH_CONFIG_NOT_READY"
    } else if !path_is_file(cli.key.as_deref()) {
        "WITNESS_HEALTH_KEY_NOT_READY"
    } else if !path_is_directory(cli.store.as_deref()) {
        "WITNESS_HEALTH_STORE_NOT_READY"
    } else {
        "WITNESS_HEALTH_SERVICE_NOT_IMPLEMENTED"
    };
    let result = writeln!(
        stdout,
        "healthy=false ready=false voting=false mode=lab reason={reason}"
    );
    match result {
        Ok(()) => EXIT_NOT_READY,
        Err(error) => output_error(error, stderr),
    }
}

fn inspect_proof<O: Write, E: Write>(cli: &Cli, stdout: &mut O, stderr: &mut E) -> u8 {
    let Some(path) = cli.proof.as_deref() else {
        let result = writeln!(
            stdout,
            "proof=not-provided verified=false reason=PROOF_PATH_NOT_CONFIGURED"
        );
        return write_error_exit(result, EXIT_MISSING);
    };
    let bytes = match read_bounded(path, MAX_SIGNED_ENVELOPE_SIZE) {
        Ok(bytes) => bytes,
        Err(ReadBoundedError::TooLarge { actual, maximum }) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_TOO_LARGE actual={actual} maximum={maximum}"
            );
            return write_error_exit(result, EXIT_DATA);
        }
        Err(ReadBoundedError::Io(error)) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_READ_IO detail={error}"
            );
            return write_error_exit(result, EXIT_IO);
        }
        Err(ReadBoundedError::Missing) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_FILE_MISSING"
            );
            return write_error_exit(result, EXIT_MISSING);
        }
        Err(ReadBoundedError::InvalidType) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_INVALID_FILE_TYPE"
            );
            return write_error_exit(result, EXIT_DATA);
        }
    };
    let signed = match SignedPromotionEnvelope::from_canonical_bytes(&bytes) {
        Ok(signed) => signed,
        Err(error) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_MALFORMED detail={error}"
            );
            return write_error_exit(result, EXIT_DATA);
        }
    };
    let digest = match signed.digest() {
        Ok(digest) => digest,
        Err(error) => {
            let result = writeln!(
                stderr,
                "proof=refused verified=false reason=PROOF_DIGEST_FAILED detail={error}"
            );
            return write_error_exit(result, EXIT_DATA);
        }
    };
    let envelope = signed.envelope();
    let result = writeln!(
        stdout,
        "proof=structurally-valid verified=false reason=PROOF_SIGNATURE_UNVERIFIED workload={} candidate={} epoch={} incarnation={} digest={}",
        envelope.workload_id,
        envelope.candidate_node_id,
        envelope.epoch,
        envelope.candidate_incarnation,
        hex(&digest),
    );
    write_exit(result, stderr)
}

fn inspect_store<O: Write, E: Write>(cli: &Cli, stdout: &mut O, stderr: &mut E) -> u8 {
    let Some(directory) = cli.store.as_deref() else {
        let result = writeln!(
            stdout,
            "store=not-configured authority=false reason=WITNESS_STORE_NOT_CONFIGURED"
        );
        return write_error_exit(result, EXIT_MISSING);
    };
    if !directory.is_dir() {
        let result = writeln!(
            stdout,
            "store=missing authority=false reason=WITNESS_STORE_DIRECTORY_MISSING"
        );
        return write_error_exit(result, EXIT_MISSING);
    }
    let paths = StorePaths::new(directory);
    if !paths.committed().is_file() {
        let result = writeln!(
            stdout,
            "store=empty authority=false generation=0 highest_epoch=0 reason=WITNESS_STORE_NO_COMMITTED_FRAME"
        );
        return write_exit(result, stderr);
    }
    let (state, generation) = match recover_store_snapshot(&paths) {
        Ok(recovered) => recovered,
        Err(InspectStoreError::Store(error)) => return store_open_error(error, stderr),
        Err(error) => return store_snapshot_error(error, stderr),
    };
    let result = writeln!(
        stdout,
        "store=recovered authority=false mode=inspection generation={} highest_epoch={} incarnation={} commit_index={} vote_present={} promotion_present={} activation_present={}",
        generation,
        state.highest_epoch(),
        state.incarnation(),
        state.commit_index(),
        state.last_vote().is_some(),
        state.last_promotion().is_some(),
        state.activation_receipt().is_some(),
    );
    write_exit(result, stderr)
}

fn simulate_failure<O: Write, E: Write>(stdout: &mut O, stderr: &mut E) -> u8 {
    let codec = match FrameCodec::new(64) {
        Ok(codec) => codec,
        Err(error) => {
            let result = writeln!(
                stderr,
                "simulation=failed reason=FRAME_CODEC_CONFIG_ERROR detail={error}"
            );
            return write_error_exit(result, EXIT_SOFTWARE);
        }
    };
    let result = codec.read_frame(&mut Cursor::new([0_u8, 0_u8]));
    match result {
        Err(error) if error.reason_code() == FrameReasonCode::TruncatedHeader => {
            let result = writeln!(
                stdout,
                "simulation=pass scenario=truncated-frame admitted=false reason={}",
                error.reason_code().as_str()
            );
            write_exit(result, stderr)
        }
        Err(error) => {
            let result = writeln!(
                stderr,
                "simulation=failed scenario=truncated-frame reason={} detail={error}",
                error.reason_code().as_str()
            );
            write_error_exit(result, EXIT_SOFTWARE)
        }
        Ok(_) => {
            let result = writeln!(
                stderr,
                "simulation=failed scenario=truncated-frame reason=FRAME_UNEXPECTEDLY_ADMITTED"
            );
            write_error_exit(result, EXIT_SOFTWARE)
        }
    }
}

fn help<O: Write, E: Write>(stdout: &mut O, stderr: &mut E) -> u8 {
    let result = writeln!(
        stdout,
        "Usage: quorumarc-witness <status|run|health|inspect-proof|inspect-store|simulate-failure> [--config PATH] [--key PATH] [--store DIR] [--proof FILE]\n\
         Gate 1A lab diagnostics are available; run and direct voting fail closed."
    );
    write_exit(result, stderr)
}

fn path_is_file(path: Option<&Path>) -> bool {
    path.is_some_and(Path::is_file)
}

fn path_is_directory(path: Option<&Path>) -> bool {
    path.is_some_and(Path::is_dir)
}

fn write_exit<E: Write>(result: io::Result<()>, stderr: &mut E) -> u8 {
    match result {
        Ok(()) => 0,
        Err(error) => output_error(error, stderr),
    }
}

fn write_error_exit(result: io::Result<()>, semantic_code: u8) -> u8 {
    if result.is_ok() {
        semantic_code
    } else {
        EXIT_IO
    }
}

fn output_error<E: Write>(error: io::Error, stderr: &mut E) -> u8 {
    let _write_result = writeln!(stderr, "reason=CLI_OUTPUT_IO_ERROR detail={error}");
    EXIT_IO
}

fn store_open_error<E: Write>(error: StoreError, stderr: &mut E) -> u8 {
    let (reason, code) = match error {
        StoreError::Corrupt(_) => ("WITNESS_STORE_CORRUPT", EXIT_DATA),
        StoreError::Io { .. } => ("WITNESS_STORE_IO", EXIT_IO),
        _ => ("WITNESS_STORE_INVARIANT", EXIT_SOFTWARE),
    };
    let result = writeln!(stderr, "store=refused authority=false reason={reason}");
    write_error_exit(result, code)
}

fn store_snapshot_error<E: Write>(error: InspectStoreError, stderr: &mut E) -> u8 {
    let (reason, detail, code) = match error {
        InspectStoreError::Read(ReadBoundedError::TooLarge { actual, maximum }) => (
            "WITNESS_STORE_TOO_LARGE",
            format!("committed frame is {actual} bytes; maximum is {maximum}"),
            EXIT_DATA,
        ),
        InspectStoreError::Read(ReadBoundedError::Io(error)) => {
            ("WITNESS_STORE_IO", error.to_string(), EXIT_IO)
        }
        InspectStoreError::Read(ReadBoundedError::Missing) => (
            "WITNESS_STORE_COMMITTED_FRAME_MISSING",
            "committed frame disappeared during inspection".to_owned(),
            EXIT_MISSING,
        ),
        InspectStoreError::Read(ReadBoundedError::InvalidType) => (
            "WITNESS_STORE_INVALID_FILE_TYPE",
            "committed frame must be a regular file".to_owned(),
            EXIT_DATA,
        ),
        InspectStoreError::SnapshotIo { operation, error } => (
            "WITNESS_STORE_SNAPSHOT_IO",
            format!("{operation}: {error}"),
            EXIT_IO,
        ),
        InspectStoreError::Store(error) => return store_open_error(error, stderr),
    };
    let result = writeln!(
        stderr,
        "store=refused authority=false reason={reason} detail={detail}"
    );
    write_error_exit(result, code)
}

fn recover_store_snapshot(
    source: &StorePaths,
) -> Result<(AuthorityState, u64), InspectStoreError> {
    let bytes = read_bounded(source.committed(), MAX_STORE_SNAPSHOT_SIZE)
        .map_err(InspectStoreError::Read)?;
    let snapshot = create_snapshot_directory().map_err(|error| InspectStoreError::SnapshotIo {
        operation: "create inspection snapshot",
        error,
    })?;
    let snapshot_paths = StorePaths::new(snapshot.path());
    fs::write(snapshot_paths.committed(), bytes).map_err(|error| {
        InspectStoreError::SnapshotIo {
            operation: "write inspection snapshot",
            error,
        }
    })?;
    let store = DurableAuthorityStore::open(snapshot_paths, FileBackend)
        .map_err(InspectStoreError::Store)?;
    Ok((store.state().clone(), store.generation()))
}

fn create_snapshot_directory() -> io::Result<SnapshotDirectory> {
    for _attempt in 0..SNAPSHOT_ATTEMPTS {
        let sequence = SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-witness-inspect-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(SnapshotDirectory(path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique inspection snapshot directory",
    ))
}

struct SnapshotDirectory(PathBuf);

impl SnapshotDirectory {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SnapshotDirectory {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

enum InspectStoreError {
    Read(ReadBoundedError),
    SnapshotIo {
        operation: &'static str,
        error: io::Error,
    },
    Store(StoreError),
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ReadBoundedError> {
    let file = fs::File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ReadBoundedError::Missing
        } else {
            ReadBoundedError::Io(error)
        }
    })?;
    let metadata = file.metadata().map_err(ReadBoundedError::Io)?;
    if !metadata.is_file() {
        return Err(ReadBoundedError::InvalidType);
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|_| ReadBoundedError::TooLarge {
        actual: u64::MAX,
        maximum: u64::MAX,
    })?;
    if metadata.len() > maximum_u64 {
        return Err(ReadBoundedError::TooLarge {
            actual: metadata.len(),
            maximum: maximum_u64,
        });
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ReadBoundedError::TooLarge {
        actual: metadata.len(),
        maximum: maximum_u64,
    })?;
    let mut reader = file.take(maximum_u64.saturating_add(1));
    let mut bytes = Vec::with_capacity(capacity.min(maximum));
    reader
        .read_to_end(&mut bytes)
        .map_err(ReadBoundedError::Io)?;
    if bytes.len() > maximum {
        let actual = u64::try_from(bytes.len()).map_err(|_| ReadBoundedError::TooLarge {
            actual: u64::MAX,
            maximum: maximum_u64,
        })?;
        return Err(ReadBoundedError::TooLarge {
            actual,
            maximum: maximum_u64,
        });
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(*byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(*byte & 0x0f)]));
    }
    encoded
}

enum ReadBoundedError {
    TooLarge { actual: u64, maximum: u64 },
    InvalidType,
    Missing,
    Io(io::Error),
}

/// Command-line syntax error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// Command name was not recognized.
    UnknownCommand(String),
    /// Option name was not recognized.
    UnknownOption(String),
    /// Option occurred more than once.
    DuplicateOption(String),
    /// Path-taking option had no following value.
    MissingOptionValue(String),
    /// An otherwise recognized option has no meaning for this command.
    OptionNotAllowed {
        /// Selected command.
        command: &'static str,
        /// Rejected option.
        option: String,
    },
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(command) => write!(formatter, "unknown command: {command}"),
            Self::UnknownOption(option) => write!(formatter, "unknown option: {option}"),
            Self::DuplicateOption(option) => write!(formatter, "duplicate option: {option}"),
            Self::MissingOptionValue(option) => {
                write!(formatter, "missing value for option: {option}")
            }
            Self::OptionNotAllowed { command, option } => {
                write!(formatter, "option {option} is not allowed for {command}")
            }
        }
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(arguments: &[&str]) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = execute(arguments.iter().copied(), &mut stdout, &mut stderr);
        let stdout = String::from_utf8_lossy(&stdout).into_owned();
        let stderr = String::from_utf8_lossy(&stderr).into_owned();
        (code, stdout, stderr)
    }

    #[test]
    fn no_arguments_defaults_to_safe_status() {
        let (code, stdout, stderr) = output(&[]);
        assert_eq!(code, 0);
        assert!(stdout.contains("voting=disabled"));
        assert!(stdout.contains("reason=WITNESS_SAFE_DEFAULT"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn all_required_commands_parse() {
        let cases = [
            ("status", Command::Status),
            ("run", Command::Run),
            ("health", Command::Health),
            ("inspect-proof", Command::InspectProof),
            ("inspect-store", Command::InspectStore),
            ("simulate-failure", Command::SimulateFailure),
        ];
        for (name, expected) in cases {
            let parsed = parse_args([name]);
            assert!(matches!(parsed, Ok(cli) if cli.command() == expected));
        }
    }

    #[test]
    fn run_without_configuration_fails_with_stable_reason() {
        let (code, _, stderr) = output(&["run"]);
        assert_eq!(code, EXIT_UNAVAILABLE);
        assert!(stderr.contains(REASON_CONFIG_MISSING));
    }

    #[test]
    fn present_paths_still_cannot_enable_unimplemented_service() {
        let executable = match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => std::process::abort(),
        };
        let store = std::env::temp_dir();
        let arguments = vec![
            String::from("run"),
            String::from("--config"),
            executable.to_string_lossy().into_owned(),
            String::from("--key"),
            executable.to_string_lossy().into_owned(),
            String::from("--store"),
            store.to_string_lossy().into_owned(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = execute(arguments, &mut stdout, &mut stderr);
        assert_eq!(code, EXIT_UNAVAILABLE);
        assert!(String::from_utf8_lossy(&stderr).contains(REASON_PROTOCOL_UNAVAILABLE));
    }

    #[test]
    fn direct_vote_and_certify_are_explicitly_refused() {
        for command in ["vote", "certify"] {
            let (code, _, stderr) = output(&[command]);
            assert_eq!(code, EXIT_UNAVAILABLE);
            assert!(stderr.contains(REASON_DIRECT_VOTE_DISABLED));
        }
    }

    #[test]
    fn health_is_diagnostic_but_never_claims_readiness() {
        let (code, stdout, _) = output(&["health"]);
        assert_eq!(code, EXIT_NOT_READY);
        assert!(stdout.contains("healthy=false"));
        assert!(stdout.contains("ready=false"));
    }

    #[test]
    fn missing_proof_and_store_paths_are_safe_diagnostics() {
        let (proof_code, proof_stdout, _) = output(&["inspect-proof"]);
        assert_eq!(proof_code, EXIT_MISSING);
        assert!(proof_stdout.contains("verified=false"));
        let (store_code, store_stdout, _) = output(&["inspect-store"]);
        assert_eq!(store_code, EXIT_MISSING);
        assert!(store_stdout.contains("authority=false"));
    }

    #[test]
    fn store_inspection_never_removes_the_live_writer_staging_file() {
        let source = match create_snapshot_directory() {
            Ok(directory) => directory,
            Err(_) => std::process::abort(),
        };
        let paths = StorePaths::new(source.path());
        let mut store = match DurableAuthorityStore::open(paths.clone(), FileBackend) {
            Ok(store) => store,
            Err(_) => std::process::abort(),
        };
        if store.allocate_incarnation(1).is_err() {
            std::process::abort();
        }
        if fs::write(paths.temporary(), b"live-writer-staging").is_err() {
            std::process::abort();
        }

        let path = source.path().to_string_lossy().into_owned();
        let (code, stdout, stderr) = output(&["inspect-store", "--store", &path]);
        assert_eq!(code, 0);
        assert!(stdout.contains("mode=inspection"));
        assert!(stderr.is_empty());
        assert_eq!(fs::read(paths.temporary()).ok().as_deref(), Some(b"live-writer-staging".as_slice()));
    }

    #[test]
    fn malformed_frame_simulation_passes_only_when_refused() {
        let (code, stdout, stderr) = output(&["simulate-failure"]);
        assert_eq!(code, 0);
        assert!(stdout.contains("simulation=pass"));
        assert!(stdout.contains("admitted=false"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn malformed_options_return_usage_error() {
        let (unknown_code, _, unknown_error) = output(&["mystery"]);
        assert_eq!(unknown_code, EXIT_USAGE);
        assert!(unknown_error.contains("CLI_USAGE_ERROR"));
        let (missing_code, _, missing_error) = output(&["status", "--store"]);
        assert_eq!(missing_code, EXIT_USAGE);
        assert!(missing_error.contains("missing value"));

        for arguments in [
            ["status", "--proof", "ignored"],
            ["run", "--proof", "ignored"],
            ["inspect-proof", "--key", "ignored"],
            ["inspect-store", "--config", "ignored"],
            ["simulate-failure", "--store", "ignored"],
        ] {
            let (code, _, error) = output(&arguments);
            assert_eq!(code, EXIT_USAGE);
            assert!(error.contains("not allowed"));
        }
    }

    #[test]
    fn help_names_every_required_command() {
        let (code, stdout, _) = output(&["--help"]);
        assert_eq!(code, 0);
        for command in [
            "status",
            "run",
            "health",
            "inspect-proof",
            "inspect-store",
            "simulate-failure",
        ] {
            assert!(stdout.contains(command));
        }
    }
}
