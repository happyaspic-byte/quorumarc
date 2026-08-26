use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use quorumarc_lab::{
    RequestId, TEST_KEY_ID, TestPeerKeys, VoteRequest, WitnessServerConfig, lab_binding,
    lab_policy, lab_witness_signing_key, lab_witness_store_identity, probe_loopback, request_vote,
    serve_witness,
};
use quorumarc_runtime::WitnessVoteActor;
use quorumarc_store::FileBackend;
use quorumarc_wire::CanonicalId;

const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("quorumarc-lab: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    let mut arguments = env::args().skip(1);
    let mode = arguments.next().ok_or(CliError::Usage)?;
    let options = ParsedOptions::parse(arguments.collect())?;
    match mode.as_str() {
        "witness" => run_witness(options),
        "candidate" => run_candidate(options),
        "probe" => run_probe(options),
        _ => Err(CliError::UnknownMode(mode)),
    }
}

fn run_witness(mut options: ParsedOptions) -> Result<(), CliError> {
    let store = PathBuf::from(options.required("--store")?);
    let ready_file = PathBuf::from(options.required("--ready-file")?);
    let listen = parse_socket(
        &options
            .optional("--listen")
            .unwrap_or_else(|| "127.0.0.1:0".to_owned()),
        "--listen",
    )?;
    let max_connections = options
        .optional("--max-connections")
        .map(|value| parse_number::<u64>(&value, "--max-connections"))
        .transpose()?;
    options.finish()?;
    if !listen.ip().is_loopback() {
        return Err(CliError::NonLoopback(listen));
    }

    let mut actor = WitnessVoteActor::open(
        lab_policy().map_err(CliError::boxed)?,
        lab_witness_signing_key(),
        store,
        lab_witness_store_identity().map_err(CliError::boxed)?,
        FileBackend,
    )
    .map_err(CliError::boxed)?;
    let listener =
        TcpListener::bind(listen).map_err(|error| CliError::io("bind witness", error))?;
    let actual = listener
        .local_addr()
        .map_err(|error| CliError::io("inspect witness address", error))?;
    if !actual.ip().is_loopback() {
        return Err(CliError::NonLoopback(actual));
    }
    publish_ready_file(&ready_file, actual)?;
    let config = WitnessServerConfig::new(IO_TIMEOUT, max_connections).map_err(CliError::boxed)?;
    serve_witness(listener, &mut actor, &TestPeerKeys, config).map_err(CliError::boxed)
}

fn publish_ready_file(path: &Path, address: SocketAddr) -> Result<(), CliError> {
    let mut temporary_name = path.as_os_str().to_os_string();
    temporary_name.push(format!(".tmp.{}", std::process::id()));
    let temporary_path = PathBuf::from(temporary_name);
    match fs::remove_file(&temporary_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(CliError::io("remove stale witness ready temp file", error)),
    }
    fs::write(&temporary_path, address.to_string())
        .map_err(|error| CliError::io("write witness ready temp file", error))?;
    fs::rename(&temporary_path, path)
        .map_err(|error| CliError::io("publish witness ready file", error))
}

fn run_candidate(mut options: ParsedOptions) -> Result<(), CliError> {
    let address = parse_socket(&options.required("--connect")?, "--connect")?;
    let candidate_text = options.required("--candidate")?;
    let epoch = options
        .optional("--epoch")
        .map_or(Ok(1_u64), |value| parse_number(&value, "--epoch"))?;
    let message_byte = options
        .optional("--message-byte")
        .map_or(Ok(1_u8), |value| {
            parse_nonzero_byte(&value, "--message-byte")
        })?;
    let request_byte = options
        .optional("--request-byte")
        .map_or(Ok(1_u8), |value| {
            parse_nonzero_byte(&value, "--request-byte")
        })?;
    options.finish()?;

    let candidate = CanonicalId::new(&candidate_text).map_err(CliError::boxed)?;
    let signing_key = TestPeerKeys::candidate_signing_key(&candidate)
        .ok_or_else(|| CliError::UnknownTestCandidate(candidate_text.clone()))?;
    let key_id = CanonicalId::new(TEST_KEY_ID).map_err(CliError::boxed)?;
    let binding = lab_binding(&candidate_text, epoch, message_byte).map_err(CliError::boxed)?;
    let request = VoteRequest::sign(
        RequestId::new([request_byte; 16]).map_err(CliError::boxed)?,
        binding,
        key_id,
        &signing_key,
    )
    .map_err(CliError::boxed)?;
    let response = request_vote(address, &request, IO_TIMEOUT).map_err(CliError::boxed)?;
    println!(
        "request_id={request_byte:02x} code={} durable_generation={} authority=false",
        response.code().as_str(),
        response
            .durable_generation()
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    Ok(())
}

fn run_probe(mut options: ParsedOptions) -> Result<(), CliError> {
    let address = parse_socket(&options.required("--connect")?, "--connect")?;
    options.finish()?;
    probe_loopback(address, IO_TIMEOUT).map_err(CliError::boxed)?;
    println!("code=PROBE_CONNECTED authority=false");
    Ok(())
}

fn parse_socket(value: &str, option: &'static str) -> Result<SocketAddr, CliError> {
    SocketAddr::from_str(value).map_err(|_| CliError::InvalidValue {
        option,
        value: value.to_owned(),
    })
}

fn parse_number<T: FromStr>(value: &str, option: &'static str) -> Result<T, CliError> {
    value.parse::<T>().map_err(|_| CliError::InvalidValue {
        option,
        value: value.to_owned(),
    })
}

fn parse_nonzero_byte(value: &str, option: &'static str) -> Result<u8, CliError> {
    let byte = parse_number::<u8>(value, option)?;
    if byte == 0 {
        Err(CliError::InvalidValue {
            option,
            value: value.to_owned(),
        })
    } else {
        Ok(byte)
    }
}

struct ParsedOptions {
    values: BTreeMap<String, String>,
}

impl ParsedOptions {
    fn parse(arguments: Vec<String>) -> Result<Self, CliError> {
        let mut values = BTreeMap::new();
        let mut iterator = arguments.into_iter();
        while let Some(option) = iterator.next() {
            if !option.starts_with("--") {
                return Err(CliError::UnexpectedArgument(option));
            }
            let value = iterator
                .next()
                .ok_or_else(|| CliError::MissingValue(option.clone()))?;
            if values.insert(option.clone(), value).is_some() {
                return Err(CliError::DuplicateOption(option));
            }
        }
        Ok(Self { values })
    }

    fn required(&mut self, option: &'static str) -> Result<String, CliError> {
        self.values
            .remove(option)
            .ok_or(CliError::MissingOption(option))
    }

    fn optional(&mut self, option: &'static str) -> Option<String> {
        self.values.remove(option)
    }

    fn finish(self) -> Result<(), CliError> {
        match self.values.into_keys().next() {
            Some(option) => Err(CliError::UnknownOption(option)),
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage,
    UnknownMode(String),
    UnexpectedArgument(String),
    MissingValue(String),
    DuplicateOption(String),
    MissingOption(&'static str),
    UnknownOption(String),
    InvalidValue {
        option: &'static str,
        value: String,
    },
    UnknownTestCandidate(String),
    NonLoopback(SocketAddr),
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
        message: String,
    },
    Other(Box<dyn Error + Send + Sync>),
}

impl CliError {
    fn boxed(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Other(Box::new(error))
    }

    fn io(operation: &'static str, error: std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter
                .write_str("usage: quorumarc-lab <witness|candidate|probe> [--option value ...]"),
            Self::UnknownMode(mode) => write!(formatter, "unknown mode {mode}"),
            Self::UnexpectedArgument(argument) => {
                write!(formatter, "unexpected argument {argument}")
            }
            Self::MissingValue(option) => write!(formatter, "missing value for {option}"),
            Self::DuplicateOption(option) => write!(formatter, "duplicate option {option}"),
            Self::MissingOption(option) => write!(formatter, "missing required option {option}"),
            Self::UnknownOption(option) => write!(formatter, "unknown option {option}"),
            Self::InvalidValue { option, value } => {
                write!(formatter, "invalid value {value} for {option}")
            }
            Self::UnknownTestCandidate(candidate) => write!(
                formatter,
                "candidate {candidate} has no deterministic lab key"
            ),
            Self::NonLoopback(address) => {
                write!(formatter, "address {address} is not loopback")
            }
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
            Self::Other(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Other(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
