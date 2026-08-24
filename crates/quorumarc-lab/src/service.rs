use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use quorumarc_runtime::{FrameCodec, FrameError, WitnessVoteActor};
use quorumarc_store::FileBackend;

use crate::protocol::{
    MAX_LAB_FRAME_SIZE, PeerKeyResolver, ProtocolError, VoteRequest, VoteResponse,
};

/// Deterministic blocking-I/O settings for the localhost witness process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessServerConfig {
    io_timeout: Duration,
    max_connections: Option<u64>,
}

impl WitnessServerConfig {
    /// Builds settings with non-zero I/O timeouts.
    pub fn new(io_timeout: Duration, max_connections: Option<u64>) -> Result<Self, ServeError> {
        if io_timeout.is_zero() {
            return Err(ServeError::ZeroTimeout);
        }
        Ok(Self {
            io_timeout,
            max_connections,
        })
    }

    /// Timeout applied to every accepted connection.
    #[must_use]
    pub const fn io_timeout(self) -> Duration {
        self.io_timeout
    }

    /// Optional deterministic connection limit used by bounded CI runs.
    #[must_use]
    pub const fn max_connections(self) -> Option<u64> {
        self.max_connections
    }
}

/// Runs a serialized witness actor on an already-bound loopback listener.
///
/// Each connection carries at most one request and one response. Malformed,
/// oversized, truncated, or disconnected peers are closed without invoking
/// the actor. Authentication failures receive an explicit refusal and likewise
/// cannot change durable state.
pub fn serve_witness<R: PeerKeyResolver>(
    listener: TcpListener,
    actor: &mut WitnessVoteActor<FileBackend>,
    resolver: &R,
    config: WitnessServerConfig,
) -> Result<(), ServeError> {
    let local_address = listener
        .local_addr()
        .map_err(|error| ServeError::io("inspect listener address", error))?;
    ensure_loopback(local_address).map_err(|_| ServeError::NonLoopback(local_address))?;
    let codec = FrameCodec::new(MAX_LAB_FRAME_SIZE).map_err(ServeError::FrameConfig)?;
    let mut accepted = 0_u64;

    loop {
        if config
            .max_connections
            .is_some_and(|maximum| accepted >= maximum)
        {
            return Ok(());
        }
        let (mut stream, peer) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(ServeError::io("accept loopback connection", error)),
            }
        };
        accepted = accepted
            .checked_add(1)
            .ok_or(ServeError::ConnectionCounterExhausted)?;
        if !peer.ip().is_loopback() {
            eprintln!("event=witness_connection code=CONNECTION_REFUSED_NON_LOOPBACK peer={peer}");
            continue;
        }
        if let Err(error) = configure_stream(&stream, config.io_timeout) {
            eprintln!(
                "event=witness_connection code=CONNECTION_REFUSED_CONFIGURATION detail={error}"
            );
            continue;
        }
        if let Err(error) = handle_connection(&mut stream, actor, resolver, codec) {
            eprintln!(
                "event=witness_connection code={} detail={error}",
                error.reason_code()
            );
        }
    }
}

fn handle_connection<R: PeerKeyResolver>(
    stream: &mut TcpStream,
    actor: &mut WitnessVoteActor<FileBackend>,
    resolver: &R,
    codec: FrameCodec,
) -> Result<(), ConnectionError> {
    let payload = match codec.read_frame(stream).map_err(ConnectionError::Frame)? {
        Some(payload) => payload,
        None => return Err(ConnectionError::NoRequest),
    };
    let request = VoteRequest::from_canonical_bytes(&payload).map_err(ConnectionError::Protocol)?;
    let response = if request.verify(resolver).is_ok() {
        VoteResponse::from_actor(request.request_id(), &actor.handle_vote(request.binding()))
    } else {
        VoteResponse::authentication_refused(request.request_id())
    };
    let response_bytes = response
        .to_canonical_bytes()
        .map_err(ConnectionError::Protocol)?;
    codec
        .write_frame(stream, &response_bytes)
        .map_err(ConnectionError::Frame)?;
    eprintln!(
        "event=witness_vote request_id={} code={} durable_generation={}",
        hex_request_id(response.request_id().as_bytes()),
        response.code().as_str(),
        response
            .durable_generation()
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    Ok(())
}

/// Sends one authenticated vote request to a loopback witness.
///
/// A successful return means only that a syntactically valid correlated
/// response arrived. Callers must inspect its decision; this API never opens
/// an effect gate or claims full authority.
pub fn request_vote(
    address: SocketAddr,
    request: &VoteRequest,
    timeout: Duration,
) -> Result<VoteResponse, ClientError> {
    ensure_loopback(address).map_err(|_| ClientError::NonLoopback(address))?;
    if timeout.is_zero() {
        return Err(ClientError::ZeroTimeout);
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| ClientError::io("connect to witness", error))?;
    configure_stream(&stream, timeout)
        .map_err(|error| ClientError::io("configure witness connection", error))?;
    let codec = FrameCodec::new(MAX_LAB_FRAME_SIZE).map_err(ClientError::FrameConfig)?;
    let request_bytes = request
        .to_canonical_bytes()
        .map_err(ClientError::Protocol)?;
    codec
        .write_frame(&mut stream, &request_bytes)
        .map_err(ClientError::Frame)?;
    let response_bytes = codec
        .read_frame(&mut stream)
        .map_err(ClientError::Frame)?
        .ok_or(ClientError::MissingResponse)?;
    let response =
        VoteResponse::from_canonical_bytes(&response_bytes).map_err(ClientError::Protocol)?;
    if response.request_id() != request.request_id() {
        return Err(ClientError::RequestIdMismatch);
    }
    Ok(response)
}

/// Tests only TCP reachability, then closes without sending an authority request.
pub fn probe_loopback(address: SocketAddr, timeout: Duration) -> Result<(), ClientError> {
    ensure_loopback(address).map_err(|_| ClientError::NonLoopback(address))?;
    if timeout.is_zero() {
        return Err(ClientError::ZeroTimeout);
    }
    let stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| ClientError::io("connect loopback probe", error))?;
    stream
        .shutdown(Shutdown::Both)
        .map_err(|error| ClientError::io("close loopback probe", error))
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)
}

fn ensure_loopback(address: SocketAddr) -> Result<(), ()> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(())
    }
}

fn hex_request_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

#[derive(Debug)]
enum ConnectionError {
    NoRequest,
    Frame(FrameError),
    Protocol(ProtocolError),
}

impl ConnectionError {
    const fn reason_code(&self) -> &'static str {
        match self {
            Self::NoRequest => "CONNECTION_CLOSED_WITHOUT_REQUEST",
            Self::Frame(error) => error.reason_code().as_str(),
            Self::Protocol(_) => "REQUEST_REFUSED_MALFORMED",
        }
    }
}

impl Display for ConnectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRequest => formatter.write_str("peer closed without a request"),
            Self::Frame(error) => write!(formatter, "frame error: {error}"),
            Self::Protocol(error) => write!(formatter, "protocol error: {error}"),
        }
    }
}

/// Fatal witness service configuration or listener failure.
#[derive(Debug)]
pub enum ServeError {
    /// Listener was not bound to a loopback address.
    NonLoopback(SocketAddr),
    /// A zero timeout cannot bound stalled peers.
    ZeroTimeout,
    /// Connection accounting overflowed.
    ConnectionCounterExhausted,
    /// The runtime frame bound was invalid.
    FrameConfig(quorumarc_runtime::FrameConfigError),
    /// Listener or filesystem-independent socket I/O failed.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Portable I/O kind.
        kind: io::ErrorKind,
        /// OS diagnostic.
        message: String,
    },
}

impl ServeError {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl Display for ServeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopback(address) => {
                write!(formatter, "witness listener {address} is not loopback")
            }
            Self::ZeroTimeout => formatter.write_str("witness I/O timeout must be non-zero"),
            Self::ConnectionCounterExhausted => {
                formatter.write_str("witness connection counter exhausted")
            }
            Self::FrameConfig(error) => write!(formatter, "invalid witness frame bound: {error}"),
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
        }
    }
}

impl Error for ServeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FrameConfig(error) => Some(error),
            _ => None,
        }
    }
}

/// Fail-closed candidate transport error.
#[derive(Debug)]
pub enum ClientError {
    /// Destination was not a loopback address.
    NonLoopback(SocketAddr),
    /// A zero timeout cannot bound a stalled peer.
    ZeroTimeout,
    /// Runtime frame configuration failed.
    FrameConfig(quorumarc_runtime::FrameConfigError),
    /// Framing or transport I/O failed.
    Frame(FrameError),
    /// Fixed-schema codec rejected a request or response.
    Protocol(ProtocolError),
    /// Peer closed before returning a response.
    MissingResponse,
    /// Response did not echo the exact request ID.
    RequestIdMismatch,
    /// Socket operation failed outside frame processing.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Portable I/O kind.
        kind: io::ErrorKind,
        /// OS diagnostic.
        message: String,
    },
}

impl ClientError {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl Display for ClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopback(address) => write!(formatter, "peer {address} is not loopback"),
            Self::ZeroTimeout => formatter.write_str("client timeout must be non-zero"),
            Self::FrameConfig(error) => write!(formatter, "invalid frame bound: {error}"),
            Self::Frame(error) => write!(formatter, "frame error: {error}"),
            Self::Protocol(error) => write!(formatter, "protocol error: {error}"),
            Self::MissingResponse => formatter.write_str("witness closed without a response"),
            Self::RequestIdMismatch => formatter.write_str("witness response request ID mismatch"),
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FrameConfig(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
