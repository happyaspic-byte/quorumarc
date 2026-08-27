use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::management_journal::{JournalError, ManagementJournal, ManagementOutcome};
use crate::protocol::{AdmissionError, AuthenticatedRequestJournal};
use crate::signal::ShutdownToken;
use crate::tls::MtlsServerConfig;

/// Static three-member Witness membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessMembership {
    node_a_id: String,
    node_a: SocketAddr,
    node_b_id: String,
    node_b: SocketAddr,
    witness_id: String,
    witness: SocketAddr,
}

/// Typed membership refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessMembershipError {
    SharedHost,
    SharedFailureDomain,
    InvalidMember,
    ReservedWitnessHost,
    DuplicateMember,
}

impl WitnessMembership {
    /// Accepts exactly two data nodes and one independent Witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_a_id: impl Into<String>,
        node_a: SocketAddr,
        node_a_domain: &str,
        node_b_id: impl Into<String>,
        node_b: SocketAddr,
        node_b_domain: &str,
        witness_id: impl Into<String>,
        witness: SocketAddr,
        witness_domain: &str,
    ) -> Result<Self, WitnessMembershipError> {
        let node_a_id = node_a_id.into();
        let node_b_id = node_b_id.into();
        let witness_id = witness_id.into();
        if node_a_id.is_empty() || node_b_id.is_empty() || witness_id.is_empty() {
            return Err(WitnessMembershipError::InvalidMember);
        }
        if node_a_id == node_b_id || node_a_id == witness_id || node_b_id == witness_id {
            return Err(WitnessMembershipError::DuplicateMember);
        }
        if same_host(node_a.ip(), witness.ip()) || same_host(node_b.ip(), witness.ip()) {
            return Err(WitnessMembershipError::SharedHost);
        }
        if canonical_ip(witness.ip()) == IpAddr::V4(Ipv4Addr::new(172, 30, 1, 84)) {
            return Err(WitnessMembershipError::ReservedWitnessHost);
        }
        if node_a_domain == witness_domain
            || node_b_domain == witness_domain
            || node_a_domain == node_b_domain
        {
            return Err(WitnessMembershipError::SharedFailureDomain);
        }
        Ok(Self {
            node_a_id,
            node_a,
            node_b_id,
            node_b,
            witness_id,
            witness,
        })
    }

    /// Independent Witness listen address.
    #[must_use]
    pub const fn witness_address(&self) -> SocketAddr {
        self.witness
    }

    /// Node A listen address.
    #[must_use]
    pub const fn node_a_address(&self) -> SocketAddr {
        self.node_a
    }

    /// Node B listen address.
    #[must_use]
    pub const fn node_b_address(&self) -> SocketAddr {
        self.node_b
    }
}

fn same_host(left: IpAddr, right: IpAddr) -> bool {
    canonical_ip(left) == canonical_ip(right)
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
    }
}

const WITNESS_IO_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_WITNESS_CONNECTIONS: usize = 32;
const MAX_WITNESS_FRAME: usize =
    8 + 2 + 1 + 4 * (1 + 128) + 16 + 8 + 8 + 8 + 8 + 32 + 4 + 65_536 + 64;

/// Independent Witness that records authenticated votes without opening effects.
#[derive(Debug)]
pub struct ProductionWitnessRuntime {
    admission: AuthenticatedRequestJournal,
}

impl ProductionWitnessRuntime {
    pub fn open(
        directory: &Path,
        identity: [u8; 16],
        cluster_id: impl Into<String>,
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, JournalError> {
        let journal = ManagementJournal::open(directory, identity)?;
        Ok(Self {
            admission: AuthenticatedRequestJournal::new(
                journal,
                cluster_id,
                workload_id,
                node_id,
                key_id,
                verifying_key,
            ),
        })
    }

    pub fn admit_vote(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        self.admission.admit(bytes)
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.admission.highest_sequence()
    }

    #[must_use]
    pub const fn effects_open(&self) -> bool {
        false
    }
}

/// Errors during Witness server operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessServerError {
    SocketBindFailed,
    SocketServeFailed,
    StateUnavailable,
}

/// Production Witness TCP server with rustls mTLS authentication.
#[derive(Debug)]
pub struct ProductionWitnessServer {
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    runtime: Arc<Mutex<ProductionWitnessRuntime>>,
}

impl ProductionWitnessServer {
    pub fn bind(
        membership: WitnessMembership,
        tls_config: MtlsServerConfig,
        runtime: ProductionWitnessRuntime,
    ) -> Result<Self, WitnessServerError> {
        let listener = TcpListener::bind(membership.witness_address())
            .map_err(|_error| WitnessServerError::SocketBindFailed)?;
        Ok(Self {
            listener,
            tls_config: tls_config.into_arc(),
            runtime: Arc::new(Mutex::new(runtime)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, WitnessServerError> {
        self.listener
            .local_addr()
            .map_err(|_error| WitnessServerError::SocketBindFailed)
    }

    pub fn serve_until(self, shutdown: &ShutdownToken) -> Result<(), WitnessServerError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_error| WitnessServerError::SocketServeFailed)?;
        let mut workers = Vec::new();
        while !shutdown.is_requested() {
            reap_finished_workers(&mut workers);
            match self.listener.accept() {
                Ok((stream, _addr)) if workers.len() < MAX_WITNESS_CONNECTIONS => {
                    let control = stream
                        .try_clone()
                        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
                    let tls_config = Arc::clone(&self.tls_config);
                    let runtime = Arc::clone(&self.runtime);
                    let handle = thread::Builder::new()
                        .name("quorumarc-witness-conn".to_owned())
                        .spawn(move || {
                            let _ = serve_stream(stream, tls_config, runtime);
                        })
                        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
                    workers.push(ConnectionWorker { control, handle });
                }
                Ok((stream, _addr)) => {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    shutdown.wait_timeout(Duration::from_millis(20));
                }
                Err(_error) => return Err(WitnessServerError::SocketServeFailed),
            }
        }
        for worker in &workers {
            let _ = worker.control.shutdown(Shutdown::Both);
        }
        for worker in workers {
            let _ = worker.handle.join();
        }
        Ok(())
    }
}

struct ConnectionWorker {
    control: TcpStream,
    handle: JoinHandle<()>,
}

fn reap_finished_workers(workers: &mut Vec<ConnectionWorker>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].handle.is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.handle.join();
        } else {
            index += 1;
        }
    }
}

fn serve_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    runtime: Arc<Mutex<ProductionWitnessRuntime>>,
) -> Result<(), WitnessServerError> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(WITNESS_IO_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(WITNESS_IO_TIMEOUT)))
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let connection = ServerConnection::new(tls_config)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut length = [0_u8; 4];
    tls.read_exact(&mut length)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let frame_len = u32::from_be_bytes(length) as usize;
    if frame_len == 0 || frame_len > MAX_WITNESS_FRAME {
        return write_witness_response(&mut tls, b"MALFORMED\n");
    }
    let mut frame = vec![0_u8; frame_len];
    tls.read_exact(&mut frame)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let response = {
        let mut runtime = runtime
            .lock()
            .map_err(|_error| WitnessServerError::StateUnavailable)?;
        match runtime.admit_vote(&frame) {
            Ok(ManagementOutcome::Committed) => b"COMMITTED\n".as_slice(),
            Ok(ManagementOutcome::AlreadyDurable) => b"ALREADY_DURABLE\n".as_slice(),
            Err(AdmissionError::Malformed) => b"MALFORMED\n".as_slice(),
            Err(AdmissionError::AuthenticationFailed) => b"AUTHENTICATION_FAILED\n".as_slice(),
            Err(AdmissionError::ReplayRefused) => b"REPLAY_REFUSED\n".as_slice(),
        }
    };
    write_witness_response(&mut tls, response)
}

fn write_witness_response(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    response: &[u8],
) -> Result<(), WitnessServerError> {
    let length =
        u32::try_from(response.len()).map_err(|_error| WitnessServerError::SocketServeFailed)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(response))
        .and_then(|()| stream.flush())
        .map_err(|_error| WitnessServerError::SocketServeFailed)
}
