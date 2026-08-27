use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use quorumarc_rpo0::{
    DurableReceipt, FileReplica, OperationId, ReplicaError, ReplicaSink, WalEntry,
};
use quorumarc_runtime::FrameCodec;
use quorumarc_wire::{SigningKey, VerifyingKey};

use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::path_guard::{
    OwnerLock, prepare_file_parent, require_keys_disjoint, require_ready_disjoint, write_ready_file,
};
use crate::protocol::{
    LAB_CANDIDATE, LAB_KEY_ID, LAB_PEER, LAB_POLICY_HASH, LAB_REQUEST_ID, LAB_WORKLOAD,
    MAX_CLUSTER_FRAME, PeerDecision, PeerRequest, PeerResponse, first_record_state_root,
    record_checksum,
};
use crate::{ClusterError, err};

/// Bounded localhost peer service configuration.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub wal_path: PathBuf,
    pub signing_key_file: PathBuf,
    pub candidate_public_key_file: PathBuf,
    pub max_connections: u64,
    pub io_timeout: Duration,
}

/// Runs Node B's one-operation durable replica endpoint.
pub fn serve_peer(config: PeerConfig) -> Result<(), ClusterError> {
    ensure_loopback(config.listen)?;
    ensure_timeout(config.io_timeout)?;
    if config.max_connections == 0 {
        return Err(err("PEER_CONFIG_REFUSED", "connection bound is zero"));
    }
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.candidate_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.candidate_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    let signing_key = load_private_seed(&config.signing_key_file)?;
    let candidate_key = load_public_key(&config.candidate_public_key_file)?;
    let peer_key = signing_key.verifying_key();
    require_distinct_role_keys(&[("peer", &peer_key), ("candidate", &candidate_key)])?;
    prepare_file_parent(&config.wal_path)?;
    let _wal_lock = OwnerLock::for_file(&config.wal_path, "peer")?;
    let mut wal_state = inspect_peer_wal(&config.wal_path)?;
    let listener = TcpListener::bind(config.listen)
        .map_err(|error| err("PEER_BIND_FAILED", format!("{}: {error}", config.listen)))?;
    let local = listener
        .local_addr()
        .map_err(|error| err("PEER_BIND_FAILED", error.to_string()))?;
    ensure_loopback(local)?;
    let codec = FrameCodec::new(MAX_CLUSTER_FRAME)
        .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
    let mut replica = FileReplica::new(LAB_PEER, &config.wal_path);

    // Readiness is published only after key checks, path checks, exclusive WAL
    // ownership, listener binding, frame construction and replica creation.
    write_ready_file(&config.ready_file, &local.to_string())?;

    for _ in 0..config.max_connections {
        let (mut stream, remote) = accept(&listener)?;
        if !remote.ip().is_loopback() {
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        if let Err(error) = handle_peer_connection(
            &mut stream,
            codec,
            &candidate_key,
            &signing_key,
            &mut replica,
            &mut wal_state,
        ) {
            eprintln!("event=peer_request {error}");
        }
    }
    Ok(())
}

fn handle_peer_connection(
    stream: &mut TcpStream,
    codec: FrameCodec,
    candidate_key: &VerifyingKey,
    signing_key: &SigningKey,
    replica: &mut FileReplica,
    wal_state: &mut PeerWalState,
) -> Result<(), ClusterError> {
    let payload = codec
        .read_frame(stream)
        .map_err(|error| err("PEER_FRAME_REFUSED", error.to_string()))?
        .ok_or_else(|| err("PEER_REQUEST_MISSING", "connection closed without request"))?;
    let request = PeerRequest::from_bytes(&payload)?;
    request.verify(candidate_key)?;

    let (decision, commit_index, checksum) = if request_in_scope(&request) {
        match persist_or_confirm(replica, wal_state, &request) {
            Ok(receipt) => (
                PeerDecision::Durable,
                receipt.commit_index,
                receipt.record_checksum,
            ),
            Err(error) => {
                eprintln!("event=peer_durability code=PEER_DURABILITY_REFUSED detail={error}");
                (PeerDecision::RefusedDurability, 0, 0)
            }
        }
    } else {
        (PeerDecision::RefusedScope, 0, 0)
    };
    let response = PeerResponse::sign(&request, decision, commit_index, checksum, signing_key)?;
    codec
        .write_frame(stream, &response.to_bytes()?)
        .map_err(|error| err("PEER_FRAME_WRITE_FAILED", error.to_string()))?;
    eprintln!("event=peer_replication code={decision:?} commit_index={commit_index}");
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerWalState {
    Empty,
    ExactDurableTail,
}

fn inspect_peer_wal(path: &Path) -> Result<PeerWalState, ClusterError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(err("PEER_WAL_RECOVERY_REFUSED", error.to_string())),
    };
    if bytes.is_empty() {
        return Ok(PeerWalState::Empty);
    }
    if bytes == expected_entry().encode() {
        return Ok(PeerWalState::ExactDurableTail);
    }
    Err(err(
        "PEER_WAL_RECOVERY_REFUSED",
        "WAL is not empty or the exact one-shot durable tail; repair is required",
    ))
}

fn persist_or_confirm(
    replica: &mut FileReplica,
    wal_state: &mut PeerWalState,
    request: &PeerRequest,
) -> Result<DurableReceipt, ReplicaError> {
    match wal_state {
        PeerWalState::Empty => {
            let receipt = replica.append_and_flush(request.entry(), request.canonical_record())?;
            *wal_state = PeerWalState::ExactDurableTail;
            Ok(receipt)
        }
        PeerWalState::ExactDurableTail => {
            replica.append_and_flush(request.entry(), request.canonical_record())
        }
    }
}

fn expected_entry() -> WalEntry {
    WalEntry {
        commit_index: 1,
        operation_id: OperationId::new([9; 16]),
        previous_value: 0,
        increment: 1,
        value: 1,
    }
}

fn request_in_scope(request: &PeerRequest) -> bool {
    let entry = request.entry();
    request.request_id() == &LAB_REQUEST_ID
        && request.sender_id().as_str() == LAB_CANDIDATE
        && request.key_id().as_str() == LAB_KEY_ID
        && request.workload_id().as_str() == LAB_WORKLOAD
        && request.policy_hash() == &LAB_POLICY_HASH
        && entry.commit_index == 1
        && entry.operation_id.into_bytes() == [9; 16]
        && entry.previous_value == 0
        && entry.increment == 1
        && entry.value == 1
        && request.canonical_record() == entry.encode()
        && entry == &expected_entry()
        && request.expected_state_root() == &first_record_state_root(request.canonical_record())
}

pub(crate) struct RemotePeerReplica {
    address: SocketAddr,
    timeout: Duration,
    signing_key: SigningKey,
    peer_key: VerifyingKey,
}

impl RemotePeerReplica {
    pub(crate) const fn new(
        address: SocketAddr,
        timeout: Duration,
        signing_key: SigningKey,
        peer_key: VerifyingKey,
    ) -> Self {
        Self {
            address,
            timeout,
            signing_key,
            peer_key,
        }
    }

    fn replicate(
        &self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ClusterError> {
        ensure_loopback(self.address)?;
        ensure_timeout(self.timeout)?;
        let request =
            PeerRequest::sign(entry.clone(), canonical_record.to_vec(), &self.signing_key)?;
        let mut stream = TcpStream::connect_timeout(&self.address, self.timeout)
            .map_err(|error| err("PEER_CONNECT_FAILED", format!("{}: {error}", self.address)))?;
        configure_stream(&stream, self.timeout)?;
        let codec = FrameCodec::new(MAX_CLUSTER_FRAME)
            .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
        codec
            .write_frame(&mut stream, &request.to_bytes()?)
            .map_err(|error| err("PEER_FRAME_WRITE_FAILED", error.to_string()))?;
        let response_bytes = codec
            .read_frame(&mut stream)
            .map_err(|error| err("PEER_FRAME_REFUSED", error.to_string()))?
            .ok_or_else(|| err("PEER_RESPONSE_MISSING", "peer closed without response"))?;
        let response = PeerResponse::from_bytes(&response_bytes)?;
        response.verify(&request, &self.peer_key)?;
        if response.decision() != PeerDecision::Durable {
            return Err(err(
                "PEER_DURABILITY_REFUSED",
                format!("peer decision was {:?}", response.decision()),
            ));
        }
        let expected_checksum = record_checksum(canonical_record)?;
        if response.commit_index() != entry.commit_index
            || response.record_checksum() != expected_checksum
        {
            return Err(err(
                "PEER_RECEIPT_REFUSED",
                "durable receipt does not bind exact WAL record",
            ));
        }
        Ok(DurableReceipt {
            replica_id: LAB_PEER.to_owned(),
            commit_index: response.commit_index(),
            record_checksum: response.record_checksum(),
        })
    }
}

impl ReplicaSink for RemotePeerReplica {
    fn replica_id(&self) -> &str {
        LAB_PEER
    }

    fn append_and_flush(
        &mut self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ReplicaError> {
        self.replicate(entry, canonical_record)
            .map_err(|error| ReplicaError::Io(io::Error::other(error.to_string())))
    }
}

fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), ClusterError> {
    loop {
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(err("PEER_ACCEPT_FAILED", error.to_string())),
        }
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), ClusterError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|error| err("SOCKET_CONFIG_FAILED", error.to_string()))
}

fn ensure_loopback(address: SocketAddr) -> Result<(), ClusterError> {
    if !address.ip().is_loopback() {
        return Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost lab"),
        ));
    }
    Ok(())
}

fn ensure_timeout(timeout: Duration) -> Result<(), ClusterError> {
    if timeout.is_zero() {
        return Err(err("TIMEOUT_REFUSED", "I/O timeout is zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn exact_durable_tail_retry_is_resynchronised_without_duplicate_append() {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "quorumarc-cluster-peer-retry-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create retry directory");
        let path = root.join("peer.wal");
        let entry = expected_entry();
        let bytes = entry.encode();
        fs::write(&path, &bytes).expect("write exact durable tail");
        let mut state = inspect_peer_wal(&path).expect("inspect exact tail");
        assert_eq!(state, PeerWalState::ExactDurableTail);
        let candidate = SigningKey::from_bytes(&[11; 32]);
        let request =
            PeerRequest::sign(entry, bytes.clone(), &candidate).expect("sign exact retry");
        let mut replica = FileReplica::new(LAB_PEER, &path);
        let receipt = persist_or_confirm(&mut replica, &mut state, &request)
            .expect("resynchronise exact retry");
        assert_eq!(receipt.commit_index, 1);
        assert_eq!(fs::read(&path).expect("read retry WAL"), bytes);
        fs::remove_dir_all(root).expect("remove retry directory");
    }
}
