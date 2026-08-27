use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use quorumarc_rpo0::{
    AcknowledgedWrite, CounterOperation, DurableReceipt, FileReplica, OperationPreflight,
    ReplicaError, ReplicaSink, ReplicatedCounter, Rpo0Error, WalEntry,
};
use quorumarc_runtime::FrameCodec;

use super::protocol::{
    ClientDecision, ClientRequest, ClientResponse, MAX_CONTINUOUS_FRAME, ReplicaDecision,
    ReplicaRequest, ReplicaResponse,
};
use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::lab_net::{LabBindPolicy, ensure_lab_bind, ensure_lab_peer};
use crate::path_guard::{
    OwnerLock, prepare_file_parent, require_keys_disjoint, require_ready_disjoint, write_ready_file,
};
use crate::{ClusterError, err};

#[derive(Clone, Debug)]
pub struct ContinuousPrimaryConfig {
    pub bind_policy: LabBindPolicy,
    pub expected_client_ips: Vec<std::net::IpAddr>,
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub wal_path: PathBuf,
    pub signing_key_file: PathBuf,
    pub client_public_key_file: PathBuf,
    pub replica_public_key_file: PathBuf,
    pub replica_address: SocketAddr,
    pub max_connections: u64,
    pub io_timeout: Duration,
    pub policy_hash: [u8; 32],
}

pub fn serve_continuous_primary(config: ContinuousPrimaryConfig) -> Result<(), ClusterError> {
    ensure_config(&config)?;
    let signing_key = load_private_seed(&config.signing_key_file)?;
    let client_key = load_public_key(&config.client_public_key_file)?;
    let replica_key = load_public_key(&config.replica_public_key_file)?;
    require_distinct_role_keys(&[
        ("continuous-primary", &signing_key.verifying_key()),
        ("continuous-client", &client_key),
        ("continuous-replica", &replica_key),
    ])?;
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.client_public_key_file.as_path(),
            config.replica_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.client_public_key_file.as_path(),
            config.replica_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    prepare_file_parent(&config.wal_path)?;
    let _wal_lock = OwnerLock::for_file(&config.wal_path, "continuous-primary")?;
    let local = FileReplica::new("continuous-primary", &config.wal_path);
    let mut remote = RemoteContinuousReplica::new(
        config.replica_address,
        config.bind_policy,
        config.io_timeout,
        signing_key.clone(),
        replica_key,
        config.policy_hash,
    );
    let (local_recovered, _) = local
        .recover_and_sync()
        .map_err(|error| err("CONTINUOUS_PRIMARY_WAL_REFUSED", error.to_string()))?;
    let remote_recovered = remote
        .query_progress()
        .map_err(|error| err("CONTINUOUS_PRIMARY_RECOVERY_REFUSED", error.to_string()))?;
    let counter = ReplicatedCounter::from_recovered_with_replica_ids(
        local_recovered,
        remote_recovered,
        "continuous-primary",
        "continuous-replica",
    )
    .map_err(|error| err("CONTINUOUS_PRIMARY_RECOVERY_REFUSED", error.to_string()))?;
    remote.close_session();
    let mut coordinator = ContinuousCoordinator {
        counter,
        local,
        remote,
        uncertain_operation: None,
    };
    let listener = TcpListener::bind(config.listen).map_err(|error| {
        err(
            "CONTINUOUS_PRIMARY_BIND_FAILED",
            format!("{}: {error}", config.listen),
        )
    })?;
    let address = listener
        .local_addr()
        .map_err(|error| err("CONTINUOUS_PRIMARY_BIND_FAILED", error.to_string()))?;
    ensure_lab_bind(config.bind_policy, address)?;
    let codec = FrameCodec::new(MAX_CONTINUOUS_FRAME)
        .map_err(|error| err("CONTINUOUS_FRAME_CONFIG_FAILED", error.to_string()))?;
    write_ready_file(&config.ready_file, &address.to_string())?;

    for _ in 0..config.max_connections {
        let (mut stream, remote_address) = listener
            .accept()
            .map_err(|error| err("CONTINUOUS_PRIMARY_ACCEPT_FAILED", error.to_string()))?;
        if let Err(error) = ensure_lab_peer(
            config.bind_policy,
            remote_address,
            &config.expected_client_ips,
        ) {
            eprintln!("event=continuous_primary_peer_refusal {error}");
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        if let Err(error) = handle_client(
            &mut stream,
            codec,
            &config,
            &client_key,
            &signing_key,
            &mut coordinator,
        ) {
            eprintln!("event=continuous_primary_refusal {error}");
        }
    }
    Ok(())
}

fn handle_client(
    stream: &mut TcpStream,
    codec: FrameCodec,
    config: &ContinuousPrimaryConfig,
    client_key: &quorumarc_wire::VerifyingKey,
    signing_key: &quorumarc_wire::SigningKey,
    coordinator: &mut ContinuousCoordinator,
) -> Result<(), ClusterError> {
    let payload = codec
        .read_frame(stream)
        .map_err(|error| err("CONTINUOUS_PRIMARY_FRAME_REFUSED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "CONTINUOUS_CLIENT_REQUEST_MISSING",
                "client closed without request",
            )
        })?;
    let request = ClientRequest::from_bytes(&payload)?;
    request.verify(client_key)?;
    if request.policy_hash != config.policy_hash {
        return Err(err(
            "CONTINUOUS_CLIENT_SCOPE_REFUSED",
            "client policy differs from primary policy",
        ));
    }
    let response = match coordinator.apply(request.operation) {
        Ok(acknowledged) => {
            if acknowledged.replica_receipts[0].replica_id != "continuous-primary"
                || acknowledged.replica_receipts[1].replica_id != "continuous-replica"
            {
                return Err(err(
                    "CONTINUOUS_ACK_RECEIPTS_REFUSED",
                    "acknowledgement receipts are not identity-distinct dual durable copies",
                ));
            }
            ClientResponse::sign(
                &request,
                ClientDecision::Acknowledged,
                acknowledged.commit_index,
                acknowledged.value,
                acknowledged.state_root,
                [
                    acknowledged.replica_receipts[0].record_checksum,
                    acknowledged.replica_receipts[1].record_checksum,
                ],
                signing_key,
            )?
        }
        Err(ContinuousApplyError::Refused(_error)) => ClientResponse::sign(
            &request,
            ClientDecision::Refused,
            coordinator.counter.commit_index(),
            coordinator.counter.value(),
            coordinator.counter.state_root(),
            [0, 0],
            signing_key,
        )?,
        Err(ContinuousApplyError::Unknown(_error)) => ClientResponse::sign(
            &request,
            ClientDecision::Unknown,
            coordinator.counter.commit_index(),
            coordinator.counter.value(),
            coordinator.counter.state_root(),
            [0, 0],
            signing_key,
        )?,
    };
    codec
        .write_frame(stream, &response.to_bytes()?)
        .map_err(|error| err("CONTINUOUS_PRIMARY_FRAME_WRITE_FAILED", error.to_string()))?;
    Ok(())
}

struct ContinuousCoordinator {
    counter: ReplicatedCounter,
    local: FileReplica,
    remote: RemoteContinuousReplica,
    uncertain_operation: Option<CounterOperation>,
}

impl ContinuousCoordinator {
    fn apply(
        &mut self,
        operation: CounterOperation,
    ) -> Result<AcknowledgedWrite, ContinuousApplyError> {
        if let Some(pending) = self.uncertain_operation {
            if pending.id == operation.id && pending != operation {
                return Err(ContinuousApplyError::Refused(
                    Rpo0Error::ConflictingDuplicate(operation.id),
                ));
            }
            if pending != operation {
                return Err(ContinuousApplyError::Unknown(
                    "another operation has unresolved durability".to_owned(),
                ));
            }
            return self.recover_uncertain(operation);
        }
        let preflight = match self.counter.preflight(operation) {
            Ok(preflight) => preflight,
            Err(error) => return Err(ContinuousApplyError::Refused(error)),
        };
        if let OperationPreflight::Exact(acknowledgement) = preflight {
            return Ok(acknowledgement);
        }
        let (local_recovered, _) = self
            .local
            .recover_and_sync()
            .map_err(|error| ContinuousApplyError::Unknown(error.to_string()))?;
        let remote_recovered = match self.remote.query_progress() {
            Ok(recovered) => recovered,
            Err(error) => {
                self.remote.close_session();
                return Err(ContinuousApplyError::Unknown(error.to_string()));
            }
        };
        if local_recovered != remote_recovered
            || local_recovered.commit_index != self.counter.commit_index()
            || local_recovered.state_root != self.counter.state_root()
        {
            self.remote.close_session();
            return Err(ContinuousApplyError::Refused(Rpo0Error::RecoveryMismatch));
        }
        let result = self
            .counter
            .apply(operation, &mut self.local, &mut self.remote);
        self.remote.close_session();
        match result {
            Ok(acknowledgement) => Ok(acknowledgement),
            Err(error) => {
                self.uncertain_operation = Some(operation);
                Err(ContinuousApplyError::Unknown(error.to_string()))
            }
        }
    }

    fn recover_uncertain(
        &mut self,
        operation: CounterOperation,
    ) -> Result<AcknowledgedWrite, ContinuousApplyError> {
        let (local, _) = self
            .local
            .recover_and_sync()
            .map_err(|error| ContinuousApplyError::Unknown(error.to_string()))?;
        let remote = match self.remote.query_progress() {
            Ok(remote) => remote,
            Err(error) => {
                self.remote.close_session();
                return Err(ContinuousApplyError::Unknown(error.to_string()));
            }
        };
        self.remote.close_session();
        let rebuilt = ReplicatedCounter::from_recovered_with_replica_ids(
            local,
            remote,
            "continuous-primary",
            "continuous-replica",
        )
        .map_err(|error| ContinuousApplyError::Unknown(error.to_string()))?;
        match rebuilt.preflight(operation) {
            Ok(OperationPreflight::Exact(acknowledgement)) => {
                self.counter = rebuilt;
                self.uncertain_operation = None;
                Ok(acknowledgement)
            }
            Ok(OperationPreflight::Fresh) => {
                self.counter = rebuilt;
                self.uncertain_operation = None;
                self.apply(operation)
            }
            Err(error) => Err(ContinuousApplyError::Refused(error)),
        }
    }
}

enum ContinuousApplyError {
    Refused(Rpo0Error),
    Unknown(String),
}

struct RemoteContinuousReplica {
    address: SocketAddr,
    bind_policy: LabBindPolicy,
    timeout: Duration,
    signing_key: quorumarc_wire::SigningKey,
    replica_key: quorumarc_wire::VerifyingKey,
    policy_hash: [u8; 32],
    next_request: u64,
    session: Option<TcpStream>,
}

impl RemoteContinuousReplica {
    fn new(
        address: SocketAddr,
        bind_policy: LabBindPolicy,
        timeout: Duration,
        signing_key: quorumarc_wire::SigningKey,
        replica_key: quorumarc_wire::VerifyingKey,
        policy_hash: [u8; 32],
    ) -> Self {
        Self {
            address,
            bind_policy,
            timeout,
            signing_key,
            replica_key,
            policy_hash,
            next_request: 1,
            session: None,
        }
    }

    fn close_session(&mut self) {
        self.session = None;
    }

    fn query_progress(&mut self) -> Result<quorumarc_rpo0::RecoveredCounter, ClusterError> {
        let request = ReplicaRequest::query(
            replica_request_id(self.next_request),
            self.policy_hash,
            &self.signing_key,
        )?;
        self.next_request = self.next_request.checked_add(1).ok_or_else(|| {
            err(
                "CONTINUOUS_REQUEST_EXHAUSTED",
                "replica request counter overflow",
            )
        })?;
        let response = self.exchange(&request)?;
        if response.decision != ReplicaDecision::Progress {
            return Err(err(
                "CONTINUOUS_REPLICA_PROGRESS_REFUSED",
                "replica did not return progress",
            ));
        }
        response.recovered()
    }

    fn exchange(&mut self, request: &ReplicaRequest) -> Result<ReplicaResponse, ClusterError> {
        if self.session.is_none() {
            ensure_lab_bind(self.bind_policy, self.address)?;
            let stream =
                TcpStream::connect_timeout(&self.address, self.timeout).map_err(|error| {
                    err(
                        "CONTINUOUS_REPLICA_UNAVAILABLE",
                        format!("{}: {error}", self.address),
                    )
                })?;
            configure_stream(&stream, self.timeout)?;
            self.session = Some(stream);
        }
        let stream = self.session.as_mut().ok_or_else(|| {
            err(
                "CONTINUOUS_REPLICA_UNAVAILABLE",
                "replica session is unavailable",
            )
        })?;
        let codec = FrameCodec::new(MAX_CONTINUOUS_FRAME)
            .map_err(|error| err("CONTINUOUS_FRAME_CONFIG_FAILED", error.to_string()))?;
        if let Err(error) = codec.write_frame(stream, &request.to_bytes()?) {
            self.session = None;
            return Err(err(
                "CONTINUOUS_REPLICA_FRAME_WRITE_FAILED",
                error.to_string(),
            ));
        }
        let response_bytes = match codec.read_frame(stream) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                self.session = None;
                return Err(err(
                    "CONTINUOUS_REPLICA_RESPONSE_MISSING",
                    "replica closed without response",
                ));
            }
            Err(error) => {
                self.session = None;
                return Err(err("CONTINUOUS_REPLICA_FRAME_REFUSED", error.to_string()));
            }
        };
        let response = ReplicaResponse::from_bytes(&response_bytes)?;
        response.verify(request, &self.replica_key)?;
        Ok(response)
    }
}

impl ReplicaSink for RemoteContinuousReplica {
    fn replica_id(&self) -> &str {
        "continuous-replica"
    }

    fn append_and_flush(
        &mut self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ReplicaError> {
        let request = ReplicaRequest::append(
            replica_request_id(self.next_request),
            self.policy_hash,
            entry.clone(),
            canonical_record.to_vec(),
            &self.signing_key,
        )
        .map_err(cluster_replica_error)?;
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or(ReplicaError::InvalidReceipt)?;
        let response = self.exchange(&request).map_err(cluster_replica_error)?;
        if response.decision != ReplicaDecision::Durable
            || response.commit_index != entry.commit_index
        {
            return Err(ReplicaError::InvalidReceipt);
        }
        Ok(DurableReceipt {
            replica_id: "continuous-replica".to_owned(),
            commit_index: response.commit_index,
            record_checksum: response.record_checksum,
        })
    }
}

fn cluster_replica_error(error: ClusterError) -> ReplicaError {
    ReplicaError::Io(io::Error::other(error.to_string()))
}

fn replica_request_id(counter: u64) -> [u8; 16] {
    let mut request = [0x72; 16];
    request[8..].copy_from_slice(&counter.to_be_bytes());
    request
}

fn ensure_config(config: &ContinuousPrimaryConfig) -> Result<(), ClusterError> {
    ensure_lab_bind(config.bind_policy, config.listen)?;
    ensure_lab_bind(config.bind_policy, config.replica_address)?;
    if config.max_connections == 0 || config.max_connections > 4_096 {
        return Err(err(
            "CONTINUOUS_PRIMARY_CONFIG_REFUSED",
            "connection bound must be between 1 and 4096",
        ));
    }
    if config.io_timeout.is_zero() || config.io_timeout > Duration::from_secs(10) {
        return Err(err(
            "CONTINUOUS_PRIMARY_CONFIG_REFUSED",
            "I/O timeout must be between 1 ms and 10 seconds",
        ));
    }
    if config.policy_hash.iter().all(|byte| *byte == 0) {
        return Err(err(
            "CONTINUOUS_PRIMARY_CONFIG_REFUSED",
            "policy hash is zero",
        ));
    }
    Ok(())
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), ClusterError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|error| err("CONTINUOUS_SOCKET_CONFIG_FAILED", error.to_string()))
}
