use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use quorumarc_rpo0::{FileReplica, ReplicaSink, recover_wal};
use quorumarc_runtime::FrameCodec;

use super::protocol::{MAX_CONTINUOUS_FRAME, ReplicaKind, ReplicaRequest, ReplicaResponse};
use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::lab_net::{LabBindPolicy, ensure_lab_bind, ensure_lab_peer};
use crate::path_guard::{
    OwnerLock, prepare_file_parent, require_keys_disjoint, require_ready_disjoint, write_ready_file,
};
use crate::{ClusterError, err};

#[derive(Clone, Debug)]
pub struct ContinuousReplicaConfig {
    pub bind_policy: LabBindPolicy,
    pub expected_primary_ips: Vec<std::net::IpAddr>,
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub wal_path: PathBuf,
    pub signing_key_file: PathBuf,
    pub primary_public_key_file: PathBuf,
    pub max_connections: u64,
    pub io_timeout: Duration,
    pub policy_hash: [u8; 32],
}

pub fn serve_continuous_replica(config: ContinuousReplicaConfig) -> Result<(), ClusterError> {
    ensure_config(&config)?;
    let signing_key = load_private_seed(&config.signing_key_file)?;
    let primary_key = load_public_key(&config.primary_public_key_file)?;
    require_distinct_role_keys(&[
        ("continuous-replica", &signing_key.verifying_key()),
        ("continuous-primary", &primary_key),
    ])?;
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.primary_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.primary_public_key_file.as_path(),
        ],
        None,
        Some(&config.wal_path),
    )?;
    prepare_file_parent(&config.wal_path)?;
    let _wal_lock = OwnerLock::for_file(&config.wal_path, "continuous-replica")?;
    let listener = TcpListener::bind(config.listen).map_err(|error| {
        err(
            "CONTINUOUS_REPLICA_BIND_FAILED",
            format!("{}: {error}", config.listen),
        )
    })?;
    let local = listener
        .local_addr()
        .map_err(|error| err("CONTINUOUS_REPLICA_BIND_FAILED", error.to_string()))?;
    ensure_lab_bind(config.bind_policy, local)?;
    let codec = FrameCodec::new(MAX_CONTINUOUS_FRAME)
        .map_err(|error| err("CONTINUOUS_FRAME_CONFIG_FAILED", error.to_string()))?;
    let mut replica = FileReplica::new("continuous-replica", &config.wal_path);
    replica
        .recover_and_sync()
        .map_err(|error| err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string()))?;
    write_ready_file(&config.ready_file, &local.to_string())?;

    for _ in 0..config.max_connections {
        let (mut stream, remote) = listener
            .accept()
            .map_err(|error| err("CONTINUOUS_REPLICA_ACCEPT_FAILED", error.to_string()))?;
        if let Err(error) =
            ensure_lab_peer(config.bind_policy, remote, &config.expected_primary_ips)
        {
            eprintln!("event=continuous_replica_peer_refusal {error}");
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        if let Err(error) = handle_session(
            &mut stream,
            codec,
            &config,
            &primary_key,
            &signing_key,
            &mut replica,
        ) {
            eprintln!("event=continuous_replica_refusal {error}");
        }
    }
    Ok(())
}

fn handle_session(
    stream: &mut TcpStream,
    codec: FrameCodec,
    config: &ContinuousReplicaConfig,
    primary_key: &quorumarc_wire::VerifyingKey,
    signing_key: &quorumarc_wire::SigningKey,
    replica: &mut FileReplica,
) -> Result<(), ClusterError> {
    loop {
        let payload = match codec
            .read_frame(stream)
            .map_err(|error| err("CONTINUOUS_REPLICA_FRAME_REFUSED", error.to_string()))?
        {
            Some(payload) => payload,
            None => return Ok(()),
        };
        let request = ReplicaRequest::from_bytes(&payload)?;
        request.verify(primary_key)?;
        if request.policy_hash != config.policy_hash {
            return Err(err(
                "CONTINUOUS_REPLICA_SCOPE_REFUSED",
                "request policy differs from replica policy",
            ));
        }
        let response = match request.kind {
            ReplicaKind::Query => {
                let (_, wal_bytes) = replica
                    .recover_and_sync()
                    .map_err(|error| err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string()))?;
                ReplicaResponse::progress(&request, wal_bytes, signing_key)?
            }
            ReplicaKind::Append => {
                let entry = request.entry.as_ref().ok_or_else(|| {
                    err(
                        "CONTINUOUS_REPLICA_REQUEST_MALFORMED",
                        "append entry is missing",
                    )
                })?;
                let receipt = replica
                    .append_and_flush(entry, &request.canonical_record)
                    .map_err(|error| {
                        err("CONTINUOUS_REPLICA_DURABILITY_REFUSED", error.to_string())
                    })?;
                let recovered =
                    recover_wal(&replica.read_all().map_err(|error| {
                        err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string())
                    })?)
                    .map_err(|error| err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string()))?;
                ReplicaResponse::durable(
                    &request,
                    receipt.commit_index,
                    recovered.value,
                    recovered.state_root,
                    receipt.record_checksum,
                    signing_key,
                )?
            }
        };
        codec
            .write_frame(stream, &response.to_bytes()?)
            .map_err(|error| err("CONTINUOUS_REPLICA_FRAME_WRITE_FAILED", error.to_string()))?;
    }
}

fn ensure_config(config: &ContinuousReplicaConfig) -> Result<(), ClusterError> {
    ensure_lab_bind(config.bind_policy, config.listen)?;
    if config.max_connections == 0 || config.max_connections > 4_096 {
        return Err(err(
            "CONTINUOUS_REPLICA_CONFIG_REFUSED",
            "connection bound must be between 1 and 4096",
        ));
    }
    if config.io_timeout.is_zero() || config.io_timeout > Duration::from_secs(10) {
        return Err(err(
            "CONTINUOUS_REPLICA_CONFIG_REFUSED",
            "I/O timeout must be between 1 ms and 10 seconds",
        ));
    }
    if config.policy_hash.iter().all(|byte| *byte == 0) {
        return Err(err(
            "CONTINUOUS_REPLICA_CONFIG_REFUSED",
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
