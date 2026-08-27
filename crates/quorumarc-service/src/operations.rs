use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::signal::ShutdownToken;

use sha2::{Digest, Sha256};

use crate::config::ProductionConfig;

const BUNDLE_DOMAIN: &[u8] = b"quorumarc/support-bundle/v1\0";

/// Read-only node status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeStatusReport {
    cluster_id: String,
    node_id: String,
    effect_gate: &'static str,
    authority_enabled: bool,
    boot_id: String,
    uptime_ms: u64,
    last_committed_index: Option<u64>,
    log_level: String,
}

impl NodeStatusReport {
    /// Builds a status report from verified configuration and clock state.
    #[must_use]
    pub fn new(
        config: &ProductionConfig,
        boot_id: impl Into<String>,
        uptime_ms: u64,
        last_committed_index: Option<u64>,
    ) -> Self {
        Self {
            cluster_id: config.cluster_id().to_owned(),
            node_id: config.node_id().to_owned(),
            effect_gate: config.effect_gate_state(),
            authority_enabled: false,
            boot_id: boot_id.into(),
            uptime_ms,
            last_committed_index,
            log_level: config.log_level().to_owned(),
        }
    }

    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub const fn effect_gate(&self) -> &'static str {
        self.effect_gate
    }

    #[must_use]
    pub const fn authority_enabled(&self) -> bool {
        self.authority_enabled
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    #[must_use]
    pub const fn uptime_ms(&self) -> u64 {
        self.uptime_ms
    }

    #[must_use]
    pub const fn last_committed_index(&self) -> Option<u64> {
        self.last_committed_index
    }

    #[must_use]
    pub fn log_level(&self) -> &str {
        &self.log_level
    }
}

/// Shared read-only status snapshot updated only after validated reloads.
#[derive(Clone, Debug)]
pub struct StatusHandle {
    status: Arc<RwLock<NodeStatusReport>>,
}

impl StatusHandle {
    #[must_use]
    pub fn new(status: NodeStatusReport) -> Self {
        Self {
            status: Arc::new(RwLock::new(status)),
        }
    }

    pub fn replace(&self, status: NodeStatusReport) -> Result<(), OperationsError> {
        let mut current = self
            .status
            .write()
            .map_err(|_error| OperationsError::StatusUnavailable)?;
        *current = status;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<NodeStatusReport, OperationsError> {
        self.status
            .read()
            .map(|guard| guard.clone())
            .map_err(|_error| OperationsError::StatusUnavailable)
    }
}

/// Redacted support bundle manifest for offline operational diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportBundle {
    cluster_id: String,
    members_count: usize,
    fence_mechanism: String,
    fence_profile: String,
    fence_read_back: bool,
    manifest_json: String,
    bundle_digest: [u8; 32],
}

impl SupportBundle {
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    #[must_use]
    pub const fn members_count(&self) -> usize {
        self.members_count
    }

    #[must_use]
    pub fn fence_mechanism(&self) -> &str {
        &self.fence_mechanism
    }

    #[must_use]
    pub fn fence_profile(&self) -> &str {
        &self.fence_profile
    }

    #[must_use]
    pub const fn fence_read_back(&self) -> bool {
        self.fence_read_back
    }

    #[must_use]
    pub fn manifest_json(&self) -> &str {
        &self.manifest_json
    }

    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
}

/// Errors occurring during local status serving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationsError {
    SocketBindFailed,
    SocketServeFailed,
    StatusUnavailable,
}

/// Local Unix-socket status server. It never accepts mutation commands.
#[derive(Debug)]
pub struct LocalStatusServer {
    listener: UnixListener,
    path: PathBuf,
    inode: (u64, u64),
    status: StatusHandle,
}

impl LocalStatusServer {
    /// Binds a read-only status socket at `path`.
    pub fn bind(path: &Path, status: NodeStatusReport) -> Result<Self, OperationsError> {
        Self::bind_shared(path, StatusHandle::new(status))
    }

    pub fn bind_shared(path: &Path, status: StatusHandle) -> Result<Self, OperationsError> {
        let listener =
            UnixListener::bind(path).map_err(|_error| OperationsError::SocketBindFailed)?;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_error| OperationsError::SocketBindFailed)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            inode: (metadata.dev(), metadata.ino()),
            status,
        })
    }

    /// Serves exactly one client: writes the snapshot and closes.
    pub fn serve_one(self) -> Result<(), OperationsError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .map_err(|_error| OperationsError::SocketServeFailed)?;
        write_shared_status(stream, &self.status)
    }

    /// Serves clients until shutdown, then returns.
    pub fn serve_until(self, shutdown: &ShutdownToken) -> Result<(), OperationsError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_error| OperationsError::SocketServeFailed)?;
        while !shutdown.is_requested() {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = write_shared_status(stream, &self.status);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    shutdown.wait_timeout(Duration::from_millis(100));
                }
                Err(_error) => return Err(OperationsError::SocketServeFailed),
            }
        }
        Ok(())
    }
}

impl Drop for LocalStatusServer {
    fn drop(&mut self) {
        unlink_if_still_ours(&self.path, self.inode);
    }
}

fn write_shared_status(
    stream: std::os::unix::net::UnixStream,
    status: &StatusHandle,
) -> Result<(), OperationsError> {
    let snapshot = status
        .status
        .read()
        .map_err(|_error| OperationsError::StatusUnavailable)?
        .clone();
    write_status(stream, &snapshot)
}

fn write_status(
    mut stream: std::os::unix::net::UnixStream,
    status: &NodeStatusReport,
) -> Result<(), OperationsError> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
    let mut discarded = [0_u8; 4_096];
    match stream.read(&mut discarded) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Err(_error) => return Err(OperationsError::SocketServeFailed),
    }
    let payload = format!(
        "{{\"cluster_id\":\"{}\",\"node_id\":\"{}\",\"effect_gate\":\"{}\",\"authority_enabled\":{},\"boot_id\":\"{}\",\"uptime_ms\":{},\"last_committed_index\":{},\"log_level\":\"{}\"}}",
        json_escape(status.cluster_id()),
        json_escape(status.node_id()),
        status.effect_gate(),
        status.authority_enabled(),
        json_escape(status.boot_id()),
        status.uptime_ms(),
        optional_u64(status.last_committed_index()),
        json_escape(status.log_level())
    );
    stream
        .write_all(payload.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_error| OperationsError::SocketServeFailed)
}

fn unlink_if_still_ours(path: &Path, inode: (u64, u64)) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if (metadata.dev(), metadata.ino()) == inode {
        let _ = std::fs::remove_file(path);
    }
}

/// Exports a redacted support bundle from the active node configuration.
#[must_use]
pub fn export_support_bundle(
    config: &ProductionConfig,
    boot_id: impl Into<String>,
    uptime_ms: u64,
    last_committed_index: Option<u64>,
) -> SupportBundle {
    let status = NodeStatusReport::new(config, boot_id, uptime_ms, last_committed_index);
    let members_count = config.members().len();
    let fence_mechanism = config.fence_mechanism().to_owned();
    let fence_profile = config.fence_profile().to_owned();
    let fence_read_back = config.fence_read_back();

    let manifest = format!(
        "{{\"cluster_id\":\"{}\",\"members_count\":{},\"effect_gate\":\"{}\",\"authority_enabled\":{},\"signing_key_path\":\"<REDACTED_PRIVATE_KEY_PATH>\",\"fence_mechanism\":\"{}\",\"fence_profile\":\"{}\",\"fence_read_back\":{},\"boot_id\":\"{}\",\"uptime_ms\":{},\"last_committed_index\":{}}}",
        json_escape(status.cluster_id()),
        members_count,
        status.effect_gate(),
        status.authority_enabled(),
        json_escape(&fence_mechanism),
        json_escape(&fence_profile),
        fence_read_back,
        json_escape(status.boot_id()),
        status.uptime_ms(),
        optional_u64(status.last_committed_index())
    );

    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_DOMAIN);
    hasher.update(manifest.as_bytes());
    let bundle_digest = hasher.finalize().into();

    SupportBundle {
        cluster_id: status.cluster_id().to_owned(),
        members_count,
        fence_mechanism,
        fence_profile,
        fence_read_back,
        manifest_json: manifest,
        bundle_digest,
    }
}

fn optional_u64(value: Option<u64>) -> String {
    match value {
        Some(index) => index.to_string(),
        None => "null".to_owned(),
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => escaped.push('?'),
            printable => escaped.push(printable),
        }
    }
    escaped
}
