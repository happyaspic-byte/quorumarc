use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustix::fs::OFlags;

use crate::config::ProductionConfig;
use crate::operations::{NodeStatusReport, StatusHandle};
use crate::signal::ReloadToken;

const MAX_CONFIG_SIZE: usize = 65_536;

/// Typed error for configuration reload reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReloadReadError {
    InvalidFileType,
    TooLarge,
    Io,
    InvalidUtf8,
}

/// Bounded file read refusing oversized configurations or directory paths.
pub fn read_config_file(path: &Path) -> Result<String, ReloadReadError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_error| ReloadReadError::InvalidFileType)?;
    let metadata = file
        .metadata()
        .map_err(|_error| ReloadReadError::InvalidFileType)?;
    if !metadata.is_file() {
        return Err(ReloadReadError::InvalidFileType);
    }
    if metadata.len() > MAX_CONFIG_SIZE as u64 {
        return Err(ReloadReadError::TooLarge);
    }
    let mut bounded = (&mut file).take(MAX_CONFIG_SIZE as u64 + 1);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_error| ReloadReadError::Io)?;
    if bytes.len() > MAX_CONFIG_SIZE {
        return Err(ReloadReadError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_error| ReloadReadError::InvalidUtf8)
}

/// Runs the event-driven configuration reload worker until process shutdown.
pub fn run_reload_loop(
    path: &Path,
    initial: ProductionConfig,
    expected_role: &'static str,
    status: &StatusHandle,
    boot_id: &str,
    now_ms: impl Fn() -> u64,
    reload: &ReloadToken,
) {
    let mut active = initial;
    let mut generation = 0;
    while let Some(next_generation) = reload.wait_after(generation) {
        generation = next_generation;
        let Ok(text) = read_config_file(path) else {
            continue;
        };
        let Ok(candidate) = active.reload(&text) else {
            continue;
        };
        if candidate.role() != expected_role {
            continue;
        }
        let next_status = NodeStatusReport::new(&candidate, boot_id, now_ms(), None);
        if status.replace(next_status).is_ok() {
            active = candidate;
        }
    }
}
