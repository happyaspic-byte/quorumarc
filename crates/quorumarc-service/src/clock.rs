use std::fs;
use std::path::{Path, PathBuf};

use quorumarc_core::TrustedClock;
use rustix::time::{ClockId, clock_gettime};

const BOOT_ID_LEN: usize = 36;

/// Fail-closed boot-bound monotonic clock.
#[derive(Debug)]
pub struct BootClock {
    boot_id_path: PathBuf,
    uptime_path: Option<PathBuf>,
    boot_id: String,
    last_ms: std::sync::atomic::AtomicU64,
}

/// Typed refusal for a production clock source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootClockError {
    InvalidBootId,
    InvalidUptime,
    BootChanged,
    SourceUnavailable,
}

impl BootClock {
    /// Opens a production kernel boot-identity clock using the host system.
    pub fn open_system() -> Result<Self, BootClockError> {
        let boot_id_path = Path::new("/proc/sys/kernel/random/boot_id");
        let boot_id = read_boot_id(boot_id_path)?;
        Ok(Self {
            boot_id_path: boot_id_path.to_path_buf(),
            uptime_path: None,
            boot_id,
            last_ms: std::sync::atomic::AtomicU64::new(timespec_ms(clock_gettime(
                ClockId::Boottime,
            ))),
        })
    }

    /// Opens a kernel boot-identity clock from explicit sources (for tests and isolation).
    pub fn open(boot_id_path: &Path, uptime_path: &Path) -> Result<Self, BootClockError> {
        let boot_id = read_boot_id(boot_id_path)?;
        let now_ms = read_uptime_ms(uptime_path)?;
        Ok(Self {
            boot_id_path: boot_id_path.to_path_buf(),
            uptime_path: Some(uptime_path.to_path_buf()),
            boot_id,
            last_ms: std::sync::atomic::AtomicU64::new(now_ms),
        })
    }

    /// Returns the bound kernel boot identity.
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Monotonic milliseconds from the bound boot identity.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        TrustedClock::now_ms(self)
    }

    /// Refuses if the kernel boot identity no longer matches the bound value.
    pub fn verify_boot(&self) -> Result<(), BootClockError> {
        let current = read_boot_id(&self.boot_id_path)?;
        if current == self.boot_id {
            Ok(())
        } else {
            Err(BootClockError::BootChanged)
        }
    }

    fn sample_raw_ms(&self) -> u64 {
        if let Some(path) = &self.uptime_path {
            read_uptime_ms(path).unwrap_or(0)
        } else {
            timespec_ms(clock_gettime(ClockId::Boottime))
        }
    }
}

impl TrustedClock for BootClock {
    fn now_ms(&self) -> u64 {
        let observed = self.sample_raw_ms();
        let mut current = self.last_ms.load(std::sync::atomic::Ordering::SeqCst);
        loop {
            let next = current.max(observed);
            match self.last_ms.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }
}

fn timespec_ms(ts: rustix::time::Timespec) -> u64 {
    let sec = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsec = u64::try_from(ts.tv_nsec).unwrap_or(0);
    sec.saturating_mul(1_000).saturating_add(nsec / 1_000_000)
}

fn read_boot_id(path: &Path) -> Result<String, BootClockError> {
    let value = fs::read_to_string(path)
        .map_err(|_error| BootClockError::SourceUnavailable)?
        .trim()
        .to_owned();
    if value.len() != BOOT_ID_LEN
        || value.as_bytes()[8] != b'-'
        || value.as_bytes()[13] != b'-'
        || value.as_bytes()[18] != b'-'
        || value.as_bytes()[23] != b'-'
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(BootClockError::InvalidBootId);
    }
    Ok(value)
}

fn read_uptime_ms(path: &Path) -> Result<u64, BootClockError> {
    let value = fs::read_to_string(path).map_err(|_error| BootClockError::SourceUnavailable)?;
    let first = value
        .split_whitespace()
        .next()
        .ok_or(BootClockError::InvalidUptime)?;
    let (seconds, fraction) = first.split_once('.').ok_or(BootClockError::InvalidUptime)?;
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_error| BootClockError::InvalidUptime)?;
    let millis = match fraction.len() {
        0 => 0,
        1 => fraction
            .parse::<u64>()
            .map_err(|_error| BootClockError::InvalidUptime)?
            .saturating_mul(100),
        2 => fraction
            .parse::<u64>()
            .map_err(|_error| BootClockError::InvalidUptime)?
            .saturating_mul(10),
        _ => fraction[..3]
            .parse::<u64>()
            .map_err(|_error| BootClockError::InvalidUptime)?,
    };
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(millis))
        .ok_or(BootClockError::InvalidUptime)
}
