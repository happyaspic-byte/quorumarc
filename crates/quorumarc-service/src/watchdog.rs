use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::signal::ShutdownToken;

/// systemd watchdog pings that never advertise readiness.
#[derive(Debug)]
pub struct SystemdWatchdog {
    socket: UnixDatagram,
    path: PathBuf,
    interval: Duration,
}

/// Watchdog socket or interval refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogError {
    SocketUnavailable,
    InvalidInterval,
}

impl SystemdWatchdog {
    /// Connects an unbound datagram client to an existing notify socket.
    pub fn from_socket_path(path: &Path, interval: Duration) -> Result<Self, WatchdogError> {
        if interval.is_zero() {
            return Err(WatchdogError::InvalidInterval);
        }
        let socket = UnixDatagram::unbound().map_err(|_error| WatchdogError::SocketUnavailable)?;
        Ok(Self {
            socket,
            path: path.to_path_buf(),
            interval,
        })
    }

    /// Builds a watchdog from systemd notify variables without claiming READY.
    pub fn from_environment_variables(
        notify_socket: Option<&str>,
        watchdog_usec: Option<&str>,
    ) -> Result<Option<Self>, WatchdogError> {
        let Some(socket) = notify_socket.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let Some(usec) = watchdog_usec.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let usec = usec
            .parse::<u64>()
            .map_err(|_error| WatchdogError::InvalidInterval)?;
        let interval_us = usec / 2;
        if interval_us == 0 {
            return Err(WatchdogError::InvalidInterval);
        }
        Self::from_socket_path(Path::new(socket), Duration::from_micros(interval_us)).map(Some)
    }

    /// Production daemons never send systemd READY=1.
    #[must_use]
    pub const fn emitted_ready(&self) -> bool {
        false
    }

    /// Ping interval derived from `WATCHDOG_USEC / 2`.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Sends `WATCHDOG=1` until shutdown without claiming service readiness.
    pub fn run_until(&self, shutdown: &ShutdownToken) {
        while !shutdown.is_requested() {
            let _ = self.socket.send_to(b"WATCHDOG=1", &self.path);
            shutdown.wait_timeout(self.interval);
        }
    }
}
