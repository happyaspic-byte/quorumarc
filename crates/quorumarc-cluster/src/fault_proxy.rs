use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use quorumarc_runtime::FrameCodec;

use crate::path_guard::{prepare_file_parent, require_ready_disjoint, write_ready_file};
use crate::{ClusterError, err};

const MAX_PROXY_FRAME: usize = 16_384;
const MAX_MODE_FILE_BYTES: u64 = 64;
const MAX_DELAY_MS: u64 = 1_000;

/// Bounded loopback fault-proxy settings for the GitHub lifecycle laboratory.
#[derive(Clone, Debug)]
pub struct FaultProxyConfig {
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub upstream: SocketAddr,
    pub mode_file: PathBuf,
    pub max_connections: u64,
    pub io_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyMode {
    Pass,
    Drop,
    Delay(u64),
    Duplicate,
    ReplyDrop,
    Corrupt,
    CorruptReply,
    ReplayLast,
    ReorderPair,
}

/// Runs a bounded, loopback-only, frame-aware fault proxy.
///
/// Promotion requests and Witness responses remain end-to-end signed. The
/// proxy can delay, duplicate, drop, corrupt, replay, or reorder opaque frames
/// but cannot create valid authority evidence.
pub fn serve_fault_proxy(config: FaultProxyConfig) -> Result<(), ClusterError> {
    ensure_loopback(config.listen)?;
    ensure_loopback(config.upstream)?;
    ensure_bounds(config.max_connections, config.io_timeout)?;
    require_ready_disjoint(
        &config.ready_file,
        &[config.mode_file.as_path()],
        None,
        None,
    )?;
    prepare_file_parent(&config.ready_file)?;
    validate_mode_file(&config.mode_file)?;

    let listener = TcpListener::bind(config.listen).map_err(|error| {
        err(
            "FAULT_PROXY_BIND_FAILED",
            format!("{}: {error}", config.listen),
        )
    })?;
    let local = listener
        .local_addr()
        .map_err(|error| err("FAULT_PROXY_BIND_FAILED", error.to_string()))?;
    ensure_loopback(local)?;
    let codec = FrameCodec::new(MAX_PROXY_FRAME)
        .map_err(|error| err("FAULT_PROXY_FRAME_CONFIG_FAILED", error.to_string()))?;
    write_ready_file(&config.ready_file, &local.to_string())?;
    eprintln!(
        "event=fault_proxy_ready listen={local} upstream={} mode_file={}",
        config.upstream,
        config.mode_file.display()
    );

    let mut last_forwarded_request: Option<Vec<u8>> = None;
    let mut remaining = config.max_connections;
    while remaining > 0 {
        let (mut downstream, remote) = listener
            .accept()
            .map_err(|error| err("FAULT_PROXY_ACCEPT_FAILED", error.to_string()))?;
        remaining -= 1;
        if !remote.ip().is_loopback() {
            continue;
        }
        configure_stream(&downstream, config.io_timeout)?;
        match handle_connection(
            &listener,
            &mut downstream,
            codec,
            &config,
            &mut last_forwarded_request,
            &mut remaining,
        ) {
            Ok(()) => {}
            Err(error) => eprintln!("event=fault_proxy_refusal {error}"),
        }
    }
    Ok(())
}

fn handle_connection(
    listener: &TcpListener,
    downstream: &mut TcpStream,
    codec: FrameCodec,
    config: &FaultProxyConfig,
    last_forwarded_request: &mut Option<Vec<u8>>,
    remaining: &mut u64,
) -> Result<(), ClusterError> {
    let request = read_downstream_request(downstream, codec)?;
    let mode = read_mode(&config.mode_file)?;
    eprintln!("event=fault_proxy_mode mode={mode:?}");
    if mode == ProxyMode::ReorderPair {
        return reorder_pair(
            listener,
            downstream,
            request,
            codec,
            config,
            last_forwarded_request,
            remaining,
        );
    }
    match mode {
        ProxyMode::Drop => Ok(()),
        ProxyMode::Delay(delay_ms) => {
            thread::sleep(Duration::from_millis(delay_ms));
            let response = upstream_exchange(config, codec, &request)?;
            *last_forwarded_request = Some(request);
            write_downstream(downstream, codec, &response)
        }
        ProxyMode::Duplicate => {
            let _first_response = upstream_exchange(config, codec, &request)?;
            let retry_response = upstream_exchange(config, codec, &request)?;
            *last_forwarded_request = Some(request);
            write_downstream(downstream, codec, &retry_response)
        }
        ProxyMode::ReplyDrop => {
            let _response = upstream_exchange(config, codec, &request)?;
            *last_forwarded_request = Some(request);
            Ok(())
        }
        ProxyMode::Corrupt => {
            let mut corrupt = request;
            let last = corrupt.last_mut().ok_or_else(|| {
                err(
                    "FAULT_PROXY_REQUEST_MALFORMED",
                    "cannot corrupt an empty request",
                )
            })?;
            *last ^= 0x80;
            let _response = upstream_exchange(config, codec, &corrupt)?;
            Ok(())
        }
        ProxyMode::CorruptReply => {
            let mut response = upstream_exchange(config, codec, &request)?;
            let last = response.last_mut().ok_or_else(|| {
                err(
                    "FAULT_PROXY_RESPONSE_MALFORMED",
                    "cannot corrupt an empty response",
                )
            })?;
            *last ^= 0x80;
            *last_forwarded_request = Some(request);
            write_downstream(downstream, codec, &response)
        }
        ProxyMode::ReplayLast => {
            let replay = last_forwarded_request.as_ref().ok_or_else(|| {
                err(
                    "FAULT_PROXY_REPLAY_REFUSED",
                    "no previously forwarded request is available",
                )
            })?;
            let response = upstream_exchange(config, codec, replay)?;
            write_downstream(downstream, codec, &response)
        }
        ProxyMode::Pass => {
            let response = upstream_exchange(config, codec, &request)?;
            *last_forwarded_request = Some(request);
            write_downstream(downstream, codec, &response)
        }
        ProxyMode::ReorderPair => Err(err(
            "FAULT_PROXY_MODE_REFUSED",
            "reorder-pair requires a paired accept",
        )),
    }
}

fn reorder_pair(
    listener: &TcpListener,
    first_downstream: &mut TcpStream,
    first_request: Vec<u8>,
    codec: FrameCodec,
    config: &FaultProxyConfig,
    last_forwarded_request: &mut Option<Vec<u8>>,
    remaining: &mut u64,
) -> Result<(), ClusterError> {
    if *remaining == 0 {
        return Err(err(
            "FAULT_PROXY_REORDER_REFUSED",
            "reorder-pair requires a second connection",
        ));
    }
    eprintln!("event=fault_proxy_reorder_buffered");
    let (mut second_downstream, second_remote) =
        accept_loopback_partner(listener, config.io_timeout)?;
    *remaining -= 1;
    if !second_remote.ip().is_loopback() {
        return Err(err(
            "FAULT_PROXY_REORDER_REFUSED",
            "reorder partner was not loopback",
        ));
    }
    configure_stream(&second_downstream, config.io_timeout)?;
    let second_request = read_downstream_request(&mut second_downstream, codec)?;
    let second_response = upstream_exchange(config, codec, &second_request)?;
    *last_forwarded_request = Some(second_request);
    write_downstream(&mut second_downstream, codec, &second_response)?;
    let first_response = upstream_exchange(config, codec, &first_request)?;
    *last_forwarded_request = Some(first_request);
    write_downstream(first_downstream, codec, &first_response)?;
    eprintln!("event=fault_proxy_reorder_complete order=second,first");
    Ok(())
}

fn accept_loopback_partner(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), ClusterError> {
    listener
        .set_nonblocking(true)
        .map_err(|error| err("FAULT_PROXY_ACCEPT_FAILED", error.to_string()))?;
    let deadline = Instant::now() + timeout;
    let accepted = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    let _blocking = listener.set_nonblocking(false);
                    return Err(err(
                        "FAULT_PROXY_REORDER_REFUSED",
                        "reorder partner did not arrive before the I/O timeout",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                let _blocking = listener.set_nonblocking(false);
                return Err(err("FAULT_PROXY_ACCEPT_FAILED", error.to_string()));
            }
        }
    };
    listener
        .set_nonblocking(false)
        .map_err(|error| err("FAULT_PROXY_ACCEPT_FAILED", error.to_string()))?;
    Ok(accepted)
}

fn read_downstream_request(
    downstream: &mut TcpStream,
    codec: FrameCodec,
) -> Result<Vec<u8>, ClusterError> {
    codec
        .read_frame(downstream)
        .map_err(|error| err("FAULT_PROXY_DOWNSTREAM_READ_FAILED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "FAULT_PROXY_DOWNSTREAM_REQUEST_MISSING",
                "downstream closed without a frame",
            )
        })
}

fn upstream_exchange(
    config: &FaultProxyConfig,
    codec: FrameCodec,
    request: &[u8],
) -> Result<Vec<u8>, ClusterError> {
    let mut upstream =
        TcpStream::connect_timeout(&config.upstream, config.io_timeout).map_err(|error| {
            err(
                "FAULT_PROXY_UPSTREAM_UNAVAILABLE",
                format!("{}: {error}", config.upstream),
            )
        })?;
    configure_stream(&upstream, config.io_timeout)?;
    codec
        .write_frame(&mut upstream, request)
        .map_err(|error| err("FAULT_PROXY_UPSTREAM_WRITE_FAILED", error.to_string()))?;
    codec
        .read_frame(&mut upstream)
        .map_err(|error| err("FAULT_PROXY_UPSTREAM_READ_FAILED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "FAULT_PROXY_UPSTREAM_RESPONSE_MISSING",
                "upstream closed without a response",
            )
        })
}

fn write_downstream(
    downstream: &mut TcpStream,
    codec: FrameCodec,
    response: &[u8],
) -> Result<(), ClusterError> {
    codec
        .write_frame(downstream, response)
        .map_err(|error| err("FAULT_PROXY_DOWNSTREAM_WRITE_FAILED", error.to_string()))
}

fn validate_mode_file(path: &Path) -> Result<(), ClusterError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        err(
            "FAULT_PROXY_MODE_REFUSED",
            format!("{}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MODE_FILE_BYTES
    {
        return Err(err(
            "FAULT_PROXY_MODE_REFUSED",
            format!("{} must be a small regular file", path.display()),
        ));
    }
    let _mode = read_mode(path)?;
    Ok(())
}

fn read_mode(path: &Path) -> Result<ProxyMode, ClusterError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        err(
            "FAULT_PROXY_MODE_REFUSED",
            format!("{}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MODE_FILE_BYTES
    {
        return Err(err(
            "FAULT_PROXY_MODE_REFUSED",
            format!("{} must be a small regular file", path.display()),
        ));
    }
    let value = fs::read_to_string(path).map_err(|error| {
        err(
            "FAULT_PROXY_MODE_REFUSED",
            format!("{}: {error}", path.display()),
        )
    })?;
    parse_mode(value.trim())
}

fn parse_mode(value: &str) -> Result<ProxyMode, ClusterError> {
    match value {
        "pass" => Ok(ProxyMode::Pass),
        "drop" => Ok(ProxyMode::Drop),
        "duplicate" => Ok(ProxyMode::Duplicate),
        "reply-drop" => Ok(ProxyMode::ReplyDrop),
        "corrupt" => Ok(ProxyMode::Corrupt),
        "corrupt-reply" => Ok(ProxyMode::CorruptReply),
        "replay-last" => Ok(ProxyMode::ReplayLast),
        "reorder-pair" => Ok(ProxyMode::ReorderPair),
        _ => {
            let delay = value
                .strip_prefix("delay-ms=")
                .ok_or_else(|| err("FAULT_PROXY_MODE_REFUSED", "unknown fault proxy mode"))?;
            let delay_ms = delay.parse::<u64>().map_err(|_| {
                err(
                    "FAULT_PROXY_MODE_REFUSED",
                    "delay must be an unsigned integer",
                )
            })?;
            if delay_ms > MAX_DELAY_MS {
                return Err(err(
                    "FAULT_PROXY_MODE_REFUSED",
                    "delay exceeds the bounded one-second maximum",
                ));
            }
            Ok(ProxyMode::Delay(delay_ms))
        }
    }
}

fn ensure_loopback(address: SocketAddr) -> Result<(), ClusterError> {
    if !address.ip().is_loopback() {
        return Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost fault lab"),
        ));
    }
    Ok(())
}

fn ensure_bounds(max_connections: u64, timeout: Duration) -> Result<(), ClusterError> {
    if !(1..=4_096).contains(&max_connections) {
        return Err(err(
            "FAULT_PROXY_CONNECTION_BOUND_REFUSED",
            "max connections must be between 1 and 4096",
        ));
    }
    if timeout.is_zero() || timeout > Duration::from_secs(10) {
        return Err(err(
            "FAULT_PROXY_TIMEOUT_REFUSED",
            "I/O timeout must be between 1 ms and 10 seconds",
        ));
    }
    Ok(())
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), ClusterError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| err("FAULT_PROXY_STREAM_CONFIG_FAILED", error.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn modes_are_strict_and_delay_is_bounded() {
        assert_eq!(parse_mode("pass").expect("pass"), ProxyMode::Pass);
        assert_eq!(
            parse_mode("delay-ms=25").expect("delay"),
            ProxyMode::Delay(25)
        );
        assert_eq!(
            parse_mode("replay-last").expect("replay"),
            ProxyMode::ReplayLast
        );
        assert_eq!(
            parse_mode("corrupt-reply").expect("corrupt reply"),
            ProxyMode::CorruptReply
        );
        assert_eq!(
            parse_mode("reorder-pair").expect("reorder pair"),
            ProxyMode::ReorderPair
        );
        assert!(parse_mode("delay-ms=1001").is_err());
        assert!(parse_mode("PASS").is_err());
        assert!(parse_mode("").is_err());
    }

    #[test]
    fn service_bounds_are_fail_closed() {
        assert!(ensure_bounds(0, Duration::from_millis(1)).is_err());
        assert!(ensure_bounds(1, Duration::ZERO).is_err());
        assert!(ensure_bounds(1, Duration::from_secs(11)).is_err());
        ensure_bounds(1, Duration::from_millis(1)).expect("valid bounds");
    }
}
