#![allow(clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quorumarc_service::management_journal::ManagementJournal;
use quorumarc_service::operations::LocalAdminServer;
use quorumarc_service::protocol::{
    AuthenticatedRequestJournal, ProductionFrame, ProductionFrameKind, ProductionRequest,
};

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

fn request(sequence: u64, payload: &[u8]) -> ProductionRequest {
    ProductionRequest {
        cluster_id: "prod-cluster".to_owned(),
        workload_id: "orders-api".to_owned(),
        node_id: "node-a".to_owned(),
        key_id: "node-a-2026-01".to_owned(),
        request_id: [11; 16],
        sequence,
        incarnation: 1,
        epoch: 4,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: payload.to_vec(),
    }
}

fn encoded(sequence: u64, payload: &[u8], key: &SigningKey) -> Vec<u8> {
    ProductionFrame::sign(
        ProductionFrameKind::Request,
        request(sequence, payload),
        key,
    )
    .expect("sign")
    .encode()
    .expect("encode")
}

fn send_and_receive(stream: &mut UnixStream, frame: &[u8]) -> String {
    let len = u32::try_from(frame.len()).expect("len");
    stream.write_all(&len.to_be_bytes()).expect("write len");
    stream.write_all(frame).expect("write frame");
    let mut response_len_buf = [0_u8; 4];
    stream.read_exact(&mut response_len_buf).expect("read len");
    let response_len = u32::from_be_bytes(response_len_buf) as usize;
    let mut response_bytes = vec![0_u8; response_len];
    stream
        .read_exact(&mut response_bytes)
        .expect("read response");
    String::from_utf8(response_bytes).expect("utf8")
}

#[test]
fn local_admin_socket_triggers_suspicion_sink_on_committed_mutation() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-admin-trigger-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = directory.join(format!("admin-trigger-{sequence}.sock"));
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let journal = ManagementJournal::open(&directory, [9; 16]).expect("journal");
    let admission = AuthenticatedRequestJournal::new(
        journal,
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    let current_uid = rustix::process::getuid().as_raw();
    let server = LocalAdminServer::bind_with_allowed_uid(&socket, admission, current_uid)
        .expect("bind admin")
        .with_suspicion_sink(move |failure, request| {
            let _ = sender.send((failure, request.sequence));
        });

    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));

    let first = encoded(1, b"node-failure-suspicion", &key);
    let mut client = UnixStream::connect(&socket).expect("connect");
    assert_eq!(send_and_receive(&mut client, &first), "COMMITTED\n");

    let received = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("received suspicion event");
    assert_eq!(
        received.0,
        quorumarc_service::candidate_loop::CandidateFailure::NodeFailureSuspicion
    );
    assert_eq!(received.1, 1);

    shutdown.request();
    handle.join().expect("join").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn local_admin_socket_records_authenticated_mutation_and_exact_retry() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-admin-socket-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = directory.join(format!("admin-{sequence}.sock"));
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let journal = ManagementJournal::open(&directory, [7; 16]).expect("journal");
    let admission = AuthenticatedRequestJournal::new(
        journal,
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    );

    let current_uid = rustix::process::getuid().as_raw();
    let server = LocalAdminServer::bind_with_allowed_uid(&socket, admission, current_uid)
        .expect("bind admin");
    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));

    let first = encoded(1, b"planned-switch", &key);
    let mut client = UnixStream::connect(&socket).expect("connect");
    assert_eq!(send_and_receive(&mut client, &first), "COMMITTED\n");

    let mut retry_client = UnixStream::connect(&socket).expect("connect retry");
    assert_eq!(
        send_and_receive(&mut retry_client, &first),
        "ALREADY_DURABLE\n"
    );

    shutdown.request();
    handle.join().expect("join").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn local_admin_socket_refuses_unauthenticated_and_malformed_frames() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-admin-refusal-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = directory.join(format!("admin-refusal-{sequence}.sock"));
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[9_u8; 32]);
    let journal = ManagementJournal::open(&directory, [8; 16]).expect("journal");
    let admission = AuthenticatedRequestJournal::new(
        journal,
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    );

    let current_uid = rustix::process::getuid().as_raw();
    let server = LocalAdminServer::bind_with_allowed_uid(&socket, admission, current_uid)
        .expect("bind admin");
    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));

    let mut bad_auth = UnixStream::connect(&socket).expect("connect");
    assert_eq!(
        send_and_receive(&mut bad_auth, &encoded(1, b"bad", &other)),
        "AUTHENTICATION_FAILED\n"
    );

    let mut malformed = UnixStream::connect(&socket).expect("connect malformed");
    assert_eq!(
        send_and_receive(&mut malformed, b"not-a-frame"),
        "MALFORMED\n"
    );

    shutdown.request();
    handle.join().expect("join").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn local_admin_socket_refuses_unauthorized_peer_uid() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-admin-uid-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = directory.join(format!("admin-uid-{sequence}.sock"));
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let journal = ManagementJournal::open(&directory, [9; 16]).expect("journal");
    let admission = AuthenticatedRequestJournal::new(
        journal,
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    );

    let current_uid = rustix::process::getuid().as_raw();
    let forbidden_uid = current_uid.wrapping_add(10_000);
    let server = LocalAdminServer::bind_with_allowed_uid(&socket, admission, forbidden_uid)
        .expect("bind admin");
    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));

    let mut client = UnixStream::connect(&socket).expect("connect");
    assert_eq!(
        send_and_receive(&mut client, &encoded(1, b"switch", &key)),
        "UNAUTHORIZED\n"
    );

    shutdown.request();
    handle.join().expect("join").expect("serve");
    let _ = fs::remove_dir_all(directory);
}
