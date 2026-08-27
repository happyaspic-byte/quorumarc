#![allow(clippy::expect_used)]

use std::fs;
use std::time::Duration;

use quorumarc_service::clock::{BootClock, BootClockError};

#[test]
fn boot_clock_is_monotonic_and_bound_to_boot_identity() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-service-clock-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("create clock fixture");
    let boot_id = directory.join("boot-id");
    let uptime = directory.join("uptime");
    fs::write(&boot_id, "11111111-2222-3333-4444-555555555555\n").expect("write boot id");
    fs::write(&uptime, "123.45 67.89\n").expect("write uptime");

    let clock = BootClock::open(&boot_id, &uptime).expect("open boot clock");
    assert_eq!(clock.boot_id(), "11111111-2222-3333-4444-555555555555");
    assert_eq!(clock.now_ms(), 123_450);

    fs::write(&uptime, "123.44 67.90\n").expect("roll back uptime fixture");
    assert_eq!(clock.now_ms(), 123_450);

    fs::write(&uptime, "123.48 67.91\n").expect("advance uptime fixture");
    assert_eq!(clock.now_ms(), 123_480);

    std::thread::sleep(Duration::from_millis(1));
    fs::write(&boot_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n").expect("change boot id");
    assert_eq!(clock.verify_boot(), Err(BootClockError::BootChanged));

    fs::remove_dir_all(directory).expect("remove clock fixture");
}

#[test]
fn system_boot_clock_reads_linux_boottime_without_unsafe_code() {
    let clock = BootClock::open_system().expect("open system boot clock");
    let first = clock.now_ms();
    std::thread::sleep(Duration::from_millis(2));
    let second = clock.now_ms();
    assert!(second >= first);
    assert_eq!(clock.verify_boot(), Ok(()));
}

#[test]
fn boot_clock_rejects_malformed_kernel_sources() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-service-clock-invalid-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create clock fixture");
    let boot_id = directory.join("boot-id");
    let uptime = directory.join("uptime");
    fs::write(&boot_id, "not-a-boot-id\n").expect("write invalid boot id");
    fs::write(&uptime, "1.00 2.00\n").expect("write uptime");
    assert!(matches!(
        BootClock::open(&boot_id, &uptime),
        Err(BootClockError::InvalidBootId)
    ));
    fs::remove_dir_all(directory).expect("remove clock fixture");
}
