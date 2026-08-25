use std::io::{self, Cursor, Read, Write};

use quorumarc_runtime::{
    FrameCodec, FrameConfigError, FrameError, FrameReasonCode, HARD_MAX_FRAME_SIZE,
};

fn value_or_abort<T, E>(result: Result<T, E>) -> T {
    let Ok(value) = result else {
        std::process::abort();
    };
    value
}

struct OneByteReader<R>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.0.read(&mut buffer[..1])
    }
}

#[test]
fn frame_round_trip_survives_one_byte_stream_fragments() {
    let codec = value_or_abort(FrameCodec::new(64));
    let mut encoded = Vec::new();
    assert_eq!(codec.write_frame(&mut encoded, b"authority"), Ok(()));
    let mut reader = OneByteReader(Cursor::new(encoded));
    assert_eq!(
        codec.read_frame(&mut reader),
        Ok(Some(b"authority".to_vec()))
    );
    assert_eq!(codec.read_frame(&mut reader), Ok(None));
}

#[test]
fn clean_boundary_eof_is_not_a_malformed_frame() {
    let codec = value_or_abort(FrameCodec::new(8));
    assert_eq!(codec.read_frame(&mut Cursor::new(Vec::new())), Ok(None));
}

#[test]
fn partial_header_and_payload_are_distinct_fail_closed_errors() {
    let codec = value_or_abort(FrameCodec::new(16));
    let header_error = codec.read_frame(&mut Cursor::new(vec![0, 0]));
    assert!(matches!(&header_error, Err(FrameError::TruncatedHeader)));
    let header_error = header_error.err();
    assert_eq!(
        header_error.as_ref().map(FrameError::reason_code),
        Some(FrameReasonCode::TruncatedHeader)
    );

    let mut short_payload = 5_u32.to_be_bytes().to_vec();
    short_payload.extend_from_slice(b"abc");
    let payload_error = codec.read_frame(&mut Cursor::new(short_payload));
    assert!(matches!(
        payload_error,
        Err(FrameError::TruncatedPayload { declared: 5 })
    ));
}

#[test]
fn oversized_declared_length_is_rejected_before_payload_read() {
    let codec = value_or_abort(FrameCodec::new(32));
    let bytes = 33_u32.to_be_bytes();
    let result = codec.read_frame(&mut Cursor::new(bytes));
    assert!(matches!(
        result,
        Err(FrameError::FrameTooLarge {
            declared: 33,
            maximum: 32
        })
    ));
}

#[test]
fn empty_frames_are_rejected_on_read_and_write() {
    let codec = value_or_abort(FrameCodec::new(32));
    assert!(matches!(
        codec.read_frame(&mut Cursor::new(0_u32.to_be_bytes())),
        Err(FrameError::EmptyFrame)
    ));
    assert!(matches!(
        codec.write_frame(&mut Vec::new(), &[]),
        Err(FrameError::EmptyFrame)
    ));
}

#[test]
fn configuration_cannot_exceed_absolute_allocation_bound() {
    assert!(FrameCodec::new(0).is_err());
    assert!(FrameCodec::new(HARD_MAX_FRAME_SIZE + 1).is_err());
    assert!(FrameCodec::new(HARD_MAX_FRAME_SIZE).is_ok());
}

#[test]
fn configuration_errors_are_typed_and_describe_the_exact_bound() {
    assert_eq!(FrameCodec::new(0), Err(FrameConfigError::ZeroMaximum));
    let requested = HARD_MAX_FRAME_SIZE + 1;
    let error = FrameCodec::new(requested);
    assert_eq!(
        error,
        Err(FrameConfigError::MaximumTooLarge {
            requested,
            hard_maximum: HARD_MAX_FRAME_SIZE,
        })
    );
    let Err(error) = error else {
        std::process::abort();
    };
    assert!(error.to_string().contains(&requested.to_string()));
    assert!(error.to_string().contains(&HARD_MAX_FRAME_SIZE.to_string()));
}

#[test]
fn oversized_write_is_rejected_before_any_bytes_reach_the_stream() {
    let codec = value_or_abort(FrameCodec::new(4));
    let mut output = Vec::new();
    let error = codec.write_frame(&mut output, b"12345");
    assert!(matches!(
        error,
        Err(FrameError::FrameTooLarge {
            declared: 5,
            maximum: 4,
        })
    ));
    assert!(output.is_empty());
}

struct AlwaysErrorReader;

impl Read for AlwaysErrorReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deterministic read failure",
        ))
    }
}

struct OneByteThenError(bool);

impl Read for OneByteThenError {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.0 && !buffer.is_empty() {
            self.0 = true;
            buffer[0] = 0;
            return Ok(1);
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "deterministic header failure",
        ))
    }
}

struct AlwaysErrorWriter;

impl Write for AlwaysErrorWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "deterministic write failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn transport_failures_remain_distinct_from_malformed_peer_frames() {
    let codec = value_or_abort(FrameCodec::new(32));
    for error in [
        codec.read_frame(&mut AlwaysErrorReader),
        codec.read_frame(&mut OneByteThenError(false)),
    ] {
        let Err(error) = error else {
            std::process::abort();
        };
        assert_eq!(error.reason_code(), FrameReasonCode::TransportIo);
        assert!(matches!(error, FrameError::Io { .. }));
    }

    let write_error = codec.write_frame(&mut AlwaysErrorWriter, b"payload");
    let Err(write_error) = write_error else {
        std::process::abort();
    };
    assert_eq!(write_error.reason_code(), FrameReasonCode::TransportIo);
    assert!(write_error.to_string().contains("write frame header"));
}
