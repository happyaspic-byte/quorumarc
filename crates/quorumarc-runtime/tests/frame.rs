use std::io::{self, Cursor, Read};

use quorumarc_runtime::{
    FrameCodec, FrameError, FrameReasonCode, HARD_MAX_FRAME_SIZE,
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
