use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};

/// Absolute defensive limit for a single lab transport payload.
pub const HARD_MAX_FRAME_SIZE: usize = 1_048_576;

/// Four-byte, big-endian, length-prefixed stream framing.
///
/// The codec is suitable for a blocking [`std::net::TcpStream`], but remains
/// generic over `Read` and `Write` so partial and malformed input can be tested
/// deterministically. It authenticates nothing; callers must authenticate and
/// decode the returned payload separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCodec {
    max_frame_size: usize,
}

impl FrameCodec {
    /// Creates a codec with a non-zero bound no larger than the hard limit.
    pub fn new(max_frame_size: usize) -> Result<Self, FrameConfigError> {
        if max_frame_size == 0 {
            return Err(FrameConfigError::ZeroMaximum);
        }
        if max_frame_size > HARD_MAX_FRAME_SIZE {
            return Err(FrameConfigError::MaximumTooLarge {
                requested: max_frame_size,
                hard_maximum: HARD_MAX_FRAME_SIZE,
            });
        }
        Ok(Self { max_frame_size })
    }

    /// Maximum payload accepted by this codec.
    #[must_use]
    pub const fn max_frame_size(self) -> usize {
        self.max_frame_size
    }

    /// Reads one complete frame.
    ///
    /// A clean EOF before the first header byte returns `Ok(None)`. EOF after
    /// any header or payload byte is a fail-closed truncation error.
    pub fn read_frame<R: Read>(&self, reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
        let mut header = [0_u8; 4];
        if !read_first_byte(reader, &mut header[0])? {
            return Ok(None);
        }
        if let Err(error) = reader.read_exact(&mut header[1..]) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Err(FrameError::TruncatedHeader);
            }
            return Err(FrameError::io("read frame header", error));
        }

        let declared = u32::from_be_bytes(header);
        let length = usize::try_from(declared).map_err(|_| FrameError::LengthOverflow)?;
        self.validate_length(length)?;
        let mut payload = vec![0_u8; length];
        if let Err(error) = reader.read_exact(&mut payload) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Err(FrameError::TruncatedPayload { declared });
            }
            return Err(FrameError::io("read frame payload", error));
        }
        Ok(Some(payload))
    }

    /// Writes one complete frame without implicitly flushing the stream.
    pub fn write_frame<W: Write>(&self, writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        self.validate_length(payload.len())?;
        let length = u32::try_from(payload.len()).map_err(|_| FrameError::LengthOverflow)?;
        writer
            .write_all(&length.to_be_bytes())
            .map_err(|error| FrameError::io("write frame header", error))?;
        writer
            .write_all(payload)
            .map_err(|error| FrameError::io("write frame payload", error))
    }

    fn validate_length(&self, length: usize) -> Result<(), FrameError> {
        if length == 0 {
            return Err(FrameError::EmptyFrame);
        }
        if length > self.max_frame_size {
            return Err(FrameError::FrameTooLarge {
                declared: length,
                maximum: self.max_frame_size,
            });
        }
        Ok(())
    }
}

fn read_first_byte<R: Read>(reader: &mut R, byte: &mut u8) -> Result<bool, FrameError> {
    loop {
        match reader.read(std::slice::from_mut(byte)) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::io("read first frame header byte", error)),
        }
    }
}

/// Invalid defensive frame configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameConfigError {
    /// A zero maximum could never carry a valid frame.
    ZeroMaximum,
    /// The requested maximum exceeded the crate's absolute allocation bound.
    MaximumTooLarge {
        /// Requested maximum.
        requested: usize,
        /// Absolute maximum.
        hard_maximum: usize,
    },
}

impl Display for FrameConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaximum => formatter.write_str("frame maximum must be non-zero"),
            Self::MaximumTooLarge {
                requested,
                hard_maximum,
            } => write!(
                formatter,
                "frame maximum {requested} exceeds hard limit {hard_maximum}"
            ),
        }
    }
}

impl Error for FrameConfigError {}

/// Stable reason code for a frame refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameReasonCode {
    /// Header ended after at least one byte.
    TruncatedHeader,
    /// Payload ended before its declared length.
    TruncatedPayload,
    /// Zero-length frames are not admitted.
    EmptyFrame,
    /// Declared or supplied payload exceeded the configured bound.
    FrameTooLarge,
    /// Platform conversion could not represent the declared length.
    LengthOverflow,
    /// Underlying transport I/O failed.
    TransportIo,
}

impl FrameReasonCode {
    /// Stable machine-readable log and protocol spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "FRAME_REFUSED_TRUNCATED_HEADER",
            Self::TruncatedPayload => "FRAME_REFUSED_TRUNCATED_PAYLOAD",
            Self::EmptyFrame => "FRAME_REFUSED_EMPTY",
            Self::FrameTooLarge => "FRAME_REFUSED_TOO_LARGE",
            Self::LengthOverflow => "FRAME_REFUSED_LENGTH_OVERFLOW",
            Self::TransportIo => "FRAME_REFUSED_TRANSPORT_IO",
        }
    }
}

/// Fail-closed frame parsing or writing failure.
#[derive(Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Header ended after at least one byte.
    TruncatedHeader,
    /// Payload ended before the declared size.
    TruncatedPayload {
        /// Size declared by the peer.
        declared: u32,
    },
    /// Zero-length frames are rejected.
    EmptyFrame,
    /// Payload exceeded the configured allocation bound.
    FrameTooLarge {
        /// Declared or supplied size.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A wire length was not representable on this platform.
    LengthOverflow,
    /// Underlying transport I/O failed.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Portable I/O category.
        kind: io::ErrorKind,
        /// Backend detail for diagnostics.
        message: String,
    },
}

impl FrameError {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    /// Stable reason code for structured logs and replies.
    #[must_use]
    pub const fn reason_code(&self) -> FrameReasonCode {
        match self {
            Self::TruncatedHeader => FrameReasonCode::TruncatedHeader,
            Self::TruncatedPayload { .. } => FrameReasonCode::TruncatedPayload,
            Self::EmptyFrame => FrameReasonCode::EmptyFrame,
            Self::FrameTooLarge { .. } => FrameReasonCode::FrameTooLarge,
            Self::LengthOverflow => FrameReasonCode::LengthOverflow,
            Self::Io { .. } => FrameReasonCode::TransportIo,
        }
    }
}

impl Display for FrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("frame header was truncated"),
            Self::TruncatedPayload { declared } => {
                write!(
                    formatter,
                    "frame payload was shorter than declared length {declared}"
                )
            }
            Self::EmptyFrame => formatter.write_str("empty frames are refused"),
            Self::FrameTooLarge { declared, maximum } => write!(
                formatter,
                "frame length {declared} exceeds configured maximum {maximum}"
            ),
            Self::LengthOverflow => formatter.write_str("frame length cannot be represented"),
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
        }
    }
}

impl Error for FrameError {}
