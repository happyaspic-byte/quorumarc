use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::model::{
    ActivationReceipt, AuthorityState, LeaseBounds, PromotionRecord, StateRoot, VoteRecord,
    validate_identifier,
};

const MAGIC: &[u8; 8] = b"QARCJNL1";
const TRAILER: &[u8; 8] = b"QARCEND1";
const FORMAT_VERSION: u16 = 1;
const HEADER_LENGTH: usize = 24;
const CHECKSUM_LENGTH: usize = 4;
const MAX_FRAME_LENGTH: usize = 1024 * 1024;

/// Durable frame corruption detected during fail-closed recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Corruption {
    /// File is too short to contain a frame.
    Truncated,
    /// Frame magic is not recognized.
    BadMagic,
    /// Format version is unsupported.
    UnsupportedVersion,
    /// Reserved header bits are non-zero.
    UnknownHeaderFields,
    /// Recorded size and actual size differ, including trailing bytes.
    LengthMismatch,
    /// Frame exceeds the defensive recovery limit.
    Oversized,
    /// Stored IEEE CRC-32 checksum did not match, so corruption or a partial
    /// write is present. This checksum is not an authenticity mechanism.
    ChecksumMismatch,
    /// End marker is absent or damaged.
    BadTrailer,
    /// A presence flag or scalar encoding is non-canonical.
    MalformedField,
    /// Identifier bytes are not valid canonical UTF-8 identifiers.
    InvalidIdentifier,
    /// Recovered fields violate authority invariants.
    InvariantViolation,
    /// Generation zero appeared in a committed frame.
    InvalidGeneration,
}

impl Display for Corruption {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("durable authority frame is truncated"),
            Self::BadMagic => formatter.write_str("durable authority frame has bad magic"),
            Self::UnsupportedVersion => {
                formatter.write_str("durable authority frame version is unsupported")
            }
            Self::UnknownHeaderFields => {
                formatter.write_str("durable authority frame contains unknown header fields")
            }
            Self::LengthMismatch => {
                formatter.write_str("durable authority frame length does not match")
            }
            Self::Oversized => formatter.write_str("durable authority frame is oversized"),
            Self::ChecksumMismatch => {
                formatter.write_str("durable authority frame checksum does not match")
            }
            Self::BadTrailer => formatter.write_str("durable authority frame trailer is invalid"),
            Self::MalformedField => {
                formatter.write_str("durable authority frame contains a malformed field")
            }
            Self::InvalidIdentifier => {
                formatter.write_str("durable authority frame contains an invalid identifier")
            }
            Self::InvariantViolation => {
                formatter.write_str("recovered durable authority invariants are inconsistent")
            }
            Self::InvalidGeneration => {
                formatter.write_str("committed durable authority generation is zero")
            }
        }
    }
}

impl Error for Corruption {}

pub(crate) fn encode(state: &AuthorityState, generation: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(320);
    push_u64(&mut payload, state.highest_epoch);
    push_u64(&mut payload, state.incarnation);

    match &state.last_vote {
        Some(vote) => {
            payload.push(1);
            push_u64(&mut payload, vote.epoch());
            push_identifier(&mut payload, vote.candidate());
            payload.extend_from_slice(vote.proposal_digest());
        }
        None => payload.push(0),
    }

    match &state.last_promotion {
        Some(promotion) => {
            payload.push(1);
            push_u64(&mut payload, promotion.epoch());
            payload.extend_from_slice(promotion.digest());
            push_u64(&mut payload, promotion.lease().not_before_ms());
            push_u64(&mut payload, promotion.lease().expires_at_ms());
            push_u64(&mut payload, promotion.commit_index());
            payload.extend_from_slice(promotion.state_root().as_bytes());
        }
        None => payload.push(0),
    }

    push_u64(&mut payload, state.commit_index);
    match state.state_root {
        Some(root) => {
            payload.push(1);
            payload.extend_from_slice(root.as_bytes());
        }
        None => payload.push(0),
    }

    match &state.activation_receipt {
        Some(receipt) => {
            payload.push(1);
            push_u64(&mut payload, receipt.epoch());
            push_identifier(&mut payload, receipt.holder());
            push_u64(&mut payload, receipt.incarnation());
            payload.extend_from_slice(receipt.promotion_digest());
            push_u64(&mut payload, receipt.activated_at_ms());
            push_u64(&mut payload, receipt.expires_at_ms());
        }
        None => payload.push(0),
    }

    // Canonical identifiers are capped at 128 bytes, so the complete payload
    // is far below `u32::MAX` by construction.
    let payload_length = payload.len() as u32;
    let mut frame =
        Vec::with_capacity(HEADER_LENGTH + payload.len() + CHECKSUM_LENGTH + TRAILER.len());
    frame.extend_from_slice(MAGIC);
    push_u16(&mut frame, FORMAT_VERSION);
    push_u16(&mut frame, 0);
    push_u64(&mut frame, generation);
    push_u32(&mut frame, payload_length);
    frame.extend_from_slice(&payload);
    let checksum = crc32(&frame);
    push_u32(&mut frame, checksum);
    frame.extend_from_slice(TRAILER);
    frame
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(AuthorityState, u64), Corruption> {
    let minimum_length = HEADER_LENGTH + CHECKSUM_LENGTH + TRAILER.len();
    if bytes.len() < minimum_length {
        return Err(Corruption::Truncated);
    }
    if bytes.len() > MAX_FRAME_LENGTH {
        return Err(Corruption::Oversized);
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Corruption::BadMagic);
    }

    let mut header = Reader::new(&bytes[MAGIC.len()..HEADER_LENGTH]);
    if header.read_u16()? != FORMAT_VERSION {
        return Err(Corruption::UnsupportedVersion);
    }
    if header.read_u16()? != 0 {
        return Err(Corruption::UnknownHeaderFields);
    }
    let generation = header.read_u64()?;
    if generation == 0 {
        return Err(Corruption::InvalidGeneration);
    }
    let payload_length =
        usize::try_from(header.read_u32()?).map_err(|_| Corruption::LengthMismatch)?;
    let expected_length = HEADER_LENGTH
        .checked_add(payload_length)
        .and_then(|length| length.checked_add(CHECKSUM_LENGTH))
        .and_then(|length| length.checked_add(TRAILER.len()))
        .ok_or(Corruption::LengthMismatch)?;
    if expected_length != bytes.len() {
        return Err(Corruption::LengthMismatch);
    }

    let checksum_offset = HEADER_LENGTH + payload_length;
    let trailer_offset = checksum_offset + CHECKSUM_LENGTH;
    if bytes.get(trailer_offset..) != Some(TRAILER.as_slice()) {
        return Err(Corruption::BadTrailer);
    }
    let checksum_bytes = bytes
        .get(checksum_offset..trailer_offset)
        .ok_or(Corruption::Truncated)?;
    let recorded_checksum = u32::from_le_bytes(
        checksum_bytes
            .try_into()
            .map_err(|_| Corruption::Truncated)?,
    );
    if crc32(&bytes[..checksum_offset]) != recorded_checksum {
        return Err(Corruption::ChecksumMismatch);
    }

    let payload = bytes
        .get(HEADER_LENGTH..checksum_offset)
        .ok_or(Corruption::Truncated)?;
    let mut reader = Reader::new(payload);
    let highest_epoch = reader.read_u64()?;
    let incarnation = reader.read_u64()?;
    let last_vote = if reader.read_presence()? {
        let epoch = reader.read_u64()?;
        let candidate = reader.read_identifier()?;
        let digest = reader.read_array_32()?;
        Some(VoteRecord::from_validated(epoch, candidate, digest))
    } else {
        None
    };
    let last_promotion = if reader.read_presence()? {
        let epoch = reader.read_u64()?;
        let digest = reader.read_array_32()?;
        let not_before_ms = reader.read_u64()?;
        let expires_at_ms = reader.read_u64()?;
        let commit_index = reader.read_u64()?;
        let state_root = StateRoot::new(reader.read_array_32()?);
        Some(PromotionRecord::from_validated(
            epoch,
            digest,
            LeaseBounds::from_validated(not_before_ms, expires_at_ms),
            commit_index,
            state_root,
        ))
    } else {
        None
    };
    let commit_index = reader.read_u64()?;
    let state_root = if reader.read_presence()? {
        Some(StateRoot::new(reader.read_array_32()?))
    } else {
        None
    };
    let activation_receipt = if reader.read_presence()? {
        let epoch = reader.read_u64()?;
        let holder = reader.read_identifier()?;
        let activation_incarnation = reader.read_u64()?;
        let promotion_digest = reader.read_array_32()?;
        let activated_at_ms = reader.read_u64()?;
        let expires_at_ms = reader.read_u64()?;
        Some(ActivationReceipt::from_validated(
            epoch,
            holder,
            activation_incarnation,
            promotion_digest,
            activated_at_ms,
            expires_at_ms,
        ))
    } else {
        None
    };
    if !reader.is_empty() {
        return Err(Corruption::LengthMismatch);
    }

    let state = AuthorityState {
        highest_epoch,
        incarnation,
        last_vote,
        last_promotion,
        commit_index,
        state_root,
        activation_receipt,
    };
    state
        .validate()
        .map_err(|_| Corruption::InvariantViolation)?;
    Ok((state, generation))
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_identifier(output: &mut Vec<u8>, value: &str) {
    // All callers hold a model that already passed the 128-byte identifier
    // limit, which is safely representable by `u16`.
    let length = value.len() as u16;
    push_u16(output, length);
    output.extend_from_slice(value.as_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Corruption> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Corruption::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(Corruption::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, Corruption> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| Corruption::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, Corruption> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| Corruption::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, Corruption> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| Corruption::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_presence(&mut self) -> Result<bool, Corruption> {
        match self.take(1)?.first().copied() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(Corruption::MalformedField),
        }
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], Corruption> {
        self.take(32)?.try_into().map_err(|_| Corruption::Truncated)
    }

    fn read_identifier(&mut self) -> Result<String, Corruption> {
        let length = usize::from(self.read_u16()?);
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| Corruption::InvalidIdentifier)?
            .to_owned();
        validate_identifier(value).map_err(|_| Corruption::InvalidIdentifier)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{Corruption, decode, encode};
    use crate::{AuthorityState, StateRoot};

    #[test]
    fn encoding_is_deterministic_and_round_trips() -> Result<(), Corruption> {
        let state = AuthorityState {
            commit_index: 7,
            state_root: Some(StateRoot::new([9; 32])),
            ..AuthorityState::default()
        };
        let first = encode(&state, 4);
        let second = encode(&state, 4);
        assert_eq!(first, second);
        let (decoded, generation) = decode(&first)?;
        assert_eq!(decoded, state);
        assert_eq!(generation, 4);
        Ok(())
    }
}
