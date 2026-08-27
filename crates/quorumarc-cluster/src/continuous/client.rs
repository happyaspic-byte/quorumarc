use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use quorumarc_rpo0::{CounterOperation, OperationId, WalEntry};
use quorumarc_runtime::FrameCodec;
use quorumarc_wire::{SigningKey, VerifyingKey};

use super::protocol::{ClientDecision, ClientRequest, ClientResponse, MAX_CONTINUOUS_FRAME};
use crate::lab_net::{LabBindPolicy, ensure_lab_bind};
use crate::{ClusterError, err};

#[derive(Debug)]
pub enum ContinuousSubmitOutcome {
    Acknowledged {
        operation_id: OperationId,
        commit_index: u64,
        value: u64,
        state_root: [u8; 32],
    },
    Refused(ClusterError),
    Unknown(ClusterError),
    NotSubmitted(ClusterError),
}

pub struct ContinuousClient {
    address: SocketAddr,
    bind_policy: LabBindPolicy,
    primary_key: VerifyingKey,
    signing_key: SigningKey,
    timeout: Duration,
    policy_hash: [u8; 32],
    next_request: u64,
}

impl ContinuousClient {
    pub fn new(
        address: SocketAddr,
        primary_key: VerifyingKey,
        signing_key: SigningKey,
        timeout: Duration,
        policy_hash: [u8; 32],
    ) -> Self {
        Self::new_with_policy(
            address,
            LabBindPolicy::LoopbackOnly,
            primary_key,
            signing_key,
            timeout,
            policy_hash,
        )
    }

    #[must_use]
    pub fn new_with_policy(
        address: SocketAddr,
        bind_policy: LabBindPolicy,
        primary_key: VerifyingKey,
        signing_key: SigningKey,
        timeout: Duration,
        policy_hash: [u8; 32],
    ) -> Self {
        Self {
            address,
            bind_policy,
            primary_key,
            signing_key,
            timeout,
            policy_hash,
            next_request: 1,
        }
    }

    pub fn apply(&mut self, operation: CounterOperation) -> ContinuousSubmitOutcome {
        if ensure_lab_bind(self.bind_policy, self.address).is_err()
            || self.timeout.is_zero()
            || self.policy_hash.iter().all(|byte| *byte == 0)
        {
            return ContinuousSubmitOutcome::NotSubmitted(err(
                "CONTINUOUS_CLIENT_CONFIG_REFUSED",
                "client requires an allowed lab address, nonzero timeout, and nonzero policy",
            ));
        }
        let request = match ClientRequest::sign(
            client_request_id(self.next_request),
            self.policy_hash,
            operation,
            &self.signing_key,
        ) {
            Ok(request) => request,
            Err(error) => return ContinuousSubmitOutcome::NotSubmitted(error),
        };
        self.next_request = match self.next_request.checked_add(1) {
            Some(next) => next,
            None => {
                return ContinuousSubmitOutcome::NotSubmitted(err(
                    "CONTINUOUS_REQUEST_EXHAUSTED",
                    "client request counter overflow",
                ));
            }
        };
        let mut stream = match TcpStream::connect_timeout(&self.address, self.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return ContinuousSubmitOutcome::NotSubmitted(err(
                    "CONTINUOUS_PRIMARY_UNAVAILABLE",
                    error.to_string(),
                ));
            }
        };
        if let Err(error) = stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .and_then(|()| stream.set_nodelay(true))
        {
            return ContinuousSubmitOutcome::NotSubmitted(err(
                "CONTINUOUS_SOCKET_CONFIG_FAILED",
                error.to_string(),
            ));
        }
        let codec = match FrameCodec::new(MAX_CONTINUOUS_FRAME) {
            Ok(codec) => codec,
            Err(error) => {
                return ContinuousSubmitOutcome::NotSubmitted(err(
                    "CONTINUOUS_FRAME_CONFIG_FAILED",
                    error.to_string(),
                ));
            }
        };
        let request_bytes = match request.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return ContinuousSubmitOutcome::NotSubmitted(error),
        };
        if let Err(error) = codec.write_frame(&mut stream, &request_bytes) {
            return ContinuousSubmitOutcome::Unknown(err(
                "CONTINUOUS_CLIENT_WRITE_UNKNOWN",
                error.to_string(),
            ));
        }
        let bytes = match codec.read_frame(&mut stream) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return ContinuousSubmitOutcome::Unknown(err(
                    "CONTINUOUS_RESPONSE_MISSING",
                    "primary closed without response",
                ));
            }
            Err(error) => {
                return ContinuousSubmitOutcome::Unknown(err(
                    "CONTINUOUS_RESPONSE_READ_UNKNOWN",
                    error.to_string(),
                ));
            }
        };
        let response = match ClientResponse::from_bytes(&bytes) {
            Ok(response) => response,
            Err(error) => return ContinuousSubmitOutcome::Unknown(error),
        };
        if let Err(error) = response.verify(&request, &self.primary_key) {
            return ContinuousSubmitOutcome::Unknown(error);
        }
        match response.decision {
            ClientDecision::Acknowledged => match validate_ack(&request, &response) {
                Ok(()) => ContinuousSubmitOutcome::Acknowledged {
                    operation_id: response.operation_id,
                    commit_index: response.commit_index,
                    value: response.value,
                    state_root: response.state_root,
                },
                Err(error) => ContinuousSubmitOutcome::Unknown(error),
            },
            ClientDecision::Refused => ContinuousSubmitOutcome::Refused(err(
                "CONTINUOUS_REFUSED",
                "primary returned an authenticated refusal",
            )),
            ClientDecision::Unknown => ContinuousSubmitOutcome::Unknown(err(
                "CONTINUOUS_UNKNOWN",
                "primary reported uncertain durability",
            )),
        }
    }
}

fn validate_ack(request: &ClientRequest, response: &ClientResponse) -> Result<(), ClusterError> {
    let expected_checksum = if response.commit_index
        == request.operation.expected_commit_index.saturating_add(1)
        && response.value >= request.operation.increment
    {
        WalEntry::from_operation(
            response.commit_index,
            response.value - request.operation.increment,
            request.operation,
        )
        .ok()
        .map(|entry| entry.record_checksum())
    } else {
        None
    };
    if response.left_role != 1
        || response.right_role != 2
        || expected_checksum != Some(response.left_checksum)
        || expected_checksum != Some(response.right_checksum)
    {
        return Err(err(
            "CONTINUOUS_ACK_RECEIPTS_REFUSED",
            "acknowledgement does not contain exact canonical dual durability receipts",
        ));
    }
    Ok(())
}

fn client_request_id(counter: u64) -> [u8; 16] {
    let mut request_id = [0x63; 16];
    request_id[8..].copy_from_slice(&counter.to_be_bytes());
    request_id
}
