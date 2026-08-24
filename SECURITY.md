# Security policy

QuorumArc is not production-ready. Do not use this Gate 0 prototype to control
live workloads, shared storage, industrial devices, or safety-critical systems.

## Non-negotiable defaults

- No proof means no promotion.
- Unknown policy, voter, epoch, state root, fence, or clock state means closed.
- SSH shutdown is not accepted as authoritative fencing.
- RPO 0 is not claimed without two durable acknowledgements or an explicitly
  designed recoverable witness journal.
- Cryptographic session keys, nonces, and replay counters are never restored by
  copying opaque process memory into another security context.

## Reporting

Report vulnerabilities privately to the repository owner. Do not include live
credentials, customer data, or exploitable production details in a public issue.

Future security work includes signed proofs and receipts, measured boot/device
identity, key rotation, rollback protection, dependency review, fuzzing, and an
external protocol audit.
