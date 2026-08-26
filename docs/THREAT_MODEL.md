# Threat model

## Scope

This model covers the Gate 0 safety kernel and the planned Gate 1A GitHub lab.
It protects the right to create external effects for one declared workload. It
does not claim Byzantine consensus, hostile-kernel isolation, or production
resistance to a fully compromised administrator.

The primary safety objective is:

> For each workload, at most one live generation can create externally visible
> effects, and no candidate can activate behind acknowledged durable state.

Availability is secondary. When evidence is missing or contradictory, the
correct outcome is no writer rather than two writers.

## Assets

- single-writer authority and its epoch/lease;
- voter keys and peer identities;
- highest accepted epoch and boot incarnation;
- durable votes, promotion digests, and activation receipts;
- acknowledged workload operations, commit index, and state root;
- policy and protocol version;
- EffectGate enforcement state and audit trail.

## Trust boundaries

| Boundary | Trusted for | Not assumed |
|---|---|---|
| Rust safety kernel | Deterministic validation of supplied evidence | Truth of an adapter's hardware, clock, disk, or health statement |
| Durable store | Surviving acknowledged writes and detecting supported corruption | Protection from a lying disk, storage rollback by an administrator, or firmware compromise |
| Signature verifier | Authenticity under uncompromised keys and reviewed algorithms | Correct authorization policy or secrecy after key theft |
| Node agent | Protocol execution and local state transitions | Independence from its host kernel or root administrator |
| Witness | One durable vote per workload/epoch under policy | Byzantine safety after compromise or collusion |
| Effect adapter | Blocking effects at its declared boundary | Blocking undeclared paths or devices outside that boundary |
| GitHub runner | Repeatable software execution for one workflow | Independent power, clock, kernel, storage, or physical network failure domains |

## Fault and attacker capabilities

The testable design must tolerate or safely refuse under:

- process crash, restart, pause, and duplicate execution;
- loss, delay, duplication, and reordering of messages;
- partitions between any subset of A, B, and Witness;
- replay of valid old votes, proofs, receipts, and workload operations;
- malformed, oversized, truncated, unknown-version, and downgraded messages;
- candidate lag, state-root mismatch, and policy mismatch;
- torn/partial writes, checksum failure, unavailable storage, and simulated disk
  full at documented injection points;
- wall-clock rollback and lease expiry observed by the trusted-clock interface;
- accidental operator misconfiguration and missing credentials;
- an unauthenticated network peer attempting to join or issue requests.

The following exceed Gate 1A's safety claim and require other controls or future
work:

- two voting identities or their private keys compromised at once;
- a malicious witness intentionally violating the durable single-vote rule;
- a compromised kernel forging time, storage completion, process isolation, or
  EffectGate enforcement;
- BMC, PDU, switch, NIC, disk firmware, or storage controller compromise;
- physical access, supply-chain compromise, side channels, and denial of service;
- an administrator rolling back every durable copy and restoring old keys; and
- cloning a Witness private key together with every trusted store into an
  independently operating cluster instance.

## Threats and required response

| Threat | Required prevention/detection | Safe response |
|---|---|---|
| Old proof replay | Bind epoch, incarnation, workload, lease, policy, state, message ID, and complete digest; persist highest epoch | Reject and keep gate closed |
| Vote transplant | Bind voter, candidate, incarnation, epoch, workload, state, lease, and domain | Reject signature or binding mismatch |
| Same-epoch double vote | Persist the first vote before replying; compare exact candidate/digest on retry | Idempotent reply for same vote; reject different vote |
| Lease extension | Include exact start/end and uncertainty domain in signed bytes | Reject modified lease |
| Candidate behind | Compare required commit and state root with candidate durable evidence | Refuse promotion |
| Candidate lies about progress | Independently authenticate two-copy durable progress and health | Current honest-candidate lab evidence is insufficient; keep production gate closed |
| Partition mistaken for fence | Never infer fencing from heartbeat loss | Wait for authoritative fence or safe lease expiry |
| Partial/corrupt store | Framed records, checksums, atomic replacement/journal recovery, explicit ambiguity state | Block voting and promotion |
| Store rollback | Highest-epoch/incarnation checks across trusted durable copies; future anti-rollback adapter | Block when detected; Gate 1A cannot defeat undetectable total rollback |
| Clock rollback/pause | Monotonic source abstraction, last-observed persistence where applicable, conservative expiry guard | Self-fence |
| Message flood/oversize | Authentication, strict maximum sizes, timeouts, bounded queues | Drop/refuse without changing authority |
| Unknown protocol field/version | Strict canonical decoder and explicit compatible versions | Reject; never guess semantics |
| Forged/cross-node control command | Controller signature, command domain, target node, request ID, and complete canonical payload binding | Reject before advancing logical time or authority state |
| Forged/malformed node observation | Verify the exact request binding, expected node, canonical response, and node signature before failure classification | Halt automatic execution; never convert authentication failure into failure suspicion |
| Signed control replay | Exact latest-request cache plus monotonic controller sequence in the lab; durable session/sequence required for production | Return the cached decision only for an exact latest retry; reject stale or conflicting content |
| Fault-proxy manipulation | The lab proxy carries opaque end-to-end signed frames, binds only to loopback, and has no signing key | A mode change may deny or distort delivery but cannot create valid authority; malformed or replayed bindings close the requesting node's promotion path |
| Stolen/retired key | Key IDs, authorization set, rotation and revocation interface | Reject unauthorized or retired key |
| Cloned authority instance | Protected Witness ownership, identity-bound stores, external uniqueness, and effect fencing | Outside the GitHub one-shot lab claim; never treat local path locks as global proof |
| Valid journal transplant | V3 binds cluster, workload, node, role, and store ID; future authenticated anti-rollback format | Refuse expected/durable identity mismatch; a perfect clone or malicious replacement still requires external fencing and closed-gate repair |
| Undeclared output path | Continuity Capsule inventory and adapter review | Workload is ineligible for automatic promotion |
| Check/use race | Generation-scoped adapter operation and enforcement at I/O boundary | Fail closed; user-space test sink is not production fencing |

## Cryptography constraints

- Do not invent an encryption, signature, hashing, or canonicalization scheme.
- Use a reviewed standard signature implementation and a collision-resistant
  digest from maintained Rust crates.
- Prefix signed material with a stable domain and protocol version.
- Sign the canonical bytes or their unambiguous domain-separated digest, never
  an ad hoc subset of fields.
- Keep private keys out of the repository and workflow logs. Test keys must be
  visibly non-production fixtures with no reuse outside tests.
- Verification must consult explicit signer authorization and key status, not
  merely accept a mathematically valid signature.

Gate 1A can test rotation interfaces and retired-key refusal. Production key
provisioning, protected key storage, emergency revocation, and offline recovery
remain operational design work.

## Consensus and witness assumptions

The intended topology has two data nodes and one independent witness. A
candidate requires a policy-authorized quorum and valid fence/expiry evidence;
quorum alone does not make promotion safe. The design assumes authenticated
identities follow the durable voting protocol. It is not Byzantine fault
tolerant: a compromised majority can violate safety.

The witness must not host the protected workload, share the data-node durable
directory, or be treated as independent when it shares the same physical host.
The GitHub three-process topology tests behavior only and does not satisfy this
physical-independence assumption.

Production Witness credentials must not be compiled into or provisioned to a
candidate. Test fixtures are not key custody. Copying a Witness secret and all
trusted state creates an indistinguishable authority clone outside this safety
claim. A production design needs protected secret ownership, rotation and
revocation, immutable membership/store identity, and a separately enforced
effect boundary. The bounded one-shot lab additionally rejects equal public-key
values across candidate, peer, and Witness roles; separate filenames alone are
not treated as key separation.

## GitHub workflow threats

A public repository can receive untrusted pull requests. GitHub-hosted runners
are disposable and must receive only the minimum token permissions. Workflows
must not expose signing material to forked PR code, must pin third-party actions
to reviewed revisions where feasible, and must not use untrusted values as shell
program text.

Do not attach permanent self-hosted lab machines to this public repository. An
untrusted workflow or dependency can persist on the machine, reach the local
network, or steal runner credentials. Hardware-in-the-loop automation belongs
in an access-controlled private lab repository with isolated accounts, narrowly
scoped tokens, explicit workflow allow-lists, and disposable test credentials.

## Residual-risk acceptance

Every release or gate-exit report must list unresolved threats, the validation
class used, and the concrete evidence URL. A risk is not resolved because an
interface or mock exists. Production claims require real adapter tests, physical
fault campaigns, operational key handling, and independent security review.
