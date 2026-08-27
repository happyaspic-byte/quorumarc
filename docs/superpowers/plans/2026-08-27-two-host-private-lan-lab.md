# Two-Host Private-LAN Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep the existing loopback lifecycle lab fail-closed, add an explicit private-LAN opt-in for 172.30.1.0/24, deploy the same binary to 172.30.1.21 and 172.30.1.22, and run a bounded two-host Active-loss campaign without claiming production HA.

**Architecture:** Introduce a shared `LabBindPolicy` that every lifecycle and continuous bind/connect path must consult. `--allow-lifecycle-lab` remains loopback-only. `--allow-private-lan-lab` additionally permits 172.30.1.0/24 unicast addresses and refuses 0.0.0.0, public, and other RFC1918 ranges. Node A stays on .22; Node B on .21; Witness is temporarily co-located on .22 and every evidence line records that shared failure domain.

**Tech Stack:** Rust, quorumarc-cluster process lab, SSH to the two Ubuntu hosts, GitHub Draft PR #2.

**Spec:** Session goal prompt “QuorumArc Two-Host Physical Lab Goal”.

## Global Constraints

- Branch `gate1a/github-lab` only; never merge `main`.
- Do not weaken lease, fence, signature, progress-contract, or EffectGate ordering.
- Malformed or authentication failures halt; they are never node-failure suspicion.
- Never print credentials, private keys, or password files.
- Evidence class is `TWO-HOST-SHARED-WITNESS-LAB`, not PHYSICAL PASS.

---

### Task 1: LabBindPolicy

**Files:**
- Create: `crates/quorumarc-cluster/src/lab_net.rs`
- Modify: `crates/quorumarc-cluster/src/lib.rs`

- [x] Failing tests for loopback-only vs private-LAN 172.30.1.0/24
- [x] Minimal policy implementation
- [x] Wire `mod lab_net` and re-export

### Task 2: Lifecycle and continuous transport

**Files:**
- Modify: `lifecycle.rs`, `auto_controller.rs`, `continuous/{primary,replica,client}.rs`, `fault_proxy.rs`, `main.rs`

- [x] Thread `LabBindPolicy` through bind/connect/accept
- [x] CLI flag `--allow-private-lan-lab`
- [x] Existing loopback tests still pass

### Task 3: Two-host process qualification

**Files:**
- Modify: `tests/lifecycle_process.rs` or add `tests/private_lan_bind.rs`

- [x] Loopback mode still refuses 172.30.1.22
- [x] Private-LAN mode refuses 8.8.8.8 / 0.0.0.0

### Task 4: Deploy .21/.22 and campaign

- [x] Same SHA-256 binary on both hosts
- [x] Localhost self-test on .21
- [x] Node A=.22, Node B=.21, Witness=.22
- [x] Active-loss promotion with zero dual writers and zero ACK loss
- [ ] Docs + commit + push + exact-head CI
