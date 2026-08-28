# Gate 1 Production Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Advance the Gate 1 production service path with a retained fail-closed candidate control loop and systemd abstract-socket watchdog support.

**Architecture:** Retain `ProductionCandidateControl` in the agent daemon without opening external effects and handle systemd `@`-prefixed abstract notify sockets in `watchdog.rs`. TLS certificate rotation remains deferred until rotation and revocation policy is specified; SIGHUP continues to reload log level only.

**Tech Stack:** Rust 1.88, rustls 0.23, rustls-pki-types 1.15, rustix 1.1, Unix domain sockets.

**Spec:** `docs/GATE1A.md` and `docs/PRODUCT_COMPLETENESS.md`

## Global Constraints
- Forbid unsafe code (`unsafe_code = "forbid"`).
- Deny clippy lints (`panic`, `expect_used`, `todo`, `unimplemented`, `unwrap_used`).
- Zero unhandled I/O failures; all errors typed and fail-closed.
- Maintain compatibility with `cargo-deny 0.20.2` and Rust 1.88.0.

---

### Task 1: Fix systemd Abstract-Socket Watchdog Support

**Files:**
- Modify: `crates/quorumarc-service/src/watchdog.rs`
- Test: `crates/quorumarc-service/tests/daemon.rs`

- [ ] **Step 1: Write the failing test for abstract socket notification**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement abstract socket address handling in SystemdWatchdog**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 2: Defer Certificate & Key Reloading under SIGHUP

TLS hot reload is explicitly deferred. Rotation and revocation semantics are not specified, so accepting changed TLS paths or material during SIGHUP would weaken the current fail-closed configuration contract. Current behavior permits log-level reload only and rejects safety-field changes.

---

### Task 3: Connect Production Candidate Control Loop to Agent Daemon

**Files:**
- Modify: `crates/quorumarc-service/src/node.rs`
- Modify: `apps/quorumarc-agent/src/lib.rs`
- Test: `apps/quorumarc-agent/tests/production_daemon.rs`

- [ ] **Step 1: Write failing test verifying live candidate promotion workflow**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Wire CandidateControl election loop into ProductionNode**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes and push to origin**
