# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-rc.1] - 2026-09-23

### Added
- **Supervisor Broker**: In-memory authority enforcing creation-provenance and single-use launch tickets.
- **Launch Ticket Authority**: Pre-authorized launch ticket issuance tied to caller PID, parent PID, and expiry TTL.
- **Process Identity & PID Reuse Defense**: Strict 8-factor process verification, nanosecond-precision start time checking, and canonical executable path resolution.
- **Controlled Signal Management**: Scoped single-PID signals (preferring SIGTERM), 0 process group kills, and strict pre-kill identity rechecking.
- **Playwright Lifecycle Adapter**: Creation-time attestation for browser workers, user profile isolation, and clean exit tracking.
- **ZCode CUA Interoperability Adapter**: Black-box lifecycle management for external ZCode CUA process chains (bridge, runner, helper, mcp-server) via standard stdio JSON-RPC.
- **TOCTOU-Hardened Resource Cleaner**: 14/15-factor pre-unlink verification for temporary files, sockets, and directories; symlink escape blocking; device/inode drift detection; and in-use handle protection.
- **Double-Action Safety & Idempotency**: Duplicate signals return `TARGET_ALREADY_EXITED`; duplicate unlinks return `NOOP_ALREADY_CLEAN`.
- **Tombstoning & Lifecycle State Metrics**: Bounded memory tracking for retired processes and resources.
- **Adversarial & Soak Test Suites**: 133 automated tests validating zero signals to unmanaged services and zero unlinks of pre-existing baseline resources.
- **Production Execution Lock**: Fail-closed gate (`executeAllowed = false`) enforcing dry-run safety for general production CLI usage.
