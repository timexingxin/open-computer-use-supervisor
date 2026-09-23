# Antigravity Process Supervisor — Architecture Freeze (v1.0.0-rc.1)

## 1. Executive Summary & Policy Declaration

**Status**: **FROZEN (Release Candidate 1 - v1.0.0-rc.1)**  
**Effective Date**: 2026-09-22  
**Governing Rule**: **No new destructive capabilities. Feature requests are DEFERRED by default.**

With the successful completion and verification of Phases S1 through S4.5, all dangerous and destructive capability development phases are formally concluded. The Antigravity Session Process Supervisor has established a complete, defense-in-depth, fail-closed lifecycle governance architecture.

From this milestone onward:
- **No Expansion of Scope**: No new process roles, resource roles, kill scopes, delete scopes, or automatic cleanup triggers will be introduced.
- **No General Production Execution**: Global production cleanup CLI execution (`executeAllowed = false`) remains **STRICTLY LOCKED**.
- **Default Policy for Ambiguity**: If ownership or attestation is uncertain, the Supervisor takes **ZERO ACTION** (no signal, no unlink).

---

## 2. Frozen Subsystems Matrix

| Subsystem | Milestone Phase | Frozen Capabilities & Boundaries | Governing Configuration |
| :--- | :--- | :--- | :--- |
| **Trust Root & Broker** | S1, S1.3 | Session trust root derived strictly from non-root parent process (`process.ppid > 1`). Single Broker daemon per session communicating over Unix domain socket with permissions `0600`. In-memory CSPRNG session secrets never persisted to disk. | `BROKER_CONFIG`, `SYSTEM_ROOT_PIDS` |
| **Launch Ticket Authority** | S1.4 | Minting tickets strictly requires an in-memory capability token (`launcherCapabilityToken`) held exclusively by authorized launchers. Single-use enforcement, 5000ms TTL, cryptographically bound intent. | `S1_4_TICKET_CONFIG` |
| **Creation Provenance & Never-Kill** | S1, S1.1, S2 | High-precision process classification replacing static live PID lists. Absolute semantic Never-Kill hierarchy protecting user Google Chrome, standalone user ZCode.app, Finder, WindowServer, launchd, Terminal, and Antigravity core services. | `NEVER_KILL_CATEGORIES`, `HARD_PROTECTED_EXECUTABLE_PATTERNS` |
| **Controlled Process Termination** | S2 | Pre-signal 10-point identity recheck (PID liveness, snapshot readability, Broker attestation, start time `lstart`, executable path, command fingerprint, Never-Kill, root validity, individual PID only). Single SIGTERM dispatch; controlled SIGKILL escalation strictly for verified disposable test children. Zero process group kills. | `S2_CONTROLLED_CONFIG`, `ControlledTerminator` |
| **Playwright Controlled Lifecycle** | S2.5 | Two-tier lifecycle governance for session-created test Chromium instances (`playwright-browser-main`, `playwright-helper`). Normal exit prioritizes `browser.close()` (0 Supervisor signals). Orphan recovery applies single-PID SIGTERM strictly to attested main browsers. Absolute immunity for user Chrome binaries. | `S2_5_PLAYWRIGHT_CONFIG`, `playwright-lifecycle.mjs` |
| **Temporary Resource Cleanup** | S3 | Scoped deletion of verified session-created test directories and Playwright test profiles (`playwright-profile`). TOCTOU-hardened path safety validation, bottom-up tree traversal, symlink refusal, and in-use descriptor detection (`lsof`). | `S3_RESOURCE_CONFIG`, `ResourceCleaner` |
| **ZCode CUA Controlled Lifecycle** | S4 | Manages freshly spawned ZCode Computer Use runtime chains (`zcode-cua-bridge` -> `zcode-cua-runner` -> `dev.zcode.cua-helper` -> `mcp-server`). Normal shutdown via bridge exit propagation (0 Supervisor signals). Orphan helper recovery applies single-PID SIGTERM with zero SIGKILL escalation. Cursor and focus invariant enforced. | `S4_ZCODE_CONFIG`, `zcode-lifecycle.mjs` |
| **ZCode Ephemeral Resource Cleanup** | S4.5 | Manages `zcode-cua-*.sock` and `zcode-cua-token-*.txt`. Filename pattern is classification, not ownership. Double attribution (`OWNER_CLEANED_RESOURCES` vs `DELETED_BY_SUPERVISOR`). 15-factor socket pre-unlink and 14-factor token pre-unlink verification. Zero token content reads. Baseline catalog (136 items) strictly immutable. | `S4_5_RESOURCE_CONFIG`, `resource-cleaner.mjs` |

---

## 3. Frozen Operational Invariants

1. **Fail-Closed Global Production Gate**:
   `PHASE_V0_1_CONFIG.executeAllowed = false`. The CLI command `agy-supervisor cleanup --execute` always fails closed and terminates immediately with exit code 1.
2. **Zero Process Group Kills**:
   Negative PGID signaling (`process.kill(-pgid)`) is forbidden across all modules. Signaling is strictly granular to individual attested PIDs.
3. **TOCTOU-Hardened Path-Based Unlink**:
   Filesystem deletions employ multi-stage verification (resolving canonical parent directories, verifying regular/socket file attributes, device ID and inode matching before and at unlink time, and rejecting symbolic links). While a minuscule userspace race window theoretically exists between final check and unlink, arbitrary path traversal is completely eliminated.
4. **Zero Token Content Reading**:
   The Supervisor cleanup / resource-management path performs zero token-content reads. Authentication token files are evaluated and unlinked strictly via POSIX inode metadata and process liveness proofs.
5. **Double Attribution Accounting**:
   When an application cleans its own ephemeral resources upon graceful shutdown, it is audited under `ownerCleanedSockets` / `ownerCleanedTokens`, and Supervisor unlink counters remain **0**. Supervisor only executes unlinks during verified orphan recovery.
6. **Background-First & Focus Invariance**:
   Native CUA and browser operations operate in background channels (CDP, AX Tree, Unix sockets) with zero physical mouse cursor drift (`dx = 0, dy = 0`) and zero active application focus stealing.
7. **No Automatic Stop Hook Binding**:
   Destructive cleanup is never automatically wired to unverified IDE stop hooks or process exit hooks. Operations occur solely via explicit lifecycle invocations.

---

## 4. Change Management & Deprecation Policy

1. **Feature Requests**: Any proposal for new capabilities, broad regex cleanup, unprompted daemon kills, or heuristic resource sweeps is **DEFERRED**.
2. **Bug Fixes Only**: Only security vulnerabilities, audit accounting discrepancies, or regression bugs within the frozen scope may be addressed.
3. **Historical Document Status**: All prior phase reports (S1, S1.1, S2, S2.5, S3, S4) represent progressive milestones. Where earlier assumptions were refined by subsequent red team findings, the latest frozen specifications take precedence.
