# Antigravity Process Supervisor — Final Architecture Specification (v1.0.0-rc.1)

## 1. Executive Summary & Core Principle

**Release Status**: **Release Candidate 1 (v1.0.0-rc.1)**  
**Core Invariant**:
> *"Supervisor does not decide business actions. Supervisor only governs process and resource ownership, lifecycle attestation, and cleanup safety. The safest action when ownership is uncertain is ZERO ACTION."*

The Antigravity Session Process Supervisor provides deterministic, fail-closed lifecycle governance for transient processes and filesystem resources created during agentic workflows. It strictly eliminates rogue background process proliferation, resource leakage, and orphaned daemons while providing robust fail-closed protections for user personal applications, active development environments, and critical operating system services.

---

## 2. Integration with Antigravity Ecosystem & Routing Topology

In the overall Antigravity orchestration hierarchy, the Supervisor operates as an orthogonal lifecycle infrastructure provider, entirely distinct from business decision routers such as `computer-use-orchestrator`:

```text
                                  USER TASK
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           ▼                          ▼                          ▼
    Browser DOM / Web          Native macOS GUI          Raw Visual Fallback
           │                          │                          │
  ┌────────┴────────┐        ┌────────┴────────┐                 │
  ▼                 ▼        ▼                 ▼                 ▼
web-access     Playwright  zcode-cua      cua-driver /       screenshot /
(Shared CDP)   (Isolated)  (Official CUA) macos-mcp          vision model
  │                 │        │                 │                 │
  └────────┬────────┴────────┴────────┬────────┴─────────────────┘
           │                          │
           ▼                          ▼
     [ Business Operations & Semantic Execution ]
           │
           │  (Lifecycle Registration, Attestation & Scoped Recovery)
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                  SUPERVISOR BROKER (v1.0.0-rc.1)                 │
│                                                                  │
│  - Launch Ticket Authority (Memory-Only Capability Token)        │
│  - In-Memory Provenance Ledger (attestedProcesses & receipts)    │
│  - Semantic Never-Kill Gate (Chrome, User ZCode, OS Daemons)     │
│  - Controlled Process Terminator (10-Point Recheck, 0 Group Kill)│
│  - Scoped Resource Cleaner (TOCTOU-Hardened Unlink, 0 Token Read)│
│  - Double Attribution & State Tombstoning (NOOP Idempotency)     │
└──────────────────────────────────────────────────────────────────┘
```

### Functional Separation of Concerns
- **Orchestrators (`computer-use-orchestrator`, `browser-routing-orchestrator`)**: Choose surfaces, execute tools, read DOM/AX trees, and drive workflows.
- **Supervisor**: Holds creation receipts, verifies process and resource boundaries, enforces Never-Kill policies, logs exact integer audit accounting, and cleans up only verified leftovers when owner shutdown fails.

---

## 3. Subsystem Architecture & Trust Model

### 3.1 Trust Root Derivation & Broker Domain
- **Non-Root Parent Anchoring**: Session trust root is derived exclusively from `process.ppid`. PIDs 0 and 1 (`kernel_task`, `launchd`) are rejected unconditionally (`TRUST_ROOT_REJECTED`).
- **Communication Channel**: Dedicated Unix domain socket (`supervisor.sock`) confined to `~/.gemini/antigravity/runtime/sessions/<sessionId>/` with permissions `0600`.
- **CSPRNG In-Memory Secrets**: `sessionSecret` (32 bytes) and `launcherCapabilityToken` (32 bytes) are generated using cryptographic pseudo-random number generators at startup and stored strictly in volatile memory. They are **never persisted to disk** or exposed via CLI inspection.

### 3.2 Launch Ticket Authority
- **Minting Gate**: Only callers presenting the unforgeable in-memory `launcherCapabilityToken` can mint launch tickets.
- **Single-Use Enforcement**: Tickets are marked consumed upon first successful attestation; any replay attempt fails with `REJECTED_TICKET_ALREADY_USED`.
- **Strict TTL**: Hard expiration bound of 5000ms.
- **Ancestry Verification**: `attestSpawn` asserts that target process `ppid` matches the authenticated `launcherPid`.

### 3.3 Semantic Never-Kill Hierarchy
Process safety is evaluated through high-fidelity executable path and signature analysis rather than fragile live PID lists:
1. **User Chrome**: Any process originating from `/Applications/Google Chrome.app` is classified `USER_BROWSER` and granted absolute immunity.
2. **User ZCode**: Standalone `/Applications/ZCode.app/Contents/MacOS/ZCode` without bridge flags is classified `STANDALONE_USER_ZCODE` (`neverKill: true`).
3. **Core OS & Antigravity**: WindowServer, Dock, Finder, Terminal, launchd, and `language_server` are hard-protected by `HARD_PROTECTED_EXECUTABLE_PATTERNS`.

### 3.4 Controlled Single-PID Termination Engine
Prior to dispatching any POSIX termination signal, `ControlledTerminator` executes a **10-Point Identity Recheck**:
1. PID confirmed currently alive (`kill(pid, 0)`).
2. Live process snapshot successfully read via `ps`.
3. In-memory Broker creation attestation verified.
4. Process start time (`lstart` and epoch timestamp) unchanged (PID reuse protection).
5. Canonical executable binary unchanged.
6. Command fingerprint matches registration record.
7. Semantic Never-Kill policy re-evaluated.
8. Session root validity confirmed.
9. Individual PID only (`allowGroupKill: false`; negative PGID signaling is strictly prohibited).
10. Explicit role approval matching active scoped execution mode.

### 3.5 Ephemeral Resource Cleaner (TOCTOU-Hardened Path-Based Unlink)
Deletion is permitted exclusively for session-created test directories, Playwright test profiles, and ZCode CUA sockets and tokens:
- **15-Factor Socket Verification**: Verified socket type, non-symlink, approved temporary root, dev/ino matching receipt, owner process chain confirmed dead, and zero open descriptor handles (`lsof`).
- **14-Factor Token Verification**: Small bounded size (`<= 4096` bytes), restrictive mode (`0600` / `0400`), regular file, dev/ino matched, owner dead, zero open handles.
- **Zero Token-Content Reads**: The Supervisor cleanup / resource-management path performs zero token-content reads. Files are unlinked purely on inode metadata and process telemetry.

### 3.6 Double Attribution & State Tombstoning
- **Owner Self-Cleanup**: Normal application exits trigger self-cleanup recorded as `OWNER_CLEANED_RESOURCES`. Supervisor unlink counter = **0**.
- **Supervisor Orphan Recovery**: Abnormal crashes leave orphaned resources; Supervisor verifies factors and unlinks them as `DELETED_BY_SUPERVISOR`.
- **Idempotent Tombstoning**: Completed lifecycles are retired to `retiredProcesses` and `retiredResources`. Repeated cleanups return `NOOP_ALREADY_CLEAN` with 0 new signals and 0 new unlinks.

---

## 4. Frozen Configuration Gates

```javascript
export const PHASE_V0_1_CONFIG = {
  version: '1.0.0-rc.1',
  phase: '1.0.0-rc.1',
  dryRunDefault: true,
  executeAllowed: false, // Strict Fail-Closed Lock for general production execute
  lockReason: 'PRODUCTION_EXECUTE_LOCKED_RELEASE_CANDIDATE'
};
```
The general CLI command `agy-supervisor cleanup --execute` remains **STRICTLY LOCKED** and fails closed across all production environments.
