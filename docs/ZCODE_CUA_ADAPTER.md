# Antigravity Process Supervisor — Phase S4 ZCode CUA Controlled Lifecycle Design

## 1. Executive Summary & Core Principle

**Core Principle**:
> *"Official ZCode CUA owns its normal shutdown. Supervisor only handles a leftover process when creation provenance is indisputable."*

Phase S4 extends the Supervisor's controlled lifecycle management to the official **ZCode Computer Use (CUA) runtime**, adhering to the principle of **Progressive Trust Expansion**:
- S1: Hardened provenance & session-scoped Broker
- S2: Controlled single-child disposable execution
- S2.5: Playwright / Chromium controlled lifecycle
- S3: Controlled temporary resource cleanup
- **S4**: **ZCode CUA Controlled Lifecycle** (New test chains only)

Production CLI cleanup remains strictly locked (`executeAllowed = false`).

---

## 2. Scope & Trust Boundary

### S4 Approved Scope
Only newly started ZCode CUA chains created after Phase S4 begins, spawned through Supervisor-attested execution:
```text
Antigravity Session Root
        ↓
Supervisor Broker
        ↓
zcode-cua bridge (node)
        ↓
official ZCode runner (ZCode with ELECTRON_RUN_AS_NODE=1)
        ↓
ZCode Computer Use Helper (dev.zcode.cua-helper / ZCode Computer Use.app)
        ↓
official MCP server (server.js --permission-broker-socket)
```

### Strictly Forbidden Operations in S4
1. **Never Adopt Existing ZCode Processes**: Any PID running prior to S4 start is immutable baseline (`BASELINE_PRE_EXISTING` / `OBSERVE_ONLY`). Zero signals, zero unlinks.
2. **Never Terminate User ZCode IDE**: Standalone `/Applications/ZCode.app/Contents/MacOS/ZCode` without bridge flags is hardcoded `STANDALONE_USER_ZCODE_APP` / `NEVER_KILL`.
3. **Never Issue Immediate SIGKILL**: `escalateToSigkill: false`. If a ZCode Helper does not exit upon `SIGTERM`, Supervisor reports `ZCODE_HELPER_SIGTERM_NOT_SUFFICIENT` and STOPS.
4. **Never Delete Sockets/Tokens in S4**: All socket and token files are recorded as `WOULD_DELETE_IN_S4_5` (deferred to S4.5).
5. **Never Delete ZCode Directories**: `~/.zcode` and `/Applications/ZCode.app` are protected by `HARD_PATH_DENYLIST`.
6. **No Automatic Session Exit Hooks**: Stop != session exit; CUA lifecycle is triggered only by explicit lifecycle protocols.

---

## 3. ZCode CUA Architecture & Lifecycle

### Process Components
1. **Bridge (`ROLES.ZCODE_BRIDGE`)**: Outer node process (`zcode-cua-bridge.mjs`). Manages stdio JSON-RPC and re-executes under the code-signed ZCode binary.
2. **Runner (`ROLES.ZCODE_RUNNER`)**: Re-executed Electron node process (`/Applications/ZCode.app/Contents/MacOS/ZCode`). Spawns the helper daemon and MCP server.
3. **Helper (`ROLES.ZCODE_HELPER`)**: Native macOS application (`ZCode Computer Use.app/Contents/MacOS/ZCode Computer Use`). Binds to a user-owned Unix socket (`zcode-cua-<id>.sock`) with token authentication (`zcode-cua-token-<id>.txt`).
4. **MCP Server (`ROLES.ZCODE_MCP_SERVER`)**: The official plugin server (`server.js`) connected to the helper via `--permission-broker-socket`.

### Normal Graceful Shutdown (`CLOSED_BY_OWNER_GRACEFULLY`)
On standard exit or EOF on stdin:
1. Bridge receives signal or stdin close.
2. Bridge triggers internal `cleanup()` handler.
3. Bridge sends `SIGTERM` to its children (runner, helper, mcp).
4. All children exit naturally within 200ms.
5. **Supervisor Signal Count = 0**.

---

## 4. Provenance Attestation Protocol (`attestZCodeChain`)

To ensure no existing or foreign ZCode processes can be adopted:
1. **Capability Token Verification**: Caller must hold the in-memory `launcherCapabilityToken`.
2. **Baseline PID Exclusion**: Neither bridge, runner, helper, nor MCP PID may exist in `baselinePids`.
3. **Liveness & Snapshot**: All PIDs must be alive and verifiable via `getProcessSnapshot`.
4. **Never-Kill Check**: None of the processes may violate `isNeverKill`.
5. **Ancestry & Launcher Flag Binding**:
   - Bridge must descend from session root.
   - Runner must be child or descendant of bridge.
   - Helper must have `--launcher-pid <runnerPid>` and `--socket <path>`.
   - MCP must have `--permission-broker-socket <path>`.
6. **Cryptographic In-Memory HMAC**:
   ```javascript
   payload = `${pid}:${snapshot.lstart}:${snapshot.canonicalExecutable}:${REGISTRATION_SOURCES.BRIDGE_ATTESTED}:${chainNonce}`
   signature = computeAttestationSig(this.sessionSecret, payload)
   ```
   Stored strictly in Broker RAM with `launch_nonce: chainNonce`.

---

## 5. Controlled Orphan Recovery Protocol (`recoverZCodeOrphan`)

When a bridge or runner dies unexpectedly, leaving the Helper running:
1. **Mode Gate**: Explicit `testExecutionMode === 'S4_ZCODE_TEST_ONLY'`.
2. **Role Gate**: Approved `ROLES.ZCODE_HELPER` (or runner/bridge).
3. **Source Gate**: Provenance must be `REGISTRATION_SOURCES.BRIDGE_ATTESTED`.
4. **Baseline Check**: Target PID must not be in baseline snapshot.
5. **Launcher Dead Confirmation**: If `launcher_pid` is specified, verify launcher process is dead.
6. **10-Point Pre-Signal Recheck**:
   - Liveness confirmed
   - Live snapshot captured
   - Broker in-memory attestation and HMAC signature verified
   - Start identity (`lstart`) unchanged
   - Executable path and comm unchanged
   - Command fingerprint unchanged
   - Never-Kill policy check passes (`neverKill: false`)
   - Session root directory valid
   - Zero Process Group Kill enforced (single PID targeting only)
   - Role approved
7. **Signal Dispatch**: Send single `SIGTERM` to Helper PID only (Zero Group Kill).
8. **Observation Loop**: Poll for exit up to `graceTimeoutMs` (2000ms).
9. **No Automatic SIGKILL Escalation**: If Helper does not exit, record `ZCODE_HELPER_SIGTERM_NOT_SUFFICIENT` and STOP without sending SIGKILL.
10. **Resource Deferral**: Record sockets/tokens as `WOULD_DELETE_IN_S4_5`.

---

## 6. Red Team & Safety Defenses

| Threat Vector | Defense Mechanism | S4 Result |
| :--- | :--- | :--- |
| Pre-existing ZCode Helper takeover | `baselinePids` check & creation attestation requirement | `ABORT_BASELINE_PID_PROTECTED` (0 signals) |
| Standalone user ZCode IDE termination | Executable & argument semantic classification | `STANDALONE_USER_ZCODE_APP` / `ABORT_NEVER_KILL` (0 signals) |
| Forged `processes.json` record | Broker in-memory HMAC attestation requirement | `BLOCKED_NO_BROKER_ATTESTATION` (0 signals) |
| Fake ZCode lookalike process | Registration source check (`MANUAL_TEST` rejected) | `ABORT_REGISTRATION_SOURCE_REJECTED` (0 signals) |
| Cross-session ZCode record | Broker session ID binding | `CROSS_SESSION_REQUEST_REJECTED` (0 signals) |
| PID recycling / drift | Pre-signal `lstart` and start-time epoch comparison | `PID_IDENTITY_CHANGED` (0 signals) |
| Broker offline during recovery | Fail-closed in-memory attestation gate | `BLOCKED_NO_BROKER_ATTESTATION` (0 signals) |
| Stale socket/token deletion | `S4_ZCODE_CONFIG.allowResourceDeletion = false` | Deferred to S4.5 (`WOULD_DELETE_IN_S4_5`) |
| Directory deletion (`~/.zcode`) | `HARD_PATH_DENYLIST` evaluation | Hard blocked from deletion |
| Focus / cursor hijacking | Background semantic execution & measurement | 0 pixel drift, 0 focus theft |
