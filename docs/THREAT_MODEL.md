# Antigravity Process Supervisor — Final Threat Model (v1.0.0-rc.1)

## 1. Overview & Security Objectives

The Antigravity Session Process Supervisor operates on a multi-tenant or single-user desktop environment where developer tools, browsers, local agents, and test scripts run concurrently.
Its primary security objectives are:
1. **Zero Collateral Damage**: Never signal, kill, or unlink user applications, pre-existing developer sessions, or operating system infrastructure.
2. **Zero Unearned Authority**: An unprivileged process or on-disk tampering must never grant termination or deletion capabilities.
3. **Fail-Closed Under Uncertainty**: If process identity, start time, parentage, socket owner, or inode metadata cannot be verified with 100% certainty, the Supervisor performs **ZERO DESTRUCTIVE ACTIONS**.

---

## 2. Threat Vector Analysis & Countermeasures

| Threat Vector | Attack Mechanism | Attacker Goal | Supervisor Defense Strategy | Security Status |
| :--- | :--- | :--- | :--- | :---: |
| **T1: Forged Disk Records** | Attacker modifies `processes.json` or `resources.json` on disk to list target PIDs or paths | Trick Supervisor into killing arbitrary user processes or deleting system files | **Memory-Only Provenance Ledger**: On-disk records are strictly unprivileged audit mirrors. Deletion and signaling require an in-memory creation receipt (`attestedProcesses`, `attestedResourceReceipts`) verified with CSPRNG session secrets. | **ELIMINATED** |
| **T2: Stale Session Authority Recovery** | Attacker launches Supervisor referencing an old session directory after crash | Resurrect dead session authority to execute stale kills or unlinks | **Broker Memory Barrier**: Session secrets, launch capability tokens, and receipts exist exclusively in RAM. A restarted Broker initializes clean state; on-disk data is classified `STALE_PREVIOUS_SESSION` (`OBSERVE_ONLY`). | **ELIMINATED** |
| **T3: Ticket Replay & Forgery** | Attacker intercepts `ticketId` or guesses random UUIDs to attest arbitrary child PIDs | Claim unauthorized ownership over unassociated processes | **In-Memory Capability Tokens & Single-Use TTL**: Launch tickets can only be minted by presenting the secret in-memory `launcherCapabilityToken`. Tickets expire in 5000ms, enforce child PPID matching, and consume immediately upon use (`TICKET_ALREADY_USED`). | **ELIMINATED** |
| **T4: PID Reuse & Race Conditions** | Attested test process exits; OS reassigns same PID to unrelated user app | Send termination signal to incorrect victim process | **Temporal & Executable Recheck**: Pre-signal gate re-verifies `lstart` (start timestamp within 1s tolerance), canonical executable path, command fingerprint, and live snapshot before dispatching any signal (`PID_IDENTITY_CHANGED`). | **ELIMINATED** |
| **T5: Cross-Session Interference** | Concurrently running Session A attempts to terminate or delete resources from Session B | Cause denial-of-service or data corruption across tasks | **Session Cryptographic Boundary**: Every receipt, ticket, and socket command is strictly scoped to `sessionId`. Cross-session requests are hard-blocked (`CROSS_SESSION_RESOURCE_REJECTED`, `RESOURCE_BINDING_MISMATCH`). | **ELIMINATED** |
| **T6: Symlink Traversal & Directory Escape** | Attacker creates symlink socket/token (`zcode-cua-*.sock -> /etc/hosts` or `~/.zcode`) | Delete sensitive host files or configuration | **Strict Symlink Rejection**: Every stage (`verifyZCodeSocketPreUnlink`, `validateZCodeResourcePathSafety`) executes `lstat` and asserts `!isSymbolicLink()`. Symlinks are unconditionally blocked (`SYMLINK_DETECTED`). | **ELIMINATED** |
| **T7: Inode Replacement / TOCTOU Swap** | Attacker unlinks attested resource and recreates substitute file before unlink | Trick Supervisor into deleting replaced file | **Double Inode Verification & Fail-Closed Checks**: Mitigates common symlink-swap and TOCTOU scenarios through dev/inode revalidation and fail-closed checks. Receipt records `dev` and `ino` at creation time. Cleaner re-checks `lstat` immediately before `fs.unlinkSync`. Any mismatch throws `RESOURCE_IDENTITY_CHANGED` and aborts. | **MITIGATED** |
| **T8: Premature Credential / Socket Deletion** | Cleaner executes while owner process is actively transacting IPC | Disrupt running CUA or browser session | **Process Liveness & Descriptor Locks**: Sockets and tokens require all owning PIDs (`chainPids`) to be dead. Active open descriptors detected via `getOpenHandles()` trigger `BLOCKED_RESOURCE_IN_USE`. | **ELIMINATED** |
| **T9: Pattern Classification Spoofing** | Attacker creates file matching `zcode-cua-*.sock` or `zcode-cua-token-*.txt` | Trigger unauthorized cleanup of untracked files | **Pattern != Ownership Rule**: Filename syntax is purely categorization. Without active Broker creation attestation, candidate paths fail with `BLOCKED_NO_BROKER_RESOURCE_ATTESTATION`. | **ELIMINATED** |
| **T10: Production Service Collateral Damage** | Unhandled exception or misconfigured regex targets live user apps | Terminate Chrome, User ZCode IDE, or Terminal | **Semantic Never-Kill Gate**: High-priority absolute classification intercepting `/Applications/Google Chrome.app`, standalone `ZCode.app`, WindowServer, Finder, and language server before any role evaluation. | **ELIMINATED** |

---

## 3. Residual Risks & Transparent Limitations

1. **Userspace TOCTOU Race Window**:
   Between the final `lstat` check and `fs.unlinkSync(realpath)`, an extremely small userspace race window (microseconds) exists on standard POSIX filesystems without kernel-level `unlinkat(AT_HANDLE)`. Mitigates common symlink-swap and TOCTOU scenarios through dev/inode revalidation and fail-closed checks, though absolute mathematical atomicity cannot be claimed without kernel extension.
2. **Pre-Existing Unowned Processes**:
   The Supervisor intentionally **does not clean** processes created prior to session start or spawned by foreign applications without Broker tickets. Such processes remain `OBSERVE_ONLY`.
3. **Privileged Root Exploits**:
   If an attacker achieves `root` or `sudo` privilege on the host, userspace permission checks (`0600`) and UID matching can be bypassed by the operating system superuser. The Supervisor operates as a non-root user-level defense.
