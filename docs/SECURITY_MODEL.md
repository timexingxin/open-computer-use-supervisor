# Open Computer-Use Supervisor: Security Model

## Core Philosophy: Fail Closed

The security model is built on one foundational axiom:
> **An unverified operation is an aborted operation.**

If any attribute of a process or filesystem entity cannot be proven beyond doubt, the Supervisor will not signal, modify, unlink, or claim that entity.

---

## The 8-Factor Process Verification Matrix

Before any POSIX signal (`SIGTERM` or `SIGKILL`) can be dispatched to a candidate PID, the `verifyProcessOwnership` routine evaluates 8 mandatory factors:

| Factor | Name | Description | Failure Verdict |
| :---: | :--- | :--- | :--- |
| **F1** | **Live Existence** | PID is actively running and observable in the OS process table. | `ALREADY_TERMINATED` |
| **F2** | **Start Time Match** | Process `startTimeEpochMs` matches the recorded registration timestamp. Protects against PID wrap-around/recycling. | `PID_IDENTITY_DRIFT` |
| **F3** | **Executable Match** | Resolved canonical executable binary path matches the authorized registration executable. | `PID_IDENTITY_DRIFT` |
| **F4** | **Command Match** | Process command line string matches registration pattern. | `PID_IDENTITY_DRIFT` |
| **F5** | **Session Match** | Process record belongs to the currently active Broker session. | `REJECTED_FOREIGN_SESSION` |
| **F6** | **Provenance Attested** | Broker in-memory attestation receipt exists and is verified. Dead on-disk files cannot pass. | `BLOCKED_NO_BROKER_ATTESTATION` |
| **F7** | **Never-Kill Exempt** | Target does NOT match any entry in the Never-Kill Policy (Google Chrome, system daemons, language servers). | `BLOCKED_BY_NEVER_KILL_POLICY` |
| **F8** | **Source Trusted** | Registration source is strictly within `TERMINABLE_SOURCES` (`SPAWN_ATTESTED`, `PLAYWRIGHT_ATTESTED`, `BRIDGE_ATTESTED`). | `REJECTED_UNTRUSTED_SOURCE` |

---

## The 14/15-Factor Resource Verification Matrix

Before any temporary file, Unix domain socket, or directory can be unlinked or removed, the cleaner verifies structural and cryptographic factors:

1. **Path Safety**: Target path is strictly within approved temporary directories (`/tmp`, `/private/tmp`, `/var/folders`).
2. **Denylist Check**: Path is not in `HARD_PATH_DENYLIST` (`/`, `$HOME`, `/Users`, `/Library`, etc.).
3. **Symlink Rejection**: Path is not a symlink and contains no symlink components.
4. **Device & Inode Match**: Device ID and inode match creation-time attestation.
5. **No TOCTOU Mutation**: Identity confirmed via `fstat`/`lstat` immediately prior to `unlink`.
6. **Owner Dead**: All owning chain PIDs are confirmed terminated before leaf unlinking.
7. **No In-Use Handles**: `lsof` verifies zero open file descriptors targeting the resource.
8. **Broker Attested**: Valid in-memory registration receipt exists.
