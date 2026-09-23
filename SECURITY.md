# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.0-rc.1` | :white_check_mark: | Current Release Candidate |
| `< 1.0.0-rc.1` | :x: | Development snapshots (superseded) |

---

## Reporting a Vulnerability

We take the security and safety of computer-use agent lifecycles seriously. If you discover a potential vulnerability (e.g., an unauthorized signal dispatch, a path traversal escape in resource cleanup, or an ownership attestation bypass):

1. **Do NOT report security vulnerabilities via public GitHub issues.**
2. Please report security issues privately via **[GitHub Private Vulnerability Reporting](https://github.com/timexingxin/open-computer-use-supervisor/security/advisories/new)** on this repository.
3. Include in your report:
   - A detailed description of the vulnerability.
   - Exact steps or minimal reproducible script to trigger the issue.
   - The impact on the host system or agent session.
   - Proposed remediation (if available).

You will receive an initial response acknowledging receipt within 48 hours.

---

## Default Safety Invariant

**Production Execution Remains Disabled by Default**:
The Release Candidate ships with general destructive execution permanently locked (`executeAllowed = false`, `Reason: PRODUCTION_EXECUTE_LOCKED_RELEASE_CANDIDATE`).

Any attempt to run destructive cleanup outside of an attested test execution harness will immediately abort with exit code `1` under the fail-closed invariant:
> `In accordance with safety rules, no POSIX kill signals or unlinks may be executed on this machine.`
