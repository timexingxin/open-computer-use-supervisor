# Open Computer-Use Supervisor: Public Release Manifest

> **Package**: `open-computer-use-supervisor`  
> **Release Candidate**: `v1.0.0-rc.1`  
> **License**: Apache License 2.0  
> **Commit Subject**: `Initial public release candidate: v1.0.0-rc.1`  

---

## 1. Files Included in Public Release Tree

```text
open-computer-use-supervisor/
├── .github/
│   └── workflows/
│       └── ci.yml
├── bin/
│   ├── agy-supervisor
│   └── open-computer-use-supervisor
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ARCHITECTURE_FREEZE.md
│   ├── PLAYWRIGHT_ADAPTER.md
│   ├── RELEASE_READINESS.md
│   ├── SECURITY_MODEL.md
│   ├── THREAT_MODEL.md
│   ├── ZCODE_CUA_ADAPTER.md
│   └── security/
│       ├── FINAL_AUDIT_ACCOUNTING.md
│       ├── FINAL_RED_TEAM_REPORT.md
│       ├── FINAL_SECURITY_AUDIT.md
│       └── FINAL_SOAK_REPORT.md
├── examples/
│   └── simple-session.mjs
├── src/
│   ├── adapters/
│   │   ├── playwright/
│   │   │   ├── lifecycle.mjs
│   │   │   └── README.md
│   │   └── zcode-cua/
│   │       ├── lifecycle.mjs
│   │       ├── predicates.mjs
│   │       └── README.md
│   ├── cli/
│   │   └── cli.mjs
│   ├── core/
│   │   ├── broker.mjs
│   │   ├── config.mjs
│   │   ├── controlled-terminator.mjs
│   │   ├── identity.mjs
│   │   ├── ipc.mjs
│   │   ├── planner.mjs
│   │   ├── predicates.mjs
│   │   ├── registry.mjs
│   │   ├── resource-cleaner.mjs
│   │   ├── resource-verifier.mjs
│   │   └── verifier.mjs
│   ├── broker.mjs
│   ├── cli.mjs
│   ├── config.mjs
│   ├── controlled-terminator.mjs
│   ├── identity.mjs
│   ├── index.mjs
│   ├── ipc.mjs
│   ├── planner.mjs
│   ├── playwright-lifecycle.mjs
│   ├── predicates.mjs
│   ├── registry.mjs
│   ├── resource-cleaner.mjs
│   ├── resource-verifier.mjs
│   ├── verifier.mjs
│   └── zcode-lifecycle.mjs
├── tests/
│   ├── fixtures/
│   │   ├── attacker.mjs
│   │   ├── mock-zcode-bridge.mjs
│   │   ├── mock-zcode-helper.mjs
│   │   ├── mock-zcode-mcp.mjs
│   │   └── mock-zcode-runner.mjs
│   ├── attacker.mjs
│   ├── test-cli.test.mjs
│   ├── test-executable-spoofing-defense.test.mjs
│   ├── test-final-soak-integration.test.mjs
│   ├── test-foreign-unmanaged.test.mjs
│   ├── test-never-kill-policy.test.mjs
│   ├── test-pid-reuse-defense.test.mjs
│   ├── test-registration-verification.test.mjs
│   ├── test-s1-1-adversarial.test.mjs
│   ├── test-s1-3-broker-adversarial.test.mjs
│   ├── test-s1-4-ticket-authority.test.mjs
│   ├── test-s2-controlled-execution.test.mjs
│   ├── test-s2-5-playwright-lifecycle.test.mjs
│   ├── test-s3-resource-cleanup.test.mjs
│   ├── test-s4-zcode-lifecycle.test.mjs
│   ├── test-s4-5-zcode-resources.test.mjs
│   └── test-socket-in-use-defense.test.mjs
├── .gitignore
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── LICENSE_AUDIT.md
├── NOTICE
├── package.json
├── package-lock.json
├── README.md
├── SECURITY.md
└── THIRD_PARTY_NOTICES.md
```

---

## 2. Files Strictly Excluded from Public Tree

- `~/.gemini/antigravity/supervisor/` development history and local `.git/` commits.
- `.verification/` and local test receipt ledgers.
- `runtime/` and `sessions/` directories.
- `baseline_zcode_resources.json` (local machine snapshot).
- Ephemeral socket files (`*.sock`) and token files (`*.txt`, `*.token`).
- All 18 intermediate milestone reports from phases S1 through S4.5 (retained in private working tree only).

---

## 3. Pre-Commit Verification Summary

- **Total Test Cases**: 133 / 133 PASS (100%)
- **Secret Scan**: 0 secrets / credentials detected
- **PII Scan**: 0 personal emails, 0 personal filesystem paths, 0 machine PIDs detected
- **Proprietary Boundaries**: Zero ZCode binaries or proprietary internals; optional adapter architecture strictly enforced
- **Production CLI Gate**: `executeAllowed = false` (LOCKED)
