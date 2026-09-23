# License & Intellectual Property Audit

> **Audit Date**: 2026-09-23  
> **Audited Package**: `open-computer-use-supervisor` (v1.0.0-rc.1)  
> **Target License**: Apache License 2.0  

---

## 1. Codebase Provenance

- **Core Engine (`src/core/`)**:
  - `broker.mjs`, `identity.mjs`, `verifier.mjs`, `controlled-terminator.mjs`, `resource-cleaner.mjs`, `resource-verifier.mjs`, `planner.mjs`, `predicates.mjs`, `registry.mjs`, `config.mjs`, `ipc.mjs`.
  - **Verdict**: 100% original code authored specifically for session process safety and resource management. Clean origin with no external copy-pasting.

- **Adapters (`src/adapters/`)**:
  - `playwright/lifecycle.mjs`: Original code utilizing standard public Playwright APIs.
  - `zcode-cua/lifecycle.mjs`, `zcode-cua/predicates.mjs`: Original code interoperating with standard stdio JSON-RPC MCP and OS process tables. Contains zero proprietary binaries, zero decompiled source, zero extracted tokens.

- **Fixtures (`tests/fixtures/`)**:
  - `mock-zcode-bridge.mjs`, `mock-zcode-helper.mjs`, `mock-zcode-runner.mjs`, `mock-zcode-mcp.mjs`, `attacker.mjs`: Original synthetic mock fixtures designed for black-box protocol simulation.

---

## 2. Dependency Compatibility Matrix

| Dependency | Version | License | Compatibility with Apache-2.0 |
| :--- | :--- | :--- | :--- |
| **playwright** | ^1.63.0 | Apache-2.0 | **Directly Compatible** |
| **Node.js runtime** | >= 20.0.0 | MIT | **Permissive Compatible** |

---

## 3. Findings & Certification

1. **No GPL / Copyleft Contamination**: Zero GPL/LGPL/AGPL dependencies.
2. **No Proprietary Binary Bundling**: No Mach-O, `.app`, `.so`, or `.dll` binaries are distributed.
3. **Patent Grant**: The Apache-2.0 license grants clear patent protection for contributors and users.
4. **Status**: **APPROVED FOR APACHE-2.0 PUBLIC RELEASE**.
