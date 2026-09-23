# ZCode CUA Interoperability Adapter

> **Important Boundary & Attribution**:
> This adapter interoperates with a legitimately installed and authorized ZCode Computer Use runtime.
> It **does not redistribute or contain ZCode proprietary binaries, source code, or internal tokens**.
> All trademarks, names, and software copyrights belong to their respective owners.

## Purpose & Scope

This adapter provides lifecycle management and orphan recovery for process chains spawned by an agent interacting with the ZCode CUA MCP bridge.

- **Process Chain**:
  `Supervisor Broker` -> `mcp-bridge` -> `ZCode runner` -> `ZCode Computer Use Helper` + `MCP Server`
- **Ownership Invariant**:
  Only process chains launched within the active session under an authorized Launch Capability Ticket are tracked.
- **Pre-existing Isolation**:
  Any ZCode processes, sockets, or tokens in existence prior to the session start are cataloged in `baselinePids` and `baselineSockets/baselineTokens` and marked **PERMANENTLY OBSERVE_ONLY**.
- **No Standalone Kill**:
  User-launched standalone `ZCode.app` instances are classified as `NEVER_KILL (STANDALONE_USER_ZCODE)` and strictly excluded from signals or shutdown.
