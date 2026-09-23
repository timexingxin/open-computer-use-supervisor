# Playwright Lifecycle Adapter

> **Session-Scoped Browser Management**:
> Manages the lifecycle of disposable Playwright and Chromium instances created specifically by AI agent test sessions.

## Key Principles

1. **User Chrome Invariance**:
   User Google Chrome, Chrome Canary, and default user profiles are strictly classified as `NEVER_KILL (USER_BROWSER)` and excluded from supervision.
2. **Launch-Ticket Attestation**:
   Playwright browser workers and processes are registered at creation time via Broker Launch Tickets.
3. **Graceful Owner Exit First**:
   Clean agent shutdown via `browser.close()` is always prioritized. Supervisor signal intervention is reserved exclusively for unmanaged orphan recovery.
4. **Disposable Profile Cleanup**:
   Ephemeral test user-data directories created by the session can be safely removed post-exit via TOCTOU-hardened file deletion checks.
