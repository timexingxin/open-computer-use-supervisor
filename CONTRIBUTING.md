# Contributing to Open Computer-Use Supervisor

Thank you for your interest in contributing to Open Computer-Use Supervisor!

## Philosophy & Core Rules

1. **Safety First & Fail-Closed**:
   Any operation where ownership or identity cannot be proven must fail closed (`NO ACTION`).
2. **Never Touch User Resources**:
   Never add logic that targets default user browsers, system daemons, or unmanaged external services.
3. **Tests Are Blocking by Default**:
   All PRs must include test coverage and pass the entire regression suite (`npm test`).
4. **No Destructive Expansion**:
   Do not introduce unconstrained kill or recursive deletion capabilities.
5. **Clean Attribution & No Proprietary Bundling**:
   Do not commit proprietary binaries, reverse-engineered source code, or private tokens.

## Development Workflow

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the test suite:
   ```bash
   npm test
   ```
4. Verify no secret or path leaks before opening a Pull Request.
