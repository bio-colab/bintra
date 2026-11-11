# Security Policy

## Supported Versions

We actively provide security patches and bug remediation for the following versions of **Bintra**:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Safety Kernel Invariants & Mediated Exceptions

Bintra is engineered with a fail-closed **Reference Monitor (`ExecutionGuard`)**:
1. **Target Immutability:** Target binaries and neural model weights are strictly read-only reference artifacts. Any attempt to modify a target file in-place raises `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.
2. **Workspace Isolation:** All patches and generated outputs must be directed to an authorized, distinct output path.
3. **Restricted Command Execution:** No unsanitized shell execution (`shell=True`) is permitted. Windows diagnostic commands are restricted to the pre-registered read-only `CommandCatalog` / `CommandExecutor`.
4. **Stack Balance Proprioception:** Binary instruction modifications check stack pointer alignment heuristically and recalculate the PE structural checksum.
5. **Audit Persistence & Degradation Contract:**
   - **Mutation commands** (`patch`, `patch-binary`, `patch-weights`, and confirmed `update --yes`) enforce strict fail-closed audit logging (`AuditLogger.set_strict_persistence(True)`, `rotate_on_corrupt=False`). If the hash-chained log cannot be initialized, verified, or written, execution aborts fail-closed (`AUDIT_INIT_FAILED` / `AuditPersistenceError`).
   - **Read-only / diagnostic commands** surface persistent audit initialization or write failures openly via `"audit_degraded": true`, `"audit_degraded_reason"`, and `stderr` warnings rather than degrading silently.
6. **Documented Architectural Exceptions (Outside Workspace / Catalog Broker):**
   - `bintra update --yes` invokes `git fetch` / `merge --ff-only` / `pull --ff-only` and `pip install` after validating branch/ref patterns and requiring explicit `--yes`/`--confirm` consent.
   - `ghidra-bridge --daemon` spawns a detached background instance of `cli.py ghidra-bridge --start` using `sys.executable`; its optional system temp discovery marker (`.bintra_bridge.json`) is mediated under `Capability.TEMPDIR_MARKER_WRITE` and can be suppressed with `--no-temp-marker` / `publish_temp_marker: false`.
   - `ghidra-headless` launches the user's local Ghidra `analyzeHeadless` batch runner on explicit CLI/MCP invocation.
   - `AuditLogger` stores tamper-evident JSONL journals in `~/.bintra/logs/audit.jsonl` outside individual workspaces by design.
   - `FileUsageInspector` queries Windows Restart Manager (`RstrtMgr.dll`) and may open target paths with non-writing shared probe flags when checking exclusive locks.

---

## Reporting a Vulnerability

If you discover a security vulnerability or bypass of the safety kernel within Bintra:
1. **Do NOT open a public issue.**
2. Report the vulnerability privately via **GitHub Security Advisories** or email `security@bio-colab.org`.
3. Provide:
   - A description of the vulnerability and potential impact.
   - Exact steps or script to reproduce the bypass.
   - Affected Windows version and environment.

### Disclosure Policy & Response Timeline
- **Initial Acknowledgment:** Within 48 hours of receipt.
- **Triage & Assessment:** Within 5 business days.
- **Fix & Public Advisory:** Coordinated release once a verified remediation patch is developed and verified against the regression test suite.
