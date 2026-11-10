# Security Policy

## Supported Versions

We actively provide security patches and bug remediation for the following versions of **REA-Neural**:

| Version | Supported          |
| ------- | ------------------ |
| 7.4.x   | :white_check_mark: |
| < 7.4   | :x:                |

---

## Safety Kernel Invariants

REA-Neural is engineered with a strict **fail-closed Reference Monitor (`ExecutionGuard`)**:
1. **Target Immutability:** Target binaries and neural model weights are strictly read-only reference artifacts. Any attempt to modify a target file in-place raises `TargetMutationError(TARGET_WRITE_FORBIDDEN)`.
2. **Workspace Isolation:** All patches and generated outputs must be directed to an authorized, distinct output path.
3. **Restricted Command Execution:** No unsanitized shell commands or arbitrary subprocess execution are permitted. Windows diagnostic operations are restricted to pre-registered, read-only catalog commands.
4. **Stack Balance Proprioception:** Binary instruction modifications must preserve stack pointer alignment ($\Delta RSP = 0$) and update the PE structural checksum.

---

## Reporting a Vulnerability

If you discover a security vulnerability or bypass of the safety kernel within REA-Neural:
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
