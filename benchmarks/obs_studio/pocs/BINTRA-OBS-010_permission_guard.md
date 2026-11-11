# PoC `BINTRA-OBS-010`: Permission Boundaries, Execution Guard & Audit Integrity

- **Axis:** A5 — Safety Kernel & Permission Guard
- **Verdict:** `PASS` (all mediated target-mutation, traversal, NTFS ADS, `PROCESS_MUTATE`, unapproved subprocess/shell attempts blocked with immutable OBS binaries on disk; valid hash-chained audit verification)
- **Primary Classification:** None *(operational caveat noted on concurrent audit-log rotations and Bintra's self-triggered `%TEMP%` block observed in `003`/`004`)*
- **Raw Evidence:** [`obs_010.json`](../evidence/obs_010.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_guard_and_mcp_pocs.py
```

## 2. Empirical Results

### A. Installed OBS Binary Immutability
- Pre- and post-benchmark SHA-256 checksums for `%ProgramFiles%\obs-studio\bin\64bit\obs.dll`, `obs-frontend-api.dll`, and `obs-plugins\64bit\droidcam-obs.dll` matched identically (`host_obs_binaries_untouched: true`).

### B. Safety Kernel Rejection Matrix (Isolated Disposable Copy & Child PID)

| Attack / Bypass Vector | Expected Policy Behavior | Observed Result | Exception / Status |
| --- | --- | :---: | --- |
| In-place overwrite via `SurgicalBinaryPatcher` | Reject (`TARGET_WRITE_FORBIDDEN`) | Blocked | `TargetMutationError` |
| Write sibling file into target's directory | Reject (`TARGET_DIRECTORY_WRITE_FORBIDDEN`) | Blocked | `TargetMutationError` |
| Write outside workspace (`..\escaped.dll`) | Reject (`CAPABILITY_NOT_GRANTED` / `OUT_OF_SCOPE`) | Blocked | `SecurityViolationError` |
| NTFS Alternate Data Stream (`clean.dll:hidden_stream`) | Reject (`INVALID_PATH`) | Blocked | `SecurityViolationError` |
| `Capability.PROCESS_MUTATE` on live child PID | Reject unconditionally | Blocked | `SecurityViolationError` |
| `Capability.SHELL_FREE_EXEC` (`cmd.exe /c whoami`) | Reject unconditionally | Blocked | `SecurityViolationError` |
| Unregistered catalog command / disallowed `/badflag` | Reject in `SafeSubprocessBroker` | Blocked | `SecurityViolationError` (`os_ver` `0` succeeded) |
| Copy-on-Write patch inside authorized workspace | Permit CoW, leave source untouched | Permitted | `output_exists: true`, source SHA-256 intact, PE checksum updated |

### C. Audit Chain Check
- `AuditLogger.verify_audit_chain()` returned `{"is_valid": true, "records_verified": 6}` after benchmark operations.
- **Honest Operational Note:** `11` rotated `audit.jsonl.legacy.*.jsonl` files exist in `%USERPROFILE%\.bintra\logs\`, showing that earlier multi-process/CLI runs triggered sequence-discontinuity log rotation when processes wrote without shared cross-process serialization. Additionally, `ExecutionGuard` protects Bintra's mediated APIs (not unmediated Python stdlib `open()` calls), and `PROCESS_VM_READ` remains open for memory/pointer scans as designed.
