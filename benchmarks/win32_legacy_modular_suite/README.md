# Sanitized Real-World Win32 Modular Runtime Case Study

Sanitized field audit exercising **Bintra v1.1.0** against a multi-component Win32 PE32 (x86) legacy application workspace under Windows 10 Pro 22H2 (Build 19045.6466 x64, standard non-elevated user), without modifying any target executable on disk.

## Contents

- [`REPORT.md`](REPORT.md): Complete operational methodology, multi-layer analytical findings (PE anatomy, RTTI/PDB, binary diffing, deobfuscation, Authenticode catalog/format auditing, static + delay-load dependencies, 5 real MiniDump crash analyses correlation, WER/AppCompat telemetry, live runtime CPython & VirtualMemory introspection, ETW fallback capture, JSON-RPC Ghidra live bridge, High P-Code / SQLite pipeline, Safety Kernel isolation test), generic defects uncovered and fixed in Bintra, and verified tool boundaries.
- [`evidence/sanitized_summary.json`](evidence/sanitized_summary.json): Sanitized machine-readable aggregation across fast scan, deep static forensics, host/MCP protocol checks, and post-fix verification runs (local user names, machine names, drive paths, and proprietary identifiers redacted).

## Safety & Reproducibility Contract

- All scans against `<TARGET_ROOT>` ran strictly read-only (`ExecutionGuard` `TargetScope` immutability enforced).
- Surgical patch safety testing (`bintra_patch_binary`) ran exclusively on an isolated duplicate inside the user workspace and verified in-place target overwrite denial (`TARGET_WRITE_FORBIDDEN`).
- Regression tests covering all generic defects discovered during this audit live in `tests/test_field_audit_regressions.py`.
