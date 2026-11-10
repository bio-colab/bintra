---
name: Windows Diagnostic / Driver Issue
about: Report a failure in Windows telemetry, driver matching, crash dumps, or event logs
title: "[WIN-DIAG] "
labels: ["windows-intelligence", "diagnostics"]
assignees: ''
---

**Diagnostic Domain**
- [ ] Windows Error Reporting (WER) / Crash Dumps (.dmp)
- [ ] Windows Event Log (`wevtapi.dll` / `wevtutil`)
- [ ] PnP Device & Driver Matching (SetupAPI / CfgMgr32 / `CM_PROB_*`)
- [ ] Registry Dual-View 32/64-bit Audit
- [ ] File Locks & Restart Manager (RstrtMgr)
- [ ] Service Control Manager (Advapi32)
- [ ] ETW Trace Sessions

**System Environment**
- Windows OS Build: (Run `python src/cli.py win-audit`)
- Privilege Level: User / Administrator / SYSTEM
- WOW64 Mode: Yes / No

**Observed Symptom**
Describe the crash, access violation (`0xc0000005`), locked file, or missing driver match.

**Diagnostic Command Output**
```powershell
python src/cli.py diagnose --file target.exe
# or
python src/cli.py dmp-inspect --file crash.dmp
```
*Output JSON:*
```json
[paste JSON output here]
```
