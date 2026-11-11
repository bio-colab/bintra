# Bintra Safety Policy & Non-Destructive Execution Contract

**Version:** 1.0.0  
**Status:** Active & Mandatory  
**Applies To:** All MCP Tools, Unified CLI Subcommands, Intelligence Providers, and Autonomous Agents

---

## 1. Foundational Axiom

> **التحليل لا يمنح سلطة الإصلاح (Analysis Does Not Grant Repair Authority)**  
> Discovering a defect, an invalid pointer, a missing dependency, a corrupt driver, or an active file lock grants `Bintra` the authority to isolate, analyze, and formulate evidence hypotheses—**never the ambient authority to mutate the host system or modify target binaries**.

`Bintra` is an intelligence and forensic reverse-engineering engine, not a system cleanup or maintenance utility. All operations executed against host system targets must be strictly non-destructive and read-only.

---

## 2. The 5 Inviolable Rules

1. **No Ambient Authority:** No module, tool, or agent inherits unverified privileges. Every operation must present a declared, typed capability.
2. **Default Deny:** Any operation, path, registry key, process handle, or command flag not explicitly recognized and whitelisted is rejected.
3. **Target Read-Only Scope:** The target binary, its directory, system binaries, running processes, PnP devices, and SCM services are strictly immutable.
4. **Workspace-Only Controlled Writes:** Writes are strictly quarantined to designated Bintra workspace paths (reports, temporary session scratchpads). Analysis outputs must never be written into the target executable's directory.
5. **Complete Mediation & Audit:** Every OS interaction is inspected, evaluated, and recorded by the central Safety Kernel (`ExecutionGuard`). Both permitted and denied operations produce hash-chained, tamper-evident audit logs.
   - **Strict Mutation Fail-Closed:** Mutating CLI paths (`patch-binary`, `patch-weights`, confirmed `update --yes`) refuse execution (`AUDIT_INIT_FAILED`) if the persistent audit log cannot be initialized, verified, or written.
   - **Explicit Degradation Telemetry:** Read-only diagnostic runs surface audit persistence failures via `"audit_degraded": true` and `stderr` warnings rather than failing silently.
   - **Scoped Operational Exceptions:** Explicitly documented exceptions outside the catalog/workspace envelope are self-update (`update --yes`), `ghidra-bridge --daemon` launch + `Capability.TEMPDIR_MARKER_WRITE` marker (opt-out via `--no-temp-marker`), `ghidra-headless`, `~/.bintra/logs/audit.jsonl`, and non-writing Restart Manager handle probes; none weaken target binary immutability (see `SECURITY.md`).

---

## 3. Mandatory Policy Matrix

| Operation Category | Permitted Access | Strictly Forbidden |
|:---|:---|:---|
| **File Access (Target)** | `GENERIC_READ`, non-exclusive sharing (`FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE`) | `GENERIC_WRITE`, file truncation, file deletion, file replacement |
| **File Access (Workspace)** | `GENERIC_WRITE` within verified `workspace_dir` (plus mediated `cap.tempdir.marker.write` opt-in) | Writes outside workspace; writes adjacent to target binary |
| **Windows Registry** | `KEY_READ \| KEY_WOW64_64KEY` | `KEY_WRITE`, `KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`, `RegDeleteKey` |
| **Process Inspection** | `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_VM_READ` (`ReadProcessMemory`), `TH32CS_SNAPPROCESS` | `PROCESS_TERMINATE`, `PROCESS_VM_WRITE` (`WriteProcessMemory`), `VirtualProtectEx`, `PROCESS_CREATE_THREAD`, code injection |
| **Service & Driver Inspection** | `EnumServicesStatusEx`, `QueryServiceConfig`, `SetupDiGetClassDevs` | `StartService`, `StopService`, `pnputil /delete-driver`, hardware state alteration |
| **Subprocess Execution** | Whitelisted catalog commands, strict argument whitelisting, `shell=False` | Arbitrary shell execution (`cmd /c`, `powershell -c`), unwhitelisted flags |
| **Process Privileges** | Medium integrity (standard user); graceful `ACCESS_DENIED` reporting | Automatic UAC elevation, token manipulation, privilege escalation |

---

## 4. Path Jail & Anti-Jailbreak Requirements

* **Canonical Resolution:** All filesystem paths must be resolved via `GetFinalPathNameByHandleW` or `os.path.realpath` to expose underlying physical targets.
* **Reparse Point Defense:** Traversal via NTFS Junctions or Symbolic Links escaping the authorized workspace boundary is rejected.
* **Alternate Data Streams:** Paths containing stream delimiters (`:`) beyond the drive colon are strictly blocked.
* **Target Directory Shield:** Analysis outputs and scratch files must never be written into `os.path.dirname(target_binary_path)`.

---

## 5. Security Decision Taxonomy

The Safety Kernel evaluates every operation against three deterministic verdicts:
* **`ALLOW`:** Safe, verified read-only operation strictly within the target scope.
* **`ALLOW_SCOPED`:** Permitted operation with explicitly declared boundaries (e.g. writing a report to the designated workspace).
* **`DENY`:** Any mutation of target binaries, system state, unauthorized execution, or unclassified request.

A user confirmation or external LLM prompt **cannot override a hard `DENY`** on target or system mutation.
