---
name: bintra-etw-telemetry
description: Inspect Event Tracing for Windows (ETW) sessions/providers and capture process-scoped temporal causality timelines using Bintra native Advapi32 OpenTraceW/ProcessTrace consumer, Event Log polling, and Toolhelp32 module-delta tracking.
metadata:
  framework: bintra
  version: "1.0.0"
  tier: runtime-telemetry
---

# Bintra: ETW Telemetry & Temporal Causality Skill

Use this skill when investigating Windows runtime instability, provider activity, late DLL loading, Windows Error Reporting (`WER 1001`) vs kernel resets (`System 41/1001`), Restart Manager locks, or pre-crash event timelines.

---

## 1. Execution Modes & Telemetry Provenance Contract

Bintra explicitly declares the active event backend in `EtwLiveCaptureSession.start_session()` so agents never confuse Event Log polling or synthetic test inputs with native ETW kernel streams:

| Host / Privilege State | `mode` | `etw_native_consumer_active` | `event_consumption_backend` |
|:---|:---|:---|:---|
| **Windows (Elevated Admin)** | `"NATIVE_REALTIME_ETW"` | `true` | `"ADVAPI32_OPENTRACE_PROCESSTRACE+WEVTAPI"` |
| **Windows (Elevated, consumer open failed)** | `"WIN32_SESSION_EVENTLOG_POLLING"` | `false` | `"WEVTAPI_EVENT_LOG_POLLING"` |
| **Windows (Non-Elevated User)** | `"USER_MODE_TELEMETRY"` | `false` | `"WEVTAPI_EVENT_LOG_POLLING"` *(+ Toolhelp32 module delta when PID set)* |
| **Non-Windows (Linux / macOS)** | `"SIMULATED"` | `false` | `telemetry_backend: "NONE_SIMULATED_NON_NT"` (`is_simulated: true`) |

Every captured `EtwEventRecord` carries an explicit `"source"` provenance tag:
- `"etw_native"`: Delivered asynchronously through `Advapi32` `OpenTraceW` / `ProcessTrace` (`EVENT_RECORD` callback).
- `"event_log_polling"`: Collected via `EventLogCollector.query_events` (`wevtapi.dll` / `wevtutil` fallback).
- `"toolhelp_module_delta"`: Non-intrusive `IMAGE_LOAD` deltas observed via Toolhelp32 snapshots when monitoring a specific `target_pid`.
- `"synthetic_manual"`: Caller-injected test/reconstructed events via `record_event(...)`.

> [!NOTE]
> **PID Filtering Rule:** Calling `get_timeline(pid=<X>)` with an explicit non-zero PID strictly filters to that process and **excludes `pid == 0` system-wide events** unless `include_global=True` is explicitly requested.

---

## 2. Tool Invocations: MCP vs CLI

### Task A: Auditing Active ETW Sessions & Registered TDH Providers

**MCP Tool:**
```json
{
  "name": "bintra_etw_audit",
  "arguments": {
    "action": "audit"
  }
}
```
*(Supports `action`: `"audit"`, `"session"`, `"providers"`, `"instances"` with optional `session_name`, `provider`, `query`, `limit`.)*

**CLI Command:**
```powershell
bintra etw-audit --format json
```

### Task B: Capturing & Correlating Pre-Crash Event Timelines

**MCP Tool:**
```json
{
  "name": "bintra_etw_capture",
  "arguments": {
    "session_name": "Bintra_Diagnostic_Trace",
    "target_pid": 1234,
    "duration_seconds": 2.0
  }
}
```

**CLI Command:**
```powershell
bintra etw-capture --session-name Bintra_Diagnostic_Trace --pid 1234 --duration 2.0 --format json
```

---

## 3. Reading `EtwTimelineCorrelator` Verdicts Accurately

Check these keys in the returned report:
- `event_sources`: Exact counts grouped by provenance (`etw_native`, `event_log_polling`, `toolhelp_module_delta`, `synthetic_manual`).
- `has_native_etw_events`: Boolean (`event_sources["etw_native"] > 0`) — verify this before concluding kernel ETW telemetry actually arrived.
- `temporal_verdict` & `causality_findings`:
  - `TEMPORAL_MEMORY_CHURN_DETECTED` (preceding `VIRTUAL_FREE` / `HEAP_FREE` events before crash timestamp)
  - `LATE_MODULE_INJECTION_DETECTED` (`IMAGE_LOAD` observed prior to crash, including non-elevated Toolhelp32 DLL loads)
  - `RECURRENT_APPLICATION_FAULT` (`APPLICATION_ERROR` / `WER_REPORT`)
  - `KERNEL_POWER_OR_BUGCHECK` (System-channel Event ID `41` or `1001`, cleanly separated from Application-channel `WER 1001`)
  - `FILE_LOCK_CONTENTION_BEFORE_CRASH` (`RESTART_MANAGER_LOCK`)
  - `GRAPHICS_PIPELINE_RESET_DETECTED` (`D3D` / `DXGI` / `GPU_TDR_OR_DEVICE_RESET` errors)
- `session_info.consumer_errors` (if any native consumer errors occurred during collection).
