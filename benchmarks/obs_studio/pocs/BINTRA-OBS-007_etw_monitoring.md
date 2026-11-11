# PoC `BINTRA-OBS-007`: Live ETW Monitoring & Lifecycle Telemetry

- **Axis:** A4 — Dynamic Telemetry & ETW
- **Verdict:** `PARTIAL` (graceful, honest non-elevated degradation and clean `WEVTAPI` fallback without false claims, but captures **zero OBS-specific runtime/module/GPU/startup/shutdown events** under standard non-Administrator Windows privileges)
- **Primary Classification:** `Engine Gap` + Environmental Privilege Constraint (requires elevated Administrator token for `StartTraceW` kernel/ETW sessions, and fallback EventLog polling does not capture user-space process lifecycle events for OBS)
- **Raw Evidence:** [`obs_007.json`](../evidence/obs_007.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_runtime_pocs.py
```

## 2. Empirical Results During Full 47.27 s OBS Lifecycle Capture
- **Host Privilege Context:** Standard medium-integrity non-Administrator user token.
- `EtwLiveCaptureSession.start_session()` returned **honest explicit status**:
  - `status`: `"non_elevated"`
  - `mode`: `"USER_MODE_TELEMETRY"`
  - `etw_native_consumer_active`: `false`
  - `event_consumption_backend`: `"WEVTAPI_EVENT_LOG_POLLING"`
  - `warning`: `"Real-time kernel trace requires Administrator privileges. Operating in non-elevated EventLog telemetry mode."`
- **OBS Event Yield (`obs_pid=5224` across spawn -> 30 plugins loaded -> terminate):**
  - `global_timeline_count`: `5` (`event_log_polling` events: `EventLog`, `Security-SPP`, `igcc`, all `pid: 0`).
  - `obs_pid_filtered_count`: **`0`** (`consumer_errors_count: 0`, `stop_result.captured_events_buffered: 30`).
- `bintra etw-audit` exited `0` cleanly.

## 3. Honest Assessment
- Bintra does **not** fabricate simulated ETW events on non-elevated Windows; its privilege-fallback disclosure is accurate.
- Practically, however, under standard non-admin execution Bintra has **zero dynamic behavioral visibility** into OBS startup, plugin loads (`droidcam-obs.dll`), threads, D3D11/DXGI frame calls, or clean shutdown (`obs_pid_filtered_count = 0`).
