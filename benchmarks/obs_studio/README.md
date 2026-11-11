# Bintra `v1.0.0` vs OBS Studio `32.1.2` (`x64`) — Benchmark Suite

Reproducible field evaluation benchmark of **Bintra `v1.0.0`** against a real multi-layer Windows x64 application (**OBS Studio `32.1.2`**, including `obs64.exe`, `libobs` (`obs.dll`), Qt6 UI, FFmpeg 61, Chromium Embedded Framework `libcef.dll` 214 MB, and third-party plugin `droidcam-obs.dll` `DEV47APPS`).

## Directory Structure
- [`TEST_PLAN.md`](TEST_PLAN.md) — Formal 6-axis, 3-level evaluation plan & gap taxonomy.
- [`SUMMARY_REPORT.md`](SUMMARY_REPORT.md) — Complete consolidated findings, Level 1/2/3 comparison, and honest engine vs integration gaps.
- `scripts/` — Reproducible, read-only/isolated benchmark runners (zero modifications to `src/`, `ghidra_scripts/`, or `tests/`):
  - `run_static_pocs.py` (`BINTRA-OBS-001`, `002`, `009`, `011`)
  - `run_ghidra_pocs.py` (`BINTRA-OBS-003`, `004`)
  - `run_runtime_pocs.py` (`BINTRA-OBS-005`, `006`, `007`, `008`)
  - `run_guard_and_mcp_pocs.py` (`BINTRA-OBS-010`, `012`)
- `evidence/` — Raw sanitized JSON outputs (`obs_001.json` through `obs_012.json`).
- `pocs/` — 12 individual PoC reports (`BINTRA-OBS-001` through `BINTRA-OBS-012`).

## Quick Verdict Snapshot
- **PASS (4):** `006` (Live Scan / Struct / Pointer Chains), `008` (Static-Dynamic Parity + Evidence Graph), `010` (ExecutionGuard Boundaries), `012` (Live `stdio` MCP Server)
- **PARTIAL (6):** `001` (Static PE), `002` (Dependencies), `003` (Ghidra Integration), `005` (Runtime VAD / Modules), `007` (Non-Admin ETW), `009` (Plugin Architecture)
- **FAIL (1):** `004` (Automated High P-Code Extraction Pipeline)
- **NOT TESTED (1):** `011` (`33.0.0 vs 33.0.1` Differential — only `32.1.2` present locally; auxiliary matcher evaluated)
