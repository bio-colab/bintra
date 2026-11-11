# Field Benchmark Final Report: Bintra `v1.0.0` vs OBS Studio `32.1.2` (`x64`)

## 1. Executive Verdict
Testing Bintra `v1.0.0` unmodified against a real, complex Windows desktop application (**OBS Studio `32.1.2`**, 200 runtime modules, Qt6, FFmpeg, 214 MB `libcef.dll`, and third-party `droidcam-obs.dll`) proved strong **runtime Cheat-Engine-style memory/struct/pointer introspection, live static-dynamic parity, ExecutionGuard mediation, and MCP server engineering**, while exposing **specific, high-impact static PE truncation caps, VAD section-parsing corruption, non-elevated ETW blindness, and a self-blocking `ExecutionGuard` conflict inside the automated Ghidra headless bridge**.

| Verdict | Count | Test IDs |
| --- | ---: | --- |
| **`PASS`** | **4** | `006`, `008`, `010`, `012` |
| **`PARTIAL`** | **6** | `001`, `002`, `003`, `005`, `007`, `009` |
| **`FAIL`** | **1** | `004` |
| **`NOT TESTED`** | **1** | `011` |

---

## 2. Full 12-Test Matrix

| Test ID | Axis | Verdict | Classification | Key Empirical Summary |
| --- | --- | :---: | --- | --- |
| [`BINTRA-OBS-001`](pocs/BINTRA-OBS-001_static_pe_analysis.md) | A1 Static | `PARTIAL` | `Engine Gap` | PE32+/mitigations/entropy accurate up to `214 MB` `libcef.dll` (`2.02 s`); caps imports at `128/DLL` (`890` vs `3,478` on `obs64.exe`), caps exports at `4,096` (`Qt6Core.dll` `4,096` vs `8,149`), skips all `45` delay-load DLLs (`libcef.dll`), lacks strings/xrefs/`VS_VERSION_INFO`; blind function recall is `0.01%` (`obs64.exe`)–`0.49%` (`obs-browser.dll`) vs `.pdb` |
| [`BINTRA-OBS-002`](pocs/BINTRA-OBS-002_dependency_mapping.md) | A1 Static | `PARTIAL` | `Engine Gap` | `obs.dll` & `obs-frontend-api.dll` pass `HEALTHY` (`10` & `2` API-Sets resolved); `obs64.exe` falsely fails (`202` missing Qt exports from 4,096 export cap); `obs-plugins\64bit\*` falsely report missing `obs.dll`/`Qt6*` because `bin\64bit\` host loader context isn't modeled |
| [`BINTRA-OBS-003`](pocs/BINTRA-OBS-003_ghidra_integration.md) | A2 Ghidra | `PARTIAL` | `Integration Issue` | `bintra ghidra-headless` fails auto-discovery without `GHIDRA_INSTALL_DIR` (`C:\ghidra` hardcoded default); `BintraGhidraBridge.java` self-triggers `TargetMutationError` by writing output JSON into `%TEMP%` alongside input JSON (masked by `rc=0`); standalone `GhidraLiveBridgeServer` JSON-RPC (`7` queued actions, `-32001` auth, `rva` tags) passes; `BintraLiveBridgeService.py` uses Python 3 f-strings incompatible with Jython 2.7 |
| [`BINTRA-OBS-004`](pocs/BINTRA-OBS-004_pcode_extraction.md) | A2 Ghidra | `FAIL` | `Integration Issue` | `bintra_extract_pcode.py` aborts under standard `analyzeHeadless.bat` (`PyGhidra` not started); `BintraGhidraBridge.java` extracts `182` blind / `188` PDB functions (`obs-frontend-api.dll`) and `636` blind / `812` PDB (`libobs-d3d11.dll`), yet downstream automated `ghidra-analyze` aborts on `%TEMP%` `TargetMutationError` |
| [`BINTRA-OBS-005`](pocs/BINTRA-OBS-005_runtime_modules_and_vad.md) | A3 Runtime | `PARTIAL` | `Engine Gap` | Live audit of isolated `obs64.exe --multi --disable-shutdown-check` resolved all `200` loaded modules (`26` core + `30` plugins including `droidcam-obs.dll`) and `2,137` regions (`1,091.37 MB` commit, `1` W^X, `30` guard pages); **bugs caught**: ~45 corrupted `IMAGE_<non-ascii>` section categories & `stack_bytes: 0` |
| [`BINTRA-OBS-006`](pocs/BINTRA-OBS-006_memory_analysis.md) | A3 Runtime | `PASS` | — | Scanned `604` regions in `750 ms` (`19` `"OBS Studio"` hits, `19/19` next-scan); `StructureDissector` reconstructed live C++ vtable (`obs64.exe+0x446060 -> +0x1A6B30`, `12` fields); `PointerScanner` verified `3` depth-2 paths to `Qt6Gui.dll` & `Qt6Widgets.dll` in `10.65 s` |
| [`BINTRA-OBS-007`](pocs/BINTRA-OBS-007_etw_monitoring.md) | A4 ETW | `PARTIAL` | `Engine Gap` | Honest non-elevated `WEVTAPI_EVENT_LOG_POLLING` disclosure (`status: non_elevated`); captures `0` OBS-specific events (`obs_pid_filtered_count: 0`) during `47.27 s` launch-init-exit lifecycle under standard non-Admin privileges |
| [`BINTRA-OBS-008`](pocs/BINTRA-OBS-008_static_dynamic_correlation.md) | A4 Correlation | `PASS` | — | `3 / 3` exact `16-byte` live RAM ↔ PE file-offset parity (`obs.dll!obs_get_version` = `0x20010002`, `obs.dll!obs_startup`, `droidcam-obs.dll!obs_module_ver`); `47`-node/`42`-edge Evidence Graph generated cleanly |
| [`BINTRA-OBS-009`](pocs/BINTRA-OBS-009_plugin_architecture.md) | A1 Arch | `PARTIAL` | `Engine Gap` | PE exports confirm `obs_module_load`+`obs_module_ver` across all 9 tested plugins; Bintra lacks built-in OBS plugin taxonomy, `VS_VERSION_INFO` parsing (`DEV47APPS` vs `OBS Project 32.1.2` vs Chromium `127.0.6533.120`), and cross-dir dependency graph |
| [`BINTRA-OBS-010`](pocs/BINTRA-OBS-010_permission_guard.md) | A5 Guard | `PASS` | — | Host OBS SHA-256 unchanged; blocks in-place write, target-dir write, workspace escape, NTFS ADS, `PROCESS_MUTATE`, `SHELL_FREE_EXEC`, unapproved broker commands/flags; valid CoW patch & valid active 6-record audit chain (`11` legacy rotations under concurrent runs noted) |
| [`BINTRA-OBS-011`](pocs/BINTRA-OBS-011_version_differential.md) | A1 Diff | `NOT TESTED` | `Test Limitation` | Only `32.1.2` (`x64`) installed locally (`33.0.0 vs 33.0.1` absent); auxiliary same-version `SemanticFunctionMatcher` verified (`1.0` self-match, `0.6676` on `graphics-hook64` vs `32`, `0.0` on tiny constant stubs); no whole-PE diff orchestrator |
| [`BINTRA-OBS-012`](pocs/BINTRA-OBS-012_reporting_and_mcp.md) | A6 MCP | `PASS` | — | Live `stdio` JSON-RPC `initialize`, silent notifications, `34` tools, batch & error codes (`-32600`, `-32700`), live OBS calls succeed, workspace escape & bad schema rejected (`isError: true`) |

---

## 3. Level 1 vs Level 2 vs Level 3 Conclusions
1. **Level 1 (Blind, No `.pdb`) vs Level 2 (With `.pdb`):**
   - Without Ghidra, Bintra sees **only exported symbols** (`0.01%` of `obs64.exe`'s `21,940` PDB functions; `0.49%` of `obs-browser.dll`'s `2,446` PDB functions; `50.44%` of `libobs-d3d11.dll`'s `339` functions).
   - With Ghidra `BintraGhidraBridge.java`, blind function discovery jumped from **`96` exports -> `182` functions** (`obs-frontend-api.dll`, vs `188` with PDB) and **`171` exports -> `636` functions** (`libobs-d3d11.dll`, vs `812` with PDB) — proving Ghidra closes most of the blind function recovery gap once the `%TEMP%` `ExecutionGuard` self-block is fixed.
2. **Level 3 (PE Spec & Runtime Validation):**
   - Independent `pefile` validation immediately exposed Bintra's silent `128` import-per-DLL cap, `4,096` export cap (causing false missing-export failures on `Qt6Widgets.dll`), and complete omission of delay-load tables (`45` DLLs in `libcef.dll`).
   - Live Win32 process testing proved Bintra's `PointerScanner` and `StructureDissector` generalize cleanly to a real 1.09 GB Qt6/C++ application, while exposing raw-byte PE section name corruption (`IMAGE_<bytes>`) inside `VirtualMemoryInspector`.

---

## 4. Prioritized Engineering Action Items (Outside Current Read-Only Benchmark Scope)
1. **Remove/raise `BinaryFormatInspector` import (`128`) & export (`4,096`) caps and add Delay-Load + `VS_VERSION_INFO` parsing.** (`001`, `002`, `009`)
2. **Add `--app-dir` / host-executable loader context to `WindowsDependencyResolver`** for plugin directories like `obs-plugins\64bit\`. (`002`, `009`)
3. **Fix `BintraGhidraBridge.java` & `bintra_extract_pcode.py` output path** so `bintra ghidra-analyze --output` writes inside `%USERPROFILE%\.bintra\workspace\` rather than `--input`'s `%TEMP%` directory; remove Python 3 f-strings from `BintraLiveBridgeService.py`; surface subprocess non-zero exit codes in `bintra ghidra-headless` and support PyGhidra or Java fallback cleanly. (`003`, `004`)
4. **Sanitize in-memory PE section names in `VirtualMemoryInspector`** (validate NT header bounds and Printable ASCII characters) and implement TEB/stack-base detection so `stack_bytes > 0`. (`005`)
5. **Add non-admin user-mode ETW (`EventRegister`/Session telemetry or Toolhelp32 module-delta stream independent of `StartTraceW` elevation)** or document Admin requirement clearly for process/module tracing. (`007`)
