# PoC `BINTRA-OBS-011`: Version Differential Analysis (`33.0.0 vs 33.0.1`)

- **Axis:** A1 — Differential & Semantic Function Matching
- **Primary Verdict:** `NOT TESTED`
- **Primary Classification:** `Test Limitation` (only OBS Studio `32.1.2` `x64` is installed on the host; no `33.0.0` or `33.0.1` binaries exist locally)
- **Auxiliary Benchmarked Feature:** `SemanticFunctionMatcher.match_functions` on same-version `32.1.2` function byte slices
- **Raw Evidence:** [`obs_011.json`](../evidence/obs_011.json)

## 1. Primary Scope Boundary
Version differential benchmarking between OBS `33.0.0` and `33.0.1` (and tracking specific commits such as CEF 150 or plugin loader refactoring) could not be executed because only OBS `32.1.2` (`libcef.dll` Chromium `127.0.6533.120`) is present on the host. No fabricated cross-version claims are made.

## 2. Auxiliary Verification of `SemanticFunctionMatcher.match_functions` (`32.1.2` Pairs)
Even without a second OBS version, testing `SemanticFunctionMatcher` on real `64-byte` function prologues extracted from OBS `32.1.2` revealed important engine characteristics:

| Comparison Label | Input Pair | Cosine Similarity | `is_semantic_match` | Result Note |
| --- | --- | ---: | :---: | --- |
| `identical_obs_module_ver_obs_browser` | `obs-browser.dll!obs_module_ver` vs self | `1.0` | `true` (`HIGH`) | Exact vector match |
| `same_api_obs_module_ver_win_capture_vs_droidcam` | `win-capture.dll!obs_module_ver` vs `droidcam-obs.dll!obs_module_ver` | `0.0` | `false` (`LOW / NO MATCH`) | Tiny constant-returning functions lack enough instructions in raw slice (`0.0` fallback) |
| `d3d11_vs_opengl_device_present` | `libobs-d3d11.dll!device_present` vs `libobs-opengl.dll!device_present` | `0.0` | `false` (`LOW / NO MATCH`) | Tiny wrapper functions -> `"insufficient valid instructions"` |
| `graphics_hook64_vs_graphics_hook32_entrypoint` | `graphics-hook64.dll` EP vs `graphics-hook32.dll` EP | `0.6676` | `false` (`LOW / NO MATCH`) | Detects moderate mix similarity (`branch_topology_congruent: true`), below match threshold on raw 64-bit vs 32-bit CRT startup |

## 3. Additional Engine Observation (`Engine Gap` for Whole-Binary Diffing)
Bintra's `bintra match` operates on manually supplied raw hex byte slices of two functions (`--func1` / `--func2`). There is **no automated whole-PE function boundary diffing or binary-to-binary diff orchestrator** natively in Bintra without first extracting function boundaries via Ghidra (see Axis A2).
