# PoC `BINTRA-OBS-002`: Dependency Resolution & Multi-Directory Context

- **Axis:** A1 — Static Analysis
- **Verdict:** `PARTIAL`
- **Primary Classification:** `Engine Gap` (4,096-export cap false-positive failures + missing host-process/app-dir loader context + no delay-load parsing)
- **Raw Evidence:** [`obs_002.json`](../evidence/obs_002.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_static_pocs.py
```

## 2. Empirical Results

| Binary | Location | Bintra Verdict | Imported DLLs / Resolved | API-Sets Resolved | Flagged Missing DLLs | Flagged Missing Exports | Actual Status at Runtime |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `obs64.exe` | `bin\64bit\` | **`DEPENDENCY_INTEGRITY_FAILURE`** | 31 / 31 | 10 | 0 | **202** | Valid (`Qt6Widgets` exports > 4,096!) |
| `obs.dll` | `bin\64bit\` | `HEALTHY` | 29 / 29 | 10 | 0 | 0 | Valid |
| `obs-frontend-api.dll` | `bin\64bit\` | `HEALTHY` | 7 / 7 | 2 | 0 | 0 | Valid |
| `obs-browser.dll` | `obs-plugins\64bit\` | **`DEPENDENCY_INTEGRITY_FAILURE`** | 10 / 5 | 0 | **5** (`obs.dll`, `obs-frontend-api.dll`, `Qt6*.dll`) | 0 | All 5 exist in `bin\64bit\` |
| `droidcam-obs.dll` | `obs-plugins\64bit\` | **`DEPENDENCY_INTEGRITY_FAILURE`** | 9 / 2 | 0 | **7** (`obs.dll`, `obs-frontend-api.dll`, `w32-pthreads.dll`, `Qt6*`, `av*`) | 0 | All 7 exist in `bin\64bit\` |
| `win-capture.dll` | `obs-plugins\64bit\` | **`DEPENDENCY_INTEGRITY_FAILURE`** | 16 / 13 | 7 | **3** (`obs.dll`, `w32-pthreads.dll`, `libcurl.dll`) | 0 | All 3 exist in `bin\64bit\` |

## 3. Root Causes Found
1. **Truncated Export Table Propagates False Missing-Export Errors:** `obs64.exe` imports C++ mangled Qt symbols (such as `?qt_metacall@QListWidget@@...`) from `Qt6Widgets.dll`. Because `BinaryFormatInspector._parse_pe_exports` stops at `4,096` symbols, `WindowsDependencyResolver` marks **202 genuine `Qt6Widgets.dll` exports as missing**, turning `obs64.exe` into `DEPENDENCY_INTEGRITY_FAILURE`.
2. **Plugin Directory vs Host Application Directory Blindness:** `WindowsDependencyResolver.get_search_directories(binary_path)` searches only the DLL's own directory (`obs-plugins\64bit\`), `System32`, and `PATH`. Because `obs64.exe` loads plugins from `bin\64bit\` (having already loaded `obs.dll`, `Qt6Core.dll`, `w32-pthreads.dll`, etc. into process space), Bintra falsely flags all cross-directory core imports as missing DLLs.
3. **No Delay-Load Audit:** Delay-loaded dependencies (like `libcef.dll`'s 45 DLLs) are never checked.
4. **What Actually Worked:** Win11 API-Set resolution (`10` API-Sets on `obs64.exe` and `obs.dll`, `7` on `win-capture.dll`), PE32+ architecture verification, and direct resolution for DLLs inside `bin\64bit\` (`obs.dll` and `obs-frontend-api.dll` both passed `HEALTHY`).
