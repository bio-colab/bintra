# PoC `BINTRA-OBS-001`: Static PE Analysis, Mitigations & Function Discovery

- **Axis:** A1 — Static Analysis
- **Verdict:** `PARTIAL`
- **Primary Classification:** `Engine Gap` (PE parser caps & missing static RE primitives: strings, xrefs, delay-loads, version resources, internal function recovery without symbols)
- **Raw Evidence:** [`obs_001.json`](../evidence/obs_001.json)

## 1. Environment & Target Scope
- **Host Target:** OBS Studio `32.1.2` (`x64`) installed under `%ProgramFiles%\obs-studio\`.
- **Level 1 (Blind) Isolation:** Copies of 9 binaries (`obs64.exe`, `obs.dll`, `libobs-d3d11.dll`, `obs-frontend-api.dll`, `droidcam-obs.dll`, `obs-browser.dll`, `avcodec-61.dll`, `Qt6Core.dll`, `libcef.dll`) were placed in a temporary directory **without `.pdb` files** before calling `BinaryFormatInspector.inspect`, `bintra inspect`, `ContinuousDeobfuscator.deobfuscate_file`, and `SensoryCortex.evaluate_all_senses`.
- **Level 2 (Symbol-Assisted):** Enumerated real `SymTagFunction` counts from shipped `.pdb`s via Windows `dbghelp.dll` (`SymLoadModuleExW`, `SymEnumSymbolsW`).
- **Level 3 (PE Spec Ground Truth):** Verified full PE tables using `pefile.PE(..., fast_load=False)`.

## 2. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_static_pocs.py
```

## 3. Empirical Results (Bintra Blind vs PDB & `pefile`)

| Binary | Bintra `inspect` (ms) | Import DLLs (Bintra / `pefile`) | Imported Symbols (Bintra / `pefile`) | Exports Parsed / Header (`pefile`) | Level 2 PDB Functions (`SymTagFunction`) | Blind Export-Only Recall vs PDB | Delay-Load DLLs (`pefile`) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `obs64.exe` | 148.31 | 31 / 31 | 890 / 3,478 | 2 / 2 (2) | 21,940 | 0.01% | 0 |
| `obs.dll` | 193.23 | 29 / 29 | 280 / 280 | 1,782 / 1,782 (1,782) | 2,596 | 68.64% | 0 |
| `libobs-d3d11.dll` | 49.74 | 20 / 20 | 176 / 176 | 171 / 171 (171) | 339 | 50.44% | 0 |
| `obs-frontend-api.dll` | 34.97 | 7 / 7 | 43 / 43 | 96 / 96 (96) | 177 | 54.24% | 0 |
| `droidcam-obs.dll` | 73.42 | 9 / 9 | 251 / 255 | 10 / 10 (10) | 0* | N/A | 0 |
| `obs-browser.dll` | 120.82 | 10 / 10 | 496 / 496 | 12 / 12 (12) | 2,446 | 0.49% | 0 |
| `avcodec-61.dll` | 262.75 | 16 / 16 | 339 / 474 | 168 / 168 (168) | — | — | 0 |
| `Qt6Core.dll` | 562.33 | 29 / 29 | 352 / 385 | **4,096 / 8,149** (8,149) | — | — | 0 |
| `libcef.dll` (214 MB) | 2,017.84 | 17 / 17 | 365 / 632 | 212 / 212 (212) | — | — | **45** |

*\*`droidcam-obs.pdb` exists alongside the binary, and `dbghelp` returned 0 private `SymTagFunction` records.*

## 4. What Works vs What Fails

### Proven Capabilities
- Accurate PE32+ identification (`AMD64 (x86-64)`), `image_base`, `entry_point_rva`, `entry_point_file_offset`, `subsystem`, `sha256`, section characteristics, Shannon entropy, and Windows security mitigations (`aslr_dynamic_base`, `high_entropy_64bit_aslr`, `dep_nx_compat`, `control_flow_guard_cfg`).
- Scales cleanly even to `libcef.dll` (`214 MB`) in `2.02 s` without crashing or timing out.
- `ContinuousDeobfuscator.deobfuscate_file` reported `0` false-positive opaque predicates / CFF loops across OBS binaries.
- `SensoryCortex` returned all 10 sense evaluations consistently.

### Confirmed Gaps & Bugs
1. **PE Import Truncation (`Engine Gap`):** `_parse_pe_imports` caps parsed symbols at **128 per DLL** (and 64 DLLs), losing `2,588` of `obs64.exe`'s imports and `267` of `libcef.dll`'s imports.
2. **PE Export Truncation (`Engine Gap`):** `_parse_pe_exports` caps parsed exports at **4,096 entries**, cutting `Qt6Core.dll` (`8,149` exports) in half and corrupting downstream `WindowsDependencyResolver` checks.
3. **Missing Delay-Load Imports (`Engine Gap`):** `BinaryFormatInspector` detects `DelayImportDescriptor` RVA in `data_directories`, but never parses `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`—missing all **45 delay-loaded DLLs** in `libcef.dll` (`d3d11.dll`, `d3d12.dll`, `dxgi.dll`, `MFPlat.DLL`, etc.).
4. **No Standalone Strings, Xrefs, Resources/VersionInfo, Debug CodeView, or Internal Function Recovery (`Engine Gap`):** Blind analysis only sees exported symbols (`0.01%` of `obs64.exe` functions, `0.49%` of `obs-browser.dll` functions); recovering internal functions requires delegating to Ghidra or `.pdb` symbols.
