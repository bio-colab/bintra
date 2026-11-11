# PoC `BINTRA-OBS-009`: OBS Plugin Architecture, Third-Party Differentiation & Embedded Runtimes

- **Axis:** A1 — Static & Component Architecture
- **Verdict:** `PARTIAL`
- **Primary Classification:** `Engine Gap` (PE export/import primitives exist, but Bintra has no OBS plugin classifier, no PE `VS_VERSION_INFO` extractor for embedded runtime/vendor identification, and fails dependency checks across the `obs-plugins\64bit` ↔ `bin\64bit` boundary)
- **Raw Evidence:** [`obs_009.json`](../evidence/obs_009.json)

## 1. Empirical Inventory of `%ProgramFiles%\obs-studio\` (`32.1.2`)
- **Core Layer (`bin\64bit\`):** `5` executables (`obs64.exe`, `obs-amf-test.exe`, `obs-ffmpeg-mux.exe`, `obs-nvenc-test.exe`, `obs-qsv-test.exe`) + `27` DLLs (including `obs.dll`, `obs-frontend-api.dll`, `Qt6*`, `avcodec-61.dll`, `w32-pthreads.dll`, `libx264-164.dll`).
- **Plugin Layer (`obs-plugins\64bit\`):** `1` child-process helper (`obs-browser-page.exe`) + `32` DLLs (including third-party `droidcam-obs.dll` and bundled Chromium Embedded Framework `libcef.dll`).
- **Hook Injection Layer (`data\obs-plugins\win-capture\`):** `graphics-hook32.dll` (PE32 32-bit) and `graphics-hook64.dll` (PE32+ 64-bit).

## 2. Multi-Layer Boundary & Third-Party Detection Matrix

| Binary | Size | Exports (`bintra`) | `obs_module_load` + `obs_module_ver` | Imports `obs.dll` / `obs-frontend-api.dll` / `Qt6` | `pefile` `CompanyName` / `FileVersion` | Bintra Dep Verdict (Isolation) |
| --- | ---: | ---: | :---: | :---: | --- | --- |
| `droidcam-obs.dll` | 2.17 MB | 10 | **Yes** | Yes / Yes / Yes | `DEV47APPS` / ProductVersion `7` | `DEPENDENCY_INTEGRITY_FAILURE` (7 in `bin\64bit\`) |
| `obs-browser.dll` | 807 KB | 12 | **Yes** | Yes / Yes / Yes | *(empty)* | `DEPENDENCY_INTEGRITY_FAILURE` (5 in `bin\64bit\`) |
| `win-capture.dll` | 141 KB | 8 | **Yes** | Yes / No / No | *(empty)* | `DEPENDENCY_INTEGRITY_FAILURE` (3 in `bin\64bit\`) |
| `obs-ffmpeg.dll` | 274 KB | 8 | **Yes** | Yes / No / No | `OBS Project` / `32.1.2` | `DEPENDENCY_INTEGRITY_FAILURE` (9 in `bin\64bit\`) |
| `obs-nvenc.dll` | 76 KB | 8 | **Yes** | Yes / No / No | `OBS Project` / `32.1.2` | `DEPENDENCY_INTEGRITY_FAILURE` (2 in `bin\64bit\`) |
| `obs-websocket.dll` | 1.24 MB | 11 | **Yes** | Yes / Yes / Yes | *(empty)* | `DEPENDENCY_INTEGRITY_FAILURE` (6 in `bin\64bit\`) |
| `obs-x264.dll` | 36 KB | 7 | **Yes** | Yes / No / No | `OBS Project` / `32.1.2` | `DEPENDENCY_INTEGRITY_FAILURE` (2 in `bin\64bit\`) |
| `win-wasapi.dll` | 78 KB | 8 | **Yes** | Yes / No / No | `OBS Project` / `32.1.2` | `DEPENDENCY_INTEGRITY_FAILURE` (1 in `bin\64bit\`) |
| `image-source.dll` | 60 KB | 7 | **Yes** | Yes / No / No | `OBS Project` / `32.1.2` | `DEPENDENCY_INTEGRITY_FAILURE` (2 in `bin\64bit\`) |
| `libcef.dll` | 214 MB | 212 | No | No / No / No | Chromium `127.145.7+g2b7d20b+chromium-127.0.6533.120` | `HEALTHY` (normal imports only; 45 delay-loads unchecked) |

## 3. Honest Evaluation
- Bintra's export parser correctly surfaces OBS plugin ABI exports (`obs_module_load`, `obs_module_ver`) for every plugin tested, which in principle enables identifying OBS plugins vs helper runtime DLLs (`libcef.dll`).
- **Missing Capabilities:** Bintra lacks built-in `VS_VERSION_INFO` extraction (needed to separate `DEV47APPS` `droidcam-obs.dll` from `OBS Project` `32.1.2` and fingerprint embedded Chromium `127.0.6533.120` inside `libcef.dll`), lacks plugin-to-host graph aggregation, and fails static dependency validation on every tested plugin because `bin\64bit\` is omitted from search paths.
