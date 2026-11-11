# PoC `BINTRA-OBS-005`: Runtime Process Monitoring, Loaded Modules & VAD Map

- **Axis:** A3 — Runtime & Memory Analysis
- **Verdict:** `PARTIAL`
- **Primary Classification:** `Engine Gap` (accurate live Toolhelp32 module enumeration & VAD querying on 2,137 OBS regions, but PE section parser inside `VirtualMemoryInspector` corrupts ~45 section category names with raw non-ASCII bytes and reports `0` stack bytes)
- **Raw Evidence:** [`obs_005.json`](../evidence/obs_005.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_runtime_pocs.py
```

## 2. Empirical Results (Isolated OBS `32.1.2`, `--multi --disable-shutdown-check`, PID `5224`)
- **Live Non-Simulated Audit (`is_simulated: false`, `x86-64`):**
  - **Loaded Modules:** **`200`** DLLs/EXEs resolved in live RAM (`26` OBS core libraries in `bin\64bit\` + **`30`** OBS plugin libraries in `obs-plugins\64bit\`, confirming third-party `droidcam-obs.dll`, `obs-browser.dll`, `libcef.dll`, `win-capture.dll`, `obs-nvenc.dll`, `obs-websocket.dll`, etc. all loaded).
  - **VAD Memory Footprint:** **`2,137` regions** (`1,091.37 MB` committed, `516.17 MB` `MEM_IMAGE`, `88.71 MB` `HEAP`, `510.11 MB` `MEM_MAPPED`, `1` `W^X` anomaly, `30` `STACK_GUARD` pages).
  - **CLI Integration:** `bintra proc-modules obs.dll` and `bintra vad-inspect --pid <pid>` both exited `0`.

## 3. Confirmed Engine Bugs During Real Execution
1. **Corrupted `IMAGE_<bytes>` Section Categories:** `VirtualMemoryInspector`'s live PE section resolver produced dozens of binary-garbage category keys inside `region_category_counts` (e.g., `"IMAGE_H\x89|$ A\xb9\x82"`, `"IMAGE_\b\x00\xc5..."`) due to unvalidated section-name decoding across some of OBS's 200 loaded modules.
2. **Thread Stack Misclassification (`stack_bytes: 0`):** Despite identifying `30` `STACK_GUARD` pages, `VirtualMemoryInspector` reported **`stack_bytes: 0` (`stack_kb: 0.0`)**, failing to classify committed thread stack regions separately from private heap allocations.
