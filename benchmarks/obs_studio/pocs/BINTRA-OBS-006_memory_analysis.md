# PoC `BINTRA-OBS-006`: Live Memory Scanning, Pointer Paths & Structure Dissection

- **Axis:** A3 — Runtime & Memory Analysis
- **Verdict:** `PASS` (read-only Cheat Engine-style memory scan, next-scan filter, heuristic vtable C++ object dissection, and live depth-2 static pointer chain verification all executed cleanly against live `obs64.exe` without write access)
- **Primary Classification:** None (observed minor heuristic limits noted cleanly: dynamic non-rooted allocations legitimately yield 0 pointer paths)
- **Raw Evidence:** [`obs_006.json`](../evidence/obs_006.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_runtime_pocs.py
```

## 2. Empirical Results on Live `obs64.exe`

### A. Read-Only Value Scanning (`ProcessMemoryScanner`)
- `first_scan(string="OBS Studio", writable_only=True)` scanned **`604` regions** in **`750.19 ms`** on live PID `5224`, locating **`19` verified `HEAP` string candidates** (`4f42532053747564696f`).
- `next_scan(EXACT_VALUE)` confirmed **`19 / 19` surviving candidates**.

### B. Structure Dissection & Multi-Level Pointer Scanning (`StructureDissector` & `PointerScanner`)
- **Live C++ VTable Object Probe (Run 1, PID `8944`, VA `0x11d1aff890`):**
  - `StructureDissector.dissect` reconstructed **`12` fields** (`96` bytes) and generated a typed C struct, automatically resolving offset `0x0` as:
    `void** field_0x0; // vtable_ptr (obs64.exe+0x446060 -> obs64.exe+0x1A6B30)`
    alongside `heap_ptr`, `static_rdata_ptr (obs64.exe+0x457250)`, and `static_data_ptr (obs64.exe+0x4F122C)`.
  - `PointerScanner.find_pointer_paths(max_depth=2, max_offset=512, alignment=8)` scanned live RAM in **`10.65 s`** and discovered **`3` dereference-verified depth-2 paths** rooted at loaded Qt6 module globals:
    - `[[Qt6Gui.dll+0x752CF8] + 0x80] + 0x50` -> `0x11D1AFF890` (`verified: true`)
    - `[[Qt6Widgets.dll+0x5E1DA0] + 0x80] + 0x50` -> `0x11D1AFF890` (`verified: true`)
    - `[[Qt6Widgets.dll+0x5E1E38] + 0x100] + 0x0` -> `0x11D1AFF890` (`verified: true`)
- **Plain Dynamic String Buffer Probe (Run 2, PID `5224`):** Dissected **`16` fields** cleanly (`vtable_detected: false`) and reported **`0` static pointer paths** within depth 2 (zero fabricated results).
