# PoC `BINTRA-OBS-003`: Ghidra Headless & Live JSON-RPC 2.0 Bridge Integration

- **Axis:** A2 — Ghidra Integration
- **Verdict:** `PARTIAL` (Headless auto-pipeline `bintra ghidra-headless` -> `ghidra-analyze` & Python/Jython bridge scripts **FAIL**; standalone `GhidraLiveBridgeServer` JSON-RPC 2.0 daemon queuing/auth **PASS**)
- **Primary Classification:** `Integration Issue`
- **Raw Evidence:** [`obs_003.json`](../evidence/obs_003.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_ghidra_pocs.py
```

## 2. Empirical Results

### A. `bintra ghidra-headless` Auto-Discovery & Script Pipeline
1. **Default Installation Lookup (`autodiscovery_without_env`):** Running `bintra ghidra-headless --file obs-frontend-api.dll` without `GHIDRA_INSTALL_DIR` failed immediately (`returncode: 1`, `Error: analyzeHeadless.bat not found at: C:\ghidra\support\analyzeHeadless.bat`), even though Ghidra `12.1.4` was present under `%USERPROFILE%\tools\ghidra`.
2. **Headless Java Bridge (`BintraGhidraBridge.java`) Self-Blocked by `ExecutionGuard`:** Passing `--ghidra-path` succeeded in launching Ghidra `12.1.4`, importing `obs-frontend-api.dll` (`12s` analysis, `.gpr` created), and extracting **High P-Code + CFG for `182 / 182` functions** (`obs-frontend-api.dll`, Level 1 Blind).
   - **Critical Integration Bug:** `BintraGhidraBridge.java` writes `bintra_ghidra_export_*.json` into `%TEMP%` and immediately invokes `bintra ghidra-analyze --input <TEMP>\bintra_ghidra_export_*.json --output <TEMP>\bintra_ghidra_plan_*.json`.
   - Bintra's `ExecutionGuard` treats `%TEMP%` (the parent directory of `--input`) as the protected target directory and **blocks the output write**:
     `TargetMutationError: TARGET_DIRECTORY_WRITE_FORBIDDEN: Writing inside target directory '...AppData\Local\Temp\bintra_ghidra_plan_....json' is prohibited.`
   - Worse, `BintraGhidraBridge.java` logs `Bintra Analysis failed with exit code: 1`, while `analyzeHeadless.bat` and `bintra ghidra-headless` **exit `0`**, masking the pipeline failure!

### B. `GhidraLiveBridgeServer` & `GhidraLiveBridgeClient` (JSON-RPC 2.0)
- Server bound cleanly to ephemeral loopback `127.0.0.1:39719` (`status: running`).
- **Fail-Closed Auth Verified:** Unauthorized `ghidra.poll_commands` with wrong token returned JSON-RPC error `-32001` (`"Authentication failed: Invalid or missing bridge token"`), while unauthenticated `ping` stays reachable as healthcheck.
- `register_client("obs-frontend-api.dll", "0x180000000", "x86_64", "12.1.4")` succeeded (`auth_token_accepted: true`).
- `bintra.deobfuscate_function` on `obs-frontend-api.dll` entry bytes succeeded over RPC.
- Injection methods (`inject_vad_snapshot`, `inject_structure_dissection` with `address_space="rva"`, `inject_pointer_chains` with `base_rva="0x1234"`) cleanly queued **`7` commands**, preserved explicit `"address_space": "rva"` on `APPLY_DATA_STRUCTURE`, `CREATE_BOOKMARK`, and `SET_PLATE_COMMENT`, and drained queue count from `7` to `0` on `poll_commands()`.

### C. GUI / Script Compatibility Defect in `BintraLiveBridgeService.py`
- Static syntax check confirmed `ghidra_scripts/BintraLiveBridgeService.py` uses Python 3 f-strings throughout (`f"http://..."`), despite containing a `# Jython 2.7 fallback inside Ghidra GUI` (`urllib2`). This makes it incompatible with Ghidra's built-in Jython interpreter unless executed via PyGhidra.
