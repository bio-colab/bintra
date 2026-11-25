# Field Case Study: Full-Spectrum Bintra Audit of a Modular Win32 PE32 Runtime

**Environment:** Windows 10 Pro 22H2 (Build `19045.6466`, x64 AMD64, 8 cores), Python `3.12`, Medium Integrity (`0x2000`, non-elevated standard user), **Bintra `v1.1.0`**.  
**Target Posture:** Strictly read-only inspection of `<TARGET_ROOT>` (legacy PE32 x86 host binary `legacy_host_x86.exe`, modular `.asi` / `.cleo` plugins, audio/input proxies, Python companion scripting subsystem, and 5 real Windows CrashDumps under `<LOCALAPPDATA>\CrashDumps`). No target file on disk was modified; surgical patch verification executed strictly on isolated workspace copies.

---

## 1. Two-Phase Operational Methodology

1. **Phase 1 — Fast Initial Survey (`22` binaries, `27` root signature checks, dependency audit, `5` `.dmp` crash dumps, Python companion source/bytecode):** Indexed PE mitigations, slack overlays, packer heuristics, digital signatures, import completeness, and exception baselines without launching a fullscreen GUI process.
2. **Phase 2 — Deep Operational Execution Plan:**
   - **Static Deep Forensics & Diffing:** `PeDeepForensicsInspector` (`.pdata`, MSVC RTTI vftables, offline RSDS/PDB GUIDs), `SemanticBinaryDiffer` (`vorbisFile.dll.vanilla_bak` vs `vorbisFile.dll` proxy), `ContinuousDeobfuscator`, and `SensoryCortex` (10 metaphorical senses).
   - **Dependency & Host Ecosystem Audit:** Static IAT + PE `DelayImportDescriptor` resolution (`--app-dir`), Registry AppCompat shims, DirectX / graphics stack (`WindowsDeviceInspector`), and Windows Error Reporting (WER) history.
   - **Crash Telemetry & Evidence Fusion:** `WindowsCrashAnalyzer` + `CrashRootCauseAnalyzer` + `BinaryTriageOrchestrator` + `fuse_static_dynamic_ghidra` across all 5 genuine captured `.dmp` files.
   - **Full MCP Protocol & Host Introspection Surface:** JSON-RPC `initialize`, `server/discover`, all `4` resources, all `5` workflow prompts, `tools/list` pagination (`[25, 25, 1] = 51` tools), and `16` Windows host audit tools.
   - **Live Non-GUI Subprocess & Ghidra Pipelines:** Read-only `PROCESS_VM_READ` introspection (`proc-profile`, `vad-inspect`, `mem-scan`, `pointer-scan`, `struct-dissect`, `cpython_memory_forensics`), non-elevated `etw-capture`, `ghidra_live_bridge` queued-poll lifecycle, `ghidra-headless` execution diagnostics, High P-Code SSA matching/deobfuscation/SQLite store (`bintra_match_pcode`, `bintra_deobfuscate_pcode`, `bintra ghidra-plan`, `bintra_ghidra_analyze`), and isolated `bintra_patch_binary` Safety Kernel validation.

---

## 2. Key Analytical Findings Across the Target Suite

### 2.1 Static PE32 Anatomy, Forensics & Plugin Ecosystem
| Artifact | Arch / Size | Mitigations (`ASLR`/`DEP`/`CFG`/`LAA`) | Key Forensic Observations |
| :--- | :--- | :--- | :--- |
| `legacy_host_x86.exe` | PE32 (`14,383,616 B`) | `False / True / False / True` | 11 sections (duplicate `.text`/`.data`, `<LEGACY_STUB>` stub section); unsigned; `14` MSVC RTTI vftables; `9` static IAT DLLs + `4` delay-loaded DirectX DLLs (`d3d9.dll`, `DINPUT8.dll`, `DSOUND.dll`, `DDRAW.dll`); overall section entropy `5.3445`; SHA-256 `590b4be1...b345b6f`. |
| `bass.dll` | PE32 (`139,128 B`) | `True / True / False / False` | Authenticode `TRUSTED` (`EMBEDDED_AUTHENTICODE`); `PE_CERTIFICATE_TABLE_REGION_DETECTED` trailing security directory; `petite` packer marker identified. |
| `CLEO.asi` | PE32 (`325,120 B`) | `True / True / False / False` | Unsigned plugin host; `38` MSVC RTTI vftables; `CLEAN_EXACT_EOF`. |
| `cleo_redux.asi` | PE32 (`5,309,952 B`) | `True / True / False / True` | Unsigned runtime; `3` RTTI vftables; RSDS CodeView PDB reference (`cleo_redux.pdb`, GUID `DB1BEE62-D645-4AB2-918C-74901C920A0A`, age `1261`). |
| `dinput8.dll` | PE32 (`x86`) | `True / True / False / False` | App-local DirectInput wrapper; `28` MSVC RTTI vftables; `CLEAN_EXACT_EOF`. |
| `vorbisFile.dll` vs `.vanilla_bak` | PE32 (`53,760 B` vs `65,536 B`) | `True/True` vs `False/False` | `SemanticBinaryDiffer` (`pe_semantic_similarity=0.552`, `import_jaccard=0.3629`): removes `ogg.dll` (`16` APIs) + `vorbis.dll` (`22` APIs), adds Win32 ASI loader APIs (`LoadLibraryW`, `FindFirstFileA`, `VirtualProtect`), reduces exports from `34` -> `8` `ov_*` stubs (`export_jaccard=0.2353`, `26` `ov_*` exports removed). `vorbisFile.dll.vanilla_bak` matches `vorbisHooked.dll` byte-for-byte (`a08923479000...`). |
| `Frontend.cleo` (`cleo\CLEO_PLUGINS\`) | PE32 (`x86`) | `True / True / False / True` | `3` RTTI vftables; RSDS Rust PDB path (`...\frontend.pdb`, GUID `27B283E8-9E02-44CF-8C7B-7148121D4276`, age `71`). |
| `AINPC\bridge.py`, `llm_brain.py`, `.pyc` | Python `3.12` | N/A | AST & bytecode CFG extraction: `24` code objects in `bridge.py` (`bridge.cpython-312.pyc` parity confirmed), `16` in `llm_brain.py`; `0` embedded ML weights in native binaries. |

- **Signature Directory Audits (`sig-audit`):**
  - Root (`27` files matched): `1` `trusted_embedded` (`bass.dll`), `10` `unsigned`, `16` `unsupported_format` (`.ini`/data/non-PE assets), `0` `tampered`, `0` `untrusted_or_expired`, `0` `scan_errors`.
  - `<TARGET_ROOT>\cleo` (`6` root script/plugin entries audited): `4` `unsigned`, `2` `unsupported_format`, `0` `untrusted_or_expired`, `0` `scan_errors`.
- **Host Compatibility & DirectX Context:** Registry AppCompat surfaced an active HKCU `HIGHDPIAWARE` shim targeting `<TARGET_ROOT>\legacy_host_x86.exe`; GPU adapter reported as `Intel(R) UHD Graphics 620`.

### 2.2 Multi-Dump Crash Root-Cause Correlation (`5/5` Genuine MiniDumps)
All 5 local WER-recorded crashes (`3` `APPCRASH` + `2` `BEX` entries) resolved deterministically against local `.dmp` captures:

| Dump (`<LOCALAPPDATA>\CrashDumps\`) | Exception / Operation | Fault Site | Root Cause & Confidence | Key Attributable Detail |
| :--- | :--- | :--- | :--- | :--- |
| `legacy_host_x86.exe.12224.dmp` | `0xC0000005` (`READ`) | `d3d9.dll+0x5FEDB` (`0x72fbfedb`) | `DETERMINISTIC_NULL_POINTER_DEREFERENCE` (`CONFIDENT_DETERMINISTIC`) | Null register `EAX=0`, `target_address=0xC` (`NULL_PAGE_TRAP`). |
| `legacy_host_x86.exe.2200.dmp` | `0xC0000005` (`READ`) | `d3d9.dll+0x5FEDB` (`0x72fbfedb`) | `DETERMINISTIC_NULL_POINTER_DEREFERENCE` (`CONFIDENT_DETERMINISTIC`) | Duplicate D3D9 device/surface null pointer dereference at `[eax+0xc]`. |
| `legacy_host_x86.exe.12992.dmp` | `0xC0000005` (`READ`) | `legacy_host_x86.exe+0x245F40` (`0x645f40`) | `DETERMINISTIC_NULL_POINTER_DEREFERENCE` (`CONFIDENT_DETERMINISTIC`) | Null register `EAX=0`, `target_address=0x474`. |
| `legacy_host_x86.exe.15592.dmp` | `0xC0000005` (`EXECUTE`, DEP/NX) | `0x0` (`UNKNOWN_MODULE`) | `NULL_FUNCTION_POINTER_CALL` (`HIGH_HEURISTIC`) | `EIP=0x0`; stack-walk identifies `probable_caller: legacy_host_x86.exe+0x69EF7` (`0x469EF7`). |
| `legacy_host_x86.exe.15656.dmp` | `0xC0000005` (`EXECUTE`, DEP/NX) | `0x0` (`UNKNOWN_MODULE`) | `NULL_FUNCTION_POINTER_CALL` (`HIGH_HEURISTIC`) | `EIP=0x0`; identical `probable_caller: legacy_host_x86.exe+0x69EF7` (`0x469EF7`). |

### 2.3 MCP, Live Process Telemetry, Ghidra Bridge & P-Code Verification
- **MCP Surface:** `initialize` (`protocolVersion=2025-06-18` / `2026-07-28` supported), `server/discover` OK, `4` resources OK, `5` prompts OK, `tools/list` paginated cleanly (`[25, 25, 1] = 51` tools), all `16` host diagnostic tools operational after fixing `bintra_win_catalog_cmd` (`command_id="list"` -> `10` registered catalog commands).
- **Live Non-GUI Companion Telemetry:** `proc-profile` (`STABLE_EQUILIBRIUM`, `user_handles=1`, `gdi_handles=0`), `vad-inspect` (`MEM_COMMIT`/`PAGE_READWRITE`/`HEAP`), `mem-scan` (`exact` first scan + stateful `unchanged` next scan -> `surviving_count=5`), `pointer-scan` (`10` paths), `struct-dissect` (`12` fields + C struct), `cpython_memory_forensics` (`pydict` `ma_used=3` / `3` keys parsed, `pyascii` `"AINPC_RUNTIME_STATUS_ACTIVE"`, `pylong` `0x13572468abcd`), `etw-capture` (`WEVTAPI_EVENT_LOG_POLLING` + `36` `toolhelp_module_baseline` events -> `DYNAMIC_MODULE_LOAD_OBSERVED`).
- **Ghidra & High P-Code Ecosystem:** `ghidra_live_bridge` bound cleanly on `127.0.0.1:41729`, queued Crash RCA / VAD / ETW annotations, and stopped cleanly; `bintra ghidra-plan`, `bintra_match_pcode`, `bintra_deobfuscate_pcode` (detected `ALGEBRAIC_ZERO_CBRANCH_OPAQUE`), and `GhidraExportStore` SQLite ingestion (`2` functions, `8` P-Code ops, `1` sensitive API match) passed end-to-end.
- **Safety Kernel Validation:** Direct in-place `bintra_patch_binary` failed closed (`TARGET_WRITE_FORBIDDEN`); workspace-isolated patch succeeded with `checksum_recalculated=true`, `hashes_differ=true`, and `pain_score=0.0`, after which temporary workspace copies were cleaned up.

---

## 3. Generic Defects Uncovered and Fixed

All fixes were implemented generically across `src/` with zero target-specific workarounds and verified via regression tests in `tests/test_field_audit_regressions.py`:

| Component | Generic Defect Uncovered | General Resolution Applied |
| :--- | :--- | :--- |
| `src/cli.py` | `ghidra-headless` registered a phantom positional `command` arg while parsing `sys.argv[2:]`, blocking every invocation. | Removed phantom `command` arg; set explicit `prog="bintra ghidra-headless"`. |
| `src/ghidra_headless_runner.py` | `analyzeHeadless.bat` blocked/failed on missing JDK interactive prompt without surfacing LaunchSupport error markers. | Passed `stdin=subprocess.DEVNULL` and added JDK/LaunchSupport markers to `SCRIPT_ERROR_MARKERS`. |
| `src/windows_intelligence/runtime_telemetry/cpython_memory_forensics.py` | `inspect_live_process` rejected `_read_memory_internal` results whenever `status != "ok"`, failing on real live PIDs whose reader returns `"success"` / `"partial"`. | Accepted `("ok", "success", "partial")` for primary object and `PyDictKeysObject` reads. |
| `src/pe_deep_forensics.py` | `diff_pe_binaries` read wrong section/export schema keys (`raw_data_size`, `entropy`, `exports.names`), zeroing real size/entropy/export diffs and overwriting duplicate section names; `.pdata` returned no `applicable` flag on PE32. | Read `raw_size` & `shannon_entropy` (with fallbacks), extracted `exports["functions"]`, disambiguated duplicate section names (`#2`), and clarified `applicable`/`total_runtime_functions` on PE32. |
| `src/windows_intelligence/signature_intelligence.py` | `0x800B0003` (`TRUST_E_SUBJECT_FORM_UNKNOWN`) fell into `VERIFICATION_ERROR` and incremented `untrusted_or_expired` in `audit_directory`. | Mapped `0x800B0003` -> `NOT_AUTHENTICODE_FORMAT` (`NON_AUTHENTICODE_FILE_FORMAT`) and added `unsupported_format` metric bucket. |
| `src/windows_intelligence/dependency_resolver.py` | `audit_dependencies` ignored PE `DelayImportDescriptor` (`delay_imports`), missing `/DELAYLOAD` DLLs like `d3d9.dll`. | Extracted shared `_audit_module_map` helper to resolve both static IAT imports and delay-load imports independently. |
| `src/windows_intelligence/evidence_engine/graph_model.py` & `src/analysis_orchestrator.py` | Fused `PE_BINARY.entropy` and `CRASH_EVENT.fault_address` emitted `null` against standard `BinaryFormatInspector` / `CrashRootCauseAnalyzer` schemas. | Added weighted section entropy fallback (`shannon_entropy` weighted by `raw_size`) and populated `fault_address`, `fault_module`, `fault_rva`, `fault_virtual_address`. |
| `src/windows_intelligence/runtime_telemetry/crash_rca_engine.py` | `NULL_FUNCTION_POINTER_CALL` / `INVALID_CONTROL_TRANSFER` remediation output cited `UNKNOWN_MODULE+0x0` even when stack-walk recovered `probable_caller`. | Passed `probable_caller` into `_generate_remediation` to guide engineers directly to `<caller_module>+<caller_rva>`. |
| `src/binary_neural_engine.py` | `detect_control_flow_flattening` performed unaligned byte scans, triggering false positives on CRT/MSVC switches, embedded call displacements, and boolean `{0, 1}` return idioms. | Used Capstone instruction-boundary sweep (`HAS_CAPSTONE`), enforced `0xCC\xCC` function-segment isolation, required `>= 3` clustered assignments, and filtered trivial volatile-register accumulator/boolean idioms. |
| `src/mcp_server.py` | `bintra_win_catalog_cmd` rejected `"command_id": "list"`, breaking parity with CLI `win-cmd list`. | Handled `"list"` / `"__list__"` to return registered `CommandCatalog` definitions. |
| `src/mcp_server.py` & `src/cli.py` | Several `GhidraExportStore.from_path` call sites left SQLite connections unclosed, locking `.db` files on Windows (`WinError 32`). | Wrapped `GhidraExportStore.from_path(...)` callers in `with ... as store:` context blocks. |

---

## 4. Honest Observed Boundaries (Non-Fabricated Limits)

- **Headless Ghidra Execution Blocked by Host JDK Version:** Local Ghidra `12.1.4` refused to run against host `JDK 17.0.17` (`JDK 21+ (64-bit) could not be found`); Bintra now detects this cleanly without hanging (`returncode=1, script_error=True`), while live decompilation of target PEs requires installing JDK 21+.
- **Embedded Neural Tensor Auditing:** Legacy PE32 binaries in `<TARGET_ROOT>` contain `0` embedded ML weights (`Safetensors`/`ONNX`/`GGUF`/`TFLite`), so `wsp-audit` / `patch-weights` do not apply to these native executables.
- **Standard-User Privilege Scope:** Under non-elevated execution, `EtwCaptureEngine` properly records `USER_MODE_TELEMETRY` via Toolhelp32 + `WEVTAPI` polling rather than claiming kernel-level real-time ETW events.
