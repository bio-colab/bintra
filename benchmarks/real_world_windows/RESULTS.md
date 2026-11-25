# Real-World Campaign Results (Windows 10 Pro 19045, Python 3.12, non-elevated)

Final run: **279 pass / 0 fail / 0 skip** across L1–L8 in 289 s
(L1 146, L2 32, L3 42, L4 24, L5 14, L6 18, L7 2 corpora = 126 malformed PEs x 8 tools, L8 150 System32 binaries).

Samples: notepad (x64/x86), kernel32, ntfs.sys, msvcp140 (RTTI), csc.exe (.NET), git-lfs (Go), git (MinGW),
Inno Setup uninstaller (overlay), Blender (large), VLC (app-local DLLs), GTA San Andreas (legacy x86),
an Arabic/space path copy, 10 real crash dumps (gta_sa x5, powershell, wordpad, HillClimbRacing, Antigravity, patch.exe),
live helper processes (value changer, leaker, file locker, WOW64 PING).

## Defects found and fixed (all generic)

| Area | Defect | Fix |
|---|---|---|
| crash-rca | Disassembled the user `--binary` even when the fault was in another module (ntdll, msftedit) and blamed a NULL register whose value could not produce the fault address | Code bytes from dump memory first, else the faulting module's own image verified by TimeDateStamp/SizeOfImage; blame only when `base+index*scale+disp == fault address`, else `OPERAND_CONTEXT_MISMATCH`; proper operand parser |
| crash-rca | Execute-at-NULL faults had no actionable output | `NULL_FUNCTION_POINTER_CALL` / `INVALID_CONTROL_TRANSFER` with top-of-stack `probable_caller` (e.g. `gta_sa.exe+0x69EF7`) |
| crash-rca / minidump | Stowed WinRT, abort, fast-fail, heap corruption etc. were `UNKNOWN_EXCEPTION` | Named codes + root-cause/remediation table, fast-fail sub-code decoding; captured dump memory used for spatial classification |
| CLI | Missing file exited 0 (`inspect`, `slack-audit`); `sense` fabricated a full report for a non-existent file | Central exit-code contract (`status:error` / `FILE_NOT_FOUND` → rc 1); sensory cortex raises `FileNotFoundError` |
| CLI | Documented `--output .\workspace\...` and `--session-file .\workspace\...` failed (`WRITE_OUTSIDE_WORKSPACE`) | CLI derives workspace from an explicit output path (MCP unchanged); unsafe roots and target trees still refused |
| mem-scan | First/Next scans could not span CLI invocations | Full session state persisted in the session file (PID-reuse check kept) |
| proc-modules | Silently capped at 128 processes / 128 modules → missed hosts | Uncapped scan + truncation flag |
| proc-info | Dead PID returned `success` with invented fields; 5 s latency | Clean error; snapshot without resolving every process path |
| wsp-audit | Planted trojan column neuron (down_proj) invisible | Column-axis robust z-scores (`suspect_input_channel_neurons`); 0 false positives on 300 clean matrices |
| slack-audit | `struct.error` on a header truncated mid-table; truncated headers reported as CLEAN | Bounds check + `TRUNCATED_PE_HEADERS` verdict |
| Audit log | Every command re-verified the whole journal (71k records, 2.5 s, growing forever) and re-read its tail on each decision | Segment sealing with a continuous hash chain; tail read skipped when the file is unchanged |
| PE parser | Byte-at-a-time string reads | Bounded single reads (identical output on 64 binaries, 3x faster) |
| diagnose | Host telemetry computed twice | Reused between dossier and graph (identical graphs) |
| Messages / docs | Target-dir error named the output folder; `triage` keys wrong in AGENTS.md | Clear message naming both folders; docs updated |

Latency: CLI floor 2.6 s → 0.48 s; `resolve-deps` 7.1 → 2.5 s; `diagnose` 18.8 → 4.3 s; unit suite 254 → 136 s.

## Known limitation (not changed)
`wsp-audit` row-axis z-scores flag heavy-tailed (Student-t, df=3) random matrices as backdoors; calibration needs real model weights.
