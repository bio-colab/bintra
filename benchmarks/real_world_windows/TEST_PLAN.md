# Real-World Windows Test Matrix

A reproducible, host-driven test campaign that exercises Bintra against **real
binaries, real crash dumps, real live processes and real MCP sessions** on a
Windows 10/11 workstation. Unlike the unit suite (synthetic fixtures), every
case here touches genuine artifacts found on the host. Cases whose sample is
absent are reported as `skipped`, never as failures.

Run it:

```powershell
python benchmarks\real_world_windows\run_matrix.py            # all levels
python benchmarks\real_world_windows\run_matrix.py --levels L1,L4
python benchmarks\real_world_windows\run_matrix.py --extra-sample "D:\Games\game.exe" --extra-dump "C:\dumps\game.dmp"
```

Outputs go to `workspace/real_world/` (git-ignored): `results.json` and
`SUMMARY.md`.

## Pass criteria (applied to every case)

1. Exit code is the expected one (normally `0`; negative/safety cases expect a
   controlled non-zero exit).
2. `stdout` is exactly one valid JSON document when JSON output is requested
   (no banners, no trailing "Unknown command", no mixed Markdown).
3. No Python `Traceback` leaks to stdout/stderr.
4. JSON `status` is not `error` unless the case expects a controlled error.
5. Case-specific semantic assertions (e.g. a 32-bit PE is reported as PE32,
   a leaking process is classified as a leak, a locked file names its locker).
6. Finishes within its timeout.

## Levels

| Level | Theme | What is exercised | Complexity |
|---|---|---|---|
| **L1** | Static PE anatomy | `inspect`, `dump`, `pe-forensics`, `slack-audit`, `sense`, `scan-hybrid`, `deobfuscate`, `sig-verify`, `triage` across x64/x86 EXEs, DLLs, kernel drivers, .NET, Go, MSVC C++ (RTTI), installers with overlays, very large binaries, a legacy 32-bit game, non-PE and empty files, non-ASCII paths | Single file, read-only |
| **L2** | Host intelligence | `win-audit`, `resolve-deps` (x64/x86/app-local DLLs), `hw-audit`, `driver-audit`, `service-audit`, `etw-audit`, `reg-audit`, `wer-inspect`, `dev-match`, `net-conns`, `port-audit`, `hw-tree`, `sys-perf`, `proc-list`, `sig-audit`, `diagnose` | Whole-host, read-only, non-elevated |
| **L3** | Crash forensics | `dmp-inspect` and `crash-rca` on every real minidump on the host (with and without the matching binary), `diagnose --crash-json` fed by `crash-rca` | Multi-artifact correlation |
| **L4** | Live runtime | Controlled helper processes: `vad-inspect`, `mem-scan` First/Next session chain on a known changing value, `pointer-scan`, `dissect-struct`, `proc-info`, `process-mitigations`, `proc-profile` on a deliberately leaking process, `file-locks` on a deliberately locked file, `proc-modules`, `etw-capture` (non-elevated fallback), a WOW64 (32-bit) target | Cross-process, timing-sensitive |
| **L5** | Mutation & safety | `patch-binary` into the workspace and re-inspection; refusal of in-place / target-directory writes; `wsp-audit` + `patch-weights` on a generated safetensors file with a planted outlier neuron; `diff-binaries` (x64 vs x86, two DLL versions); `py-bytecode` on real `.pyc` files | Write paths + safety kernel |
| **L6** | MCP end-to-end | A full stdio JSON-RPC session against `mcp_server.py`: `initialize`, paginated `tools/list`, `resources/*`, `prompts/*`, real `tools/call`s, batches, malformed frames, unknown tools, schema violations | Protocol conformance |
| **L7** | Robustness fuzzing | A corpus of malformed PEs derived from a real binary (truncations, bogus `e_lfanew`, huge section counts, out-of-file raw pointers, corrupted optional/data directories, random byte flips) pushed through every static analyzer in-process; any uncaught exception is a defect | Adversarial input |
| **L8** | Scale | `triage` over a large slice of `System32` binaries in-process, measuring per-file latency and catching crashes/timeouts | Throughput |
