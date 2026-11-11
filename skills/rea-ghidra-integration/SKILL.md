---
name: rea-ghidra-integration
description: Connect REA-Neural to Ghidra using High P-Code vectorization, headless batch deobfuscation, and the authenticated localhost JSON-RPC 2.0 Live Bridge daemon (with queue+poll transaction lifecycle, RVA/VA awareness, and mediated markers).
metadata:
  framework: rea-neural
  version: "7.4.0"
  tier: ghidra-bridge
---

# REA-Neural: Ghidra High P-Code & Live Bridge Skill

Use this skill when exporting or matching Ghidra High P-Code IR vectors, pruning P-Code algebraic opaque predicates, orchestrating headless Ghidra scripts, or running the localhost JSON-RPC 2.0 live bridge between REA-Neural and an open Ghidra session.

Architecture details: see [`ghidra-bridge-status.md`](../reverse-engineer-anything/references/ghidra-bridge-status.md).

---

## 1. Execution & Consistency Contract (Read Carefully)

1. **Queue + Polling Transaction Model (Not Instant Synchronous Commit):**
   - `inject_*` RPC calls and `rea_ghidra_live_bridge` enqueue commands into an in-memory bounded FIFO (`2000` commands max; overflow counted in `queue_overflow_count`) and return `status: "queued"`.
   - Changes inside Ghidra's Program Database (`setPlateComment`, `Bookmarks`, `setName`, `DataTypeManager` structs) are committed only when an active Ghidra script (`ghidra_scripts/ReaLiveBridgeService.py`) polls `ghidra.poll_commands` (~1.0s loop) inside `currentProgram.startTransaction(...)`.
   - Always check `ghidra_client_connected` via `action: "status"` before claiming annotations were applied inside Ghidra.
2. **Multithreaded Localhost Transport & Bounds:**
   - The server (`GhidraLiveBridgeServer`) binds `127.0.0.1` (`ThreadingMixIn` HTTPServer, `5.0s` socket timeout, `2 MiB` max JSON body returning HTTP `413` on overshoot).
   - Every RPC method except unauthenticated health `ping` requires `Authorization: Bearer <token>` or JSON-RPC auth token matching (missing/wrong token returns `-32001`).
3. **Mediated Discovery Marker (`cap.tempdir.marker.write`):**
   - Workspace marker `.rea_bridge.json` writes through workspace confinement; the convenience system temp marker is strictly mediated by `Capability.TEMPDIR_MARKER_WRITE`. Pass `--no-temp-marker` (CLI) or `"publish_temp_marker": false` (MCP `start`) to keep discovery strictly inside the workspace.
4. **RVA vs Absolute Runtime VA Resolution:**
   - Live telemetry addresses (`inject_struct`, `inject_pointers`) are emitted with `"address_space": "va"`, while Crash RCA faults carry `"address_space": "rva"`. `ReaLiveBridgeService._resolve_addr` honors this tag explicitly to avoid misinterpreting low heap addresses (`< image_base`) as RVAs.

---

## 2. MCP Tools & Unified CLI Workflows

### Modality A: High P-Code Semantic IR (Offline / Cross-Arch)

| Task | MCP Tool | CLI Command (`rea-neural`) |
|:---|:---|:---|
| **P-Code Semantic Match** | `rea_match_pcode` | `match-pcode --func1 <f1.json> --func2 <f2.json>` |
| **P-Code Deobfuscation** | `rea_deobfuscate_pcode` | `deobfuscate-pcode --file <pcode.json>` |
| **Batch Plan Generation** | `rea_ghidra_analyze` | `ghidra-analyze --input <export.json> --output <plan.json>` |
| **Headless Analyzer** | `rea_ghidra_headless` | `ghidra-headless --binary <target.exe> [--apply]` |

> **PowerShell Rule:** Never pass large P-Code JSON arrays inline on PowerShell command lines; write them to workspace files and use `--func1` / `--file` paths.

### Modality B: Live Bidirectional Bridge (`rea_ghidra_live_bridge` / `ghidra-bridge`)

**MCP Actions (`action` enum):** `start`, `status`, `inject_crash_rca`, `inject_vad`, `inject_etw`, `inject_struct`, `inject_pointers`, `stop`.

```json
{
  "name": "rea_ghidra_live_bridge",
  "arguments": {
    "action": "start",
    "port": 41718,
    "publish_temp_marker": false
  }
}
```

**CLI Management:**
```powershell
# Start foreground or background daemon (workspace-only marker):
rea-neural ghidra-bridge --start --port 41718 --no-temp-marker
rea-neural ghidra-bridge --daemon --port 41718 --no-temp-marker

# Check client status & queue depth:
rea-neural ghidra-bridge --status --port 41718

# Queue live diagnostics for connected Ghidra session:
rea-neural ghidra-bridge --annotate-crash .\crash.dmp
rea-neural ghidra-bridge --annotate-vad 1234
rea-neural ghidra-bridge --annotate-struct 1234 --addr 0x7FF71000 --size 128
rea-neural ghidra-bridge --annotate-pointers 1234 --addr 0x7FF71000 --depth 2

# Stop cleanly:
rea-neural ghidra-bridge --stop --port 41718
```
