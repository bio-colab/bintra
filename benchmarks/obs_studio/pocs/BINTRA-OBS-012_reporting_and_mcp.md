# PoC `BINTRA-OBS-012`: Reporting Contracts, Schema Enforcement & Live MCP Server

- **Axis:** A6 — Reporting & MCP Server
- **Verdict:** `PASS`
- **Primary Classification:** None
- **Raw Evidence:** [`obs_012.json`](../evidence/obs_012.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_guard_and_mcp_pocs.py
```

## 2. Live `stdio` JSON-RPC 2.0 Verification (`src/mcp_server.py`)
1. **Protocol Handshake & Notification Silence:**
   - `initialize` returned `protocolVersion: "2024-11-05"` and `serverInfo: {"name": "bintra", "version": "1.0.0"}`.
   - `notifications/initialized` produced zero spurious output lines; subsequent `ping` preserved `id: 2`.
2. **Tool Registry & Batch/Error Semantics:**
   - `tools/list` returned **`34` tools** with JSON input schemas.
   - 2-item batch request returned **`2` matching responses**; empty batch `[]` returned `-32600` (`Invalid Request: empty batch`); malformed JSON returned `-32700` (`Parse error`).
3. **Real OBS `tools/call` Invocations (`isError: false`):**
   - `bintra_inspect_binary` on `obs.dll` -> full PE/mitigation/section/import/export envelope.
   - `bintra_resolve_dependencies` on `obs.dll` -> `"status": "success"`, `"verdict": "HEALTHY"`.
   - `bintra_sensory_audit` on `obs-frontend-api.dll` -> all 10 senses returned.
   - `bintra_evidence_graph` on `obs64.exe` -> `"status": "success"` with graph & Mermaid output.
4. **Security & Schema Envelopes (`isError: true`):**
   - `bintra_patch_binary` attempting `"workspace_dir": "%ProgramFiles%\obs-studio\bin\64bit"` returned `isError: true` with `"UNTRUSTED_WORKSPACE_OVERRIDE"`.
   - `bintra_vad_inspect` with `pid: "not_an_int"` returned `isError: true` (`"Invalid type for parameter 'pid'..."`).
   - `nonexistent_tool_xyz` returned `isError: true` (`"UNREGISTERED_TOOL"`).
