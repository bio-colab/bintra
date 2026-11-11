# PoC `BINTRA-OBS-008`: Static ↔ Dynamic Correlation & Evidence Graph

- **Axis:** A4 — Static-Dynamic Correlation
- **Verdict:** `PASS` (exact live-VA ↔ RVA ↔ VAD section ↔ PE file offset ↔ 16-byte machine-code parity verified across both first-party `obs.dll` and third-party `droidcam-obs.dll`, plus 47-node Causality Evidence Graph synthesis)
- **Primary Classification:** None (minor test helper limitation: `dbghelp!SymFromAddrW` Level 2 helper returned `null` while Level 1 Blind PE export + live byte comparison gave exact proof)
- **Raw Evidence:** [`obs_008.json`](../evidence/obs_008.json)

## 1. Reproducible Command
```powershell
python benchmarks/obs_studio/scripts/run_runtime_pocs.py
```

## 2. Empirical Byte-Exact Correlation Results

| Module | Exported Symbol | Live Module Base | RVA | Live VA | PE File Offset (`BinaryFormatInspector`) | Live VAD Class (`VirtualMemoryInspector`) | Live RAM vs Disk 16-Byte Match |
| --- | --- | --- | --- | --- | --- | --- | :---: |
| `obs.dll` | `obs_get_version` | `0x7ff8c52c0000` | `0x74ab0` | `0x7ff8c5334ab0` | `0x73eb0` | `COMMITTED` / `IMAGE_TEXT` (`.text`) | **`true`** (`b802000120c3...` -> `0x20010002` = OBS `32.1.2`) |
| `obs.dll` | `obs_startup` | `0x7ff8c52c0000` | `0x74070` | `0x7ff8c5334070` | `0x73470` | `COMMITTED` / `IMAGE_TEXT` (`.text`) | **`true`** (`48896c24104889742418574883ec2048`) |
| `droidcam-obs.dll` | `obs_module_ver` | `0x7ff8af060000` | `0x21df` | `0x7ff8af0621df` | `0x15df` | `COMMITTED` / `IMAGE_TEXT` (`.text`) | **`true`** (`e91c651000e96f351700e926891600e9`) |

## 3. Causality Evidence Graph Synthesis
- `CausalitySynthesizer.build_evidence_graph(".../obs64.exe")` produced a **`47`-node, `42`-edge** directed Evidence Graph, and `synthesize_dossier` produced all 21 diagnostic sections (`binary_mapping`, `dependency_health`, `causal_chain`, `evidence_graph`, `mermaid_diagram`, `safety_kernel_audit`, etc.).
