---
name: rea-neural-weight-security
description: Audit embedded neural models and Safetensors weights without execution, detect dormant trojan/backdoor neurons (>4.5σ), compute spectral effective rank, and surgically cure infinite loop attractors using selective column direction subtraction without retraining.
metadata:
  framework: rea-neural
  version: "7.4.0"
  tier: neural-weight-space
---

# REA-Neural: Weight Security & Safetensors Surgery Skill

Use this skill whenever an AI coding agent or user needs to audit embedded AI models, inspect `.safetensors` weight matrices, detect hidden backdoors/trojans, or fix pathological looping without running costly backpropagation or training pipelines.

---

## 1. When to Activate This Skill

Activate this skill when the user asks:
- *"Scan this Windows application (`.exe`) to see if it embeds an AI model (ONNX, DirectML, GGUF, Safetensors)."*
- *"Audit this `.safetensors` file without running forward passes."*
- *"Check if this neural model has backdoors or dormant trojan trigger neurons."*
- *"The model is stuck generating repetitive infinite text / reasoning loops. Can we fix the weights?"*
- *"Compute the spectral effective rank or cross-layer composition of these attention matrices."*
- *"Apply selective column direction subtraction to eliminate a loop attractor."*

---

## 2. Theoretical Grounding (MIT CSAIL Weight-Space Programming)

This skill operationalizes recent breakthroughs from MIT CSAIL (*"Sparks of Weight-Space Programming"*, Takehi, Teoh, Zhang, Khattab, 2026):

1. **Zero-Execution Weight Auditing:**
   Weights can be inspected directly as spatial representations:
   - **First-Layer Receptive Fields:** Expose the model's perceptual focus directly from weight norms.
   - **Spectral Effective Rank:** Evaluates singular value entropy ($H(\mathbf{p})$) to measure model expressive capacity without tokens.
   - **Backdoor / Trojan Outliers:** Maliciously grafted trigger neurons exhibit extreme norm z-scores ($> 4.5\sigma$) relative to the background weight distribution.
2. **Selective Column Direction Subtraction:**
   Pathological loop attractors (repetitive loops) concentrate along specific singular projection directions. Rather than fine-tuning with gradients, REA-Neural subtracts the loop vector exclusively from the top-$K$ most active columns (e.g., 64 columns; $\approx 0.016\%$ of weights), curing the loop while leaving $98.4\%$ of parameters untouched.

---

## 3. Operational Workflow

```mermaid
flowchart TD
    Request[User Request] --> Mode{Task Modality?}
    
    Mode -->|Audit Software for AI Assets| ScanFlow[Scan Native Windows PE]
    Mode -->|Audit Model File for Backdoors| AuditFlow[Zero-Execution WSP Audit]
    Mode -->|Fix Repetitive Generation Loop| SurgeryFlow[Selective Column Surgery]
    
    subgraph ScanFlow[PE Scanning]
        S1[Call rea_scan_hybrid on target.exe]
        S2[Locate Embedded ONNX/DirectML/Safetensors in .rsrc or .rodata]
        S3[Report Model Architecture & Tensor Geometries]
    end
    
    subgraph AuditFlow[Backdoor & Spectral Audit]
        A1[Call rea_wsp_audit on model.safetensors]
        A2[Compute Spectral Effective Rank & Cross-Layer Induction]
        A3[Scan for Outlier Trigger Neurons > 4.5 sigma]
        A4[Emit Clean / Compromised Diagnostic]
    end
    
    subgraph SurgeryFlow[Column Direction Subtraction]
        G1[Identify Pathological Attractor Tensor e.g. mlp.down_proj]
        G2[Call rea_patch_weights with column_direction_subtract]
        G3[Write Patched Safetensors to Dedicated Workspace]
        G4[Verify Frobenius Perturbation Delta < epsilon]
    end
```

---

## 4. Tool Invocations: MCP vs CLI

### Task A: Scanning an Executable for Embedded AI Models

**MCP Tool:**
```json
{
  "name": "rea_scan_hybrid",
  "arguments": {
    "file_path": "C:\\path\\to\\application.exe"
  }
}
```

**CLI Command:**
```powershell
rea-neural scan-hybrid --file "C:\path\to\application.exe"
```

---

### Task B: Zero-Evaluation Backdoor & Spectral Audit

**MCP Tool:**
```json
{
  "name": "rea_wsp_audit",
  "arguments": {
    "model_path": "C:\\path\\to\\model.safetensors"
  }
}
```

**CLI Command:**
```powershell
rea-neural wsp-audit --model "C:\path\to\model.safetensors"
```

**Key Diagnostic Metrics:**
- `effective_rank`: Spectral entropy measure of weight diversity.
- `dormant_backdoors_detected`: Boolean flag indicating if outlier neurons ($> 4.5\sigma$) exist.
- `amenability`: Assesses whether the model is amenable to weight surgery without degradation.

---

### Task C: Curing Pathological Loops via Column Direction Subtraction

> [!IMPORTANT]
> **Workspace Confinement:** Always write the patched safetensors model to a dedicated workspace folder outside the source directory!

**MCP Tool:**
```json
{
  "name": "rea_patch_weights",
  "arguments": {
    "source_path": "C:\\models\\llama_base.safetensors",
    "output_path": "C:\\workspace\\llama_cured.safetensors",
    "tensor_name": "model.layers.15.mlp.down_proj.weight",
    "num_columns": 64
  }
}
```

**CLI Command:**
```powershell
rea-neural patch-weights `
  --source "C:\models\llama_base.safetensors" `
  --output ".\workspace\llama_cured.safetensors" `
  --tensor "model.layers.15.mlp.down_proj.weight" `
  --operation column_direction_subtract `
  --num-columns 64
```

**Output Telemetry:**
- `sparsity_ratio`: Percentage of parameters altered (typically $< 0.02\%$).
- `frobenius_norm_delta`: $\|\Delta W\|_F$ showing minimal perturbation.
- `is_loop_cured`: True, confirming the attractor direction was eliminated.
