# REA-Neural -- Declared Scope & Boundaries

This document draws an explicit line so the project is not pulled toward the original
agenda of *"Sparks of Weight-Space Programming"* (modifying standalone AI models).

## In scope (what REA-Neural IS)
A reverse-engineering & security framework for **Windows compiled software**
(`.exe`, `.dll`, PE32/PE32+). Where a Windows binary **embeds** neural weights
(ONNX / TFLite / GGUF / Safetensors / DirectML / WinML), REA-Neural may:
- **Read / audit** those embedded weights WITHOUT executing the host binary
  (effective rank, backdoor/trojan spikes, induction structure, amenability verdict,
  SVD subspace inspection).
- **Neutralize** a specific malicious/pathological direction found inside an embedded
  model as part of securing or understanding that binary.

These are legitimate reverse-engineering operations on a shipped artifact.

## Out of scope (what REA-Neural is NOT)
REA-Neural does **not** pursue the WSP paper's own research goals of **improving,
training, merging, or synthesizing standalone AI models**. The following modules are
retained ONLY as archived historical/experimental lineage. They are **not** part of the
supported reverse-engineering surface and must not be presented as product capabilities:

- `WeightSpaceCompiler` (builds a network from scratch; exposed as CLI `synthesize-weights`)
- `CircuitGrafter.transplant_reasoning_subspace` (model merging across shapes)
- `CircuitGrafter.graft_conditional_subcircuit` (grafting new circuits into a model)
- `ForwardPassHarness.run_budgeted_optimization` (training-like weight optimization)

Running `synthesize-weights` emits a scope warning for this reason.

## Why
Respecting the project's identity means keeping its reverse-engineering mission sharp.
Auditing an embedded model to secure a binary is reverse engineering. Building, merging,
or optimizing a standalone model is not -- it is the paper's agenda, and it is out of scope.
