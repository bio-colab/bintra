# Neural Circuit Decompilation Methodology

## 1. Concept: Decompiling Weights to Logic

In classical reverse engineering, Ghidra or IDA Pro translates assembly opcodes into High-Pcode or C pseudocode:
```
push ebp; mov ebp, esp; cmp eax, 0 -> if (x == 0) return;
```

In `Bintra`, the **Circuit Decompiler** translates continuous weight matrices into symbolic mechanistic logic:
```
W_QK[Layer 14, Head 3] + W_OV[Layer 14, Head 3] -> 
"Induction circuit: Copies token at t - k when preceded by token at t - (k + 1)"
```

---

## 2. Canonical Circuit Taxonomy

### 2.1 Induction Heads
- **Behavior:** Look back at the token sequence, find where the current token appeared previously, and attend to the token that came immediately after it.
- **Weight Signature:** High positive trace for $W_{QK}$ on shifted bigram embeddings; identity-like alignment in $W_{OV}$ (or elevated singular dominance $\sigma_0/\sigma_1 > 1.8$ on attention projections).
- **Decompiled Output (`CircuitDecompiler.decompile_attention_head`):**
  ```json
  {
    "layer_index": 14,
    "head_index": 3,
    "circuit_type": "attention_head",
    "circuit_classification": "INDUCTION_COPY_HEAD",
    "is_anomaly": false,
    "classification_confidence": "HEURISTIC_SPECTRAL_RATIO",
    "heuristic_note": "Classified from a single spectral singular value ratio (s0/s1); small or rank-deficient test tensors can trigger elevated dominance without runtime looping.",
    "dominance_ratio": 2.45,
    "pseudocode": "circuit Layer_14_Head_3 { ... }"
  }
  ```
  *(For two-layer composition analysis, `CrossLayerCircuitAnalyzer.analyze_cross_layer_induction` emits `num_heads_analyzed`, `copying_heads_detected`, `copying_head_density`, `inferred_corpus_type`, and `head_composition_table`.)*

### 2.2 Previous-Token Heads
- **Behavior:** Attend unconditionally to the immediate previous token ($t-1$).
- **Weight Signature:** Diagonal-heavy positional bias, uniform output projection.

### 2.3 Inhibitory / Suppression Heads
- **Behavior:** Suppress tokens that have already been generated to prevent verbatim looping.
- **Weight Signature:** Negative singular modes on the diagonal of $W_{OV}$; projects anti-correlated vectors to the residual stream.

### 2.4 Knowledge Retrieval Slots (MLP Key-Value Memories)
- In MLP layers ($W_{gate}, W_{up}, W_{down}$):
  $$\text{MLP}(x) = (x W_{gate} \odot \sigma(x W_{up})) W_{down}$$
  Each row of $W_{gate}$ acts as a "key" detecting a specific concept, and the corresponding column of $W_{down}$ acts as the "value" injected into the residual stream.
