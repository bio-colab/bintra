# Neural Circuit Decompilation Methodology

## 1. Concept: Decompiling Weights to Logic

In classical reverse engineering, Ghidra or IDA Pro translates assembly opcodes into High-Pcode or C pseudocode:
```
push ebp; mov ebp, esp; cmp eax, 0 -> if (x == 0) return;
```

In `REA-Neural`, the **Circuit Decompiler** translates continuous weight matrices into symbolic mechanistic logic:
```
W_QK[Layer 14, Head 3] + W_OV[Layer 14, Head 3] -> 
"Induction circuit: Copies token at t - k when preceded by token at t - (k + 1)"
```

---

## 2. Canonical Circuit Taxonomy

### 2.1 Induction Heads
- **Behavior:** Look back at the token sequence, find where the current token appeared previously, and attend to the token that came immediately after it.
- **Weight Signature:** High positive trace for $W_{QK}$ on shifted bigram embeddings; identity-like alignment in $W_{OV}$.
- **Decompiled Output:**
  ```json
  {
    "circuit_type": "induction_head",
    "layer": 14,
    "head": 3,
    "confidence": 0.94,
    "function": "In-context pattern continuation and copy mechanism",
    "evidence_ref": "ev_svd_l14h3_01"
  }
  ```

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
