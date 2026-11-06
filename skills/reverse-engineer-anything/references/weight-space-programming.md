# Weight-Space Programming (WSP) Reference Specification

Based on MIT CSAIL research (*"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, Takehi, Teoh, Zhang, Khattab, 2026).

---

## 1. Paradigm Shift: The Parameter Space as Code

Traditional machine learning relies on loss functions and iterative numerical optimization (SGD, Adam, AdamW, Muon) to find local minima in a high-dimensional continuous space. The resulting parameters are treated as uninterpretable floating-point matrices.

**Weight-Space Programming (WSP)** establishes that:
1. Neural network weights contain organized, structured geometric representations that frontier reasoning models can parse natively.
2. An autonomous agent can navigate weight matrices, identify symbolic logic, and modify parameters directly without gradient descent.
3. Common model bugs (such as catastrophic reasoning loops, infinite token cycling, or sycophancy) often reside in isolated, low-rank subspaces ($<0.05\%$ of total parameters).

---

## 2. Mathematical Formalization

### 2.1 The Forward Pass as Circuit Composition
For a standard Transformer layer $l$:
$$x^{(l+1)} = x^{(l)} + \sum_{h=1}^H \text{Attn}^{(l, h)}(x^{(l)}) + \text{MLP}^{(l)}(x^{(l)})$$

Where each attention head $h$ comprises:
$$W_Q^{(l,h)}, W_K^{(l,h)} \in \mathbb{R}^{d_{head} \times d_{model}}, \quad W_V^{(l,h)}, W_O^{(l,h)} \in \mathbb{R}^{d_{model} \times d_{head}}$$

The **QK-Circuit** (information routing):
$$A^{(l,h)} = \text{softmax}\left(\frac{(x W_Q)(x W_K)^T}{\sqrt{d_{head}}}\right)$$

The **OV-Circuit** (information transformation):
$$\text{Output}^{(l,h)} = (A^{(l,h)} x W_V) W_O$$

### 2.2 Low-Rank Subspace Extraction
Directly passing $d_{model} \times d_{model}$ (e.g. $4096 \times 4096 = 16.7\text{M}$ parameters per projection) into an LLM context is wasteful. We apply Truncated SVD:
$$W \approx U_k \Sigma_k V_k^T$$
Where:
- $\Sigma_k = \text{diag}(\sigma_1, \dots, \sigma_k)$ captures the principal energetic modes.
- $U_k$ indicates the output semantic directions.
- $V_k$ indicates the input activation trigger directions.

An LLM can examine the top-16 singular values $\sigma_i$ and the sparsified coordinate peaks of $u_i, v_i$ to recognize the operational mode of the weight matrix.

---

## 3. The 0.016% Intervention Case Study (Takehi et al., 2026)

### 3.1 The Failure Mode
`Qwen3.5-0.8B` suffered from persistent degenerative thinking loops in mathematical reasoning: when computing multi-step arithmetic, intermediate attention heads reinforced previous reasoning tokens in an infinite feedback loop, causing token generation cutoffs and benchmark degradation (7.9% on MATH-500).

### 3.2 The WSP Solution
1. **Diagnosis:** By inspecting the attention output projections ($W_O$) of layers 12 to 16, Astra/GPT-6 identified a dominant eigenvalue in head 3 of layer 14 that exhibited positive feedback self-reinforcement with zero decay.
2. **Intervention:** Astra synthesized a Rank-1 nullifying modification:
   $$\Delta W_O^{(14, 3)} = -\alpha \cdot u_{loop} v_{loop}^T$$
   Modifying only 131,072 parameters out of 800 million (0.016% of the network).
3. **Outcome:** Without training, MATH-500 accuracy surged to 48.1%, and IFEval instruction compliance improved threefold, proving that removing latent pathological attractors unlocks existing pre-trained capabilities.
