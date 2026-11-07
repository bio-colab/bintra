# Ghidra Integration -- Honest Status

Short version: REA-Neural currently ships a **P-code vectorizer/matcher** and an
**annotation-plan generator**, not a live Ghidra bridge.

## What exists today (`src/ghidra_pcode_vectorizer.py`)
- `PcodeVectorizer` / `PcodeFunctionMatcher` -- real: vectorize a list of P-code ops into a
  64-D unit vector and match two routines by cosine similarity.
- `PcodeDeobfuscator` -- real: detect algebraic opaque predicates in a P-code op list.
- `GhidraAnnotationPlanner` -- builds JSON-RPC **plan dicts** (`set_address_name`,
  `annotate_native_function`, C-struct text). It returns dicts; it does nothing else.

## What does NOT exist yet (despite earlier README wording)
- **No transport.** There is no socket, no TCP client, no "authenticated loopback TCP",
  and no "database lock removal". Nothing connects to Ghidra.
- **No extraction.** There is no script that pulls P-code out of Ghidra. The JSON input to
  `match-pcode` / `deobfuscate-pcode` must currently be produced by hand or by an external tool.
- **Version.** "Ghidra 12.1.4" is an unverified target string.

## What a real integration would need (future work, not in this patch)
A `ghidra_scripts/` directory with a Headless/PyGhidra script that (a) exports High P-code to the
JSON shape these classes expect, and (b) applies the generated annotation plans back into the
Program Database. Only then is "bidirectional integration" an accurate description.
