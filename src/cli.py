#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Unified Command-Line Interface.
Dispatches to Binary Engine (inspect, deobfuscate, match, patch-binary, scan-hybrid),
Weight-Space Engine (subspace, decompile, patch-weights, diff-weights, probe-trace, verify-behavior),
or Metaphorical Sensory Cortex (sense / sensory-audit).
"""

import sys
import os
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binary_neural_engine
import rea_neural_engine
from binary_neural_engine import SensoryCortex


def _ensure_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


BINARY_COMMANDS = {"inspect", "deobfuscate", "match", "match-functions", "patch-binary", "scan-hybrid"}
WEIGHT_COMMANDS = {
    "subspace", "decompile", "decompile-circuit", "patch-weights",
    "diff", "diff-weights", "probe-trace", "verify-behavior",
    "wsp-audit", "synthesize-weights"
}
SENSORY_COMMANDS = {"sense", "sensory-audit"}
GHIDRA_COMMANDS = {"match-pcode", "deobfuscate-pcode", "ghidra-plan"}


def print_help():
    print("""
REA-Neural Unified CLI v7.1.0-neural (Windows-Native & 10-Sense Edition)
Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

Usage:
  python src/cli.py <command> [options]

Binary / Windows Executable Commands:
  inspect           Inspect PE32/PE32+/ELF headers, mitigations (ASLR/DEP/CFG), and sections
  deobfuscate       Detect and prune REX-aware opaque predicates & CFF dispatcher loops
  match             Semantically match functions across compilers / architectures (x86-64 / ARM64)
  patch-binary      Surgically patch a binary file on disk with stack proprioception & PE checksum
  scan-hybrid       Scan an executable for embedded neural logic (DirectML, WinML, ONNX, GGUF, TFLite)

Weight-Space / Neural Commands:
  subspace          Extract SVD modes, sparse extremes, or coordinate slices from weight tensors
  decompile         Decompile attention heads, MLP projections, or LayerNorm drift into pseudocode
  patch-weights     Surgically patch a safetensors weight tensor without gradients
  diff-weights      Compare baseline and patched models with Frobenius diff
  probe-trace       Probe temporal activation traces across token steps (Temporal Hearing)
  verify-behavior      Verify neural equilibrium and Lipschitz bounds (Vestibular Balance)
  wsp-audit            Run MIT CSAIL WSP audit (Effective Rank, Cross-Layer Induction, Amenability, Backdoors)
  synthesize-weights   Compile neural network weights from scratch without training (Exp 5 & 6)

Metaphorical Sensory Cortex Commands:
  sense             Run all 10 Metaphorical Senses on a binary (--file), model (--file), or code (--hex)

Ghidra P-Code & Symbolic Integration Commands:
  match-pcode       Match functions using Ghidra High P-code IR (Architecture-Invariant)
  deobfuscate-pcode Detect and prune P-code algebraic opaque predicates and dispatcher loops
  ghidra-plan       Generate type-safe Ghidra database mutation and annotation plans
""")


def main():
    _ensure_utf8_stdio()
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "patch":
        if "--patch-hex" in sys.argv or "--offset" in sys.argv:
            cmd = "patch-binary"
        elif "--alpha" in sys.argv or "--mode-index" in sys.argv or "--tensor" in sys.argv or "--operation" in sys.argv:
            cmd = "patch-weights"
        else:
            print("Ambiguous command 'patch'. Please specify 'patch-binary' for PE files or 'patch-weights' for model tensors.")
            sys.exit(1)

    if cmd in SENSORY_COMMANDS:
        parser = argparse.ArgumentParser(description="REA-Neural 10-Sense Diagnostic Audit")
        parser.add_argument("command", help="sense or sensory-audit")
        parser.add_argument("--file", default=None, help="Optional path to PE executable or .safetensors model")
        parser.add_argument("--hex", default=None, help="Optional hex string of machine code")
        args = parser.parse_args()
        report = SensoryCortex.evaluate_all_senses(file_path=args.file, code_hex=args.hex)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    if cmd in GHIDRA_COMMANDS:
        from ghidra_pcode_vectorizer import (
            PcodeVectorizer, PcodeFunctionMatcher, PcodeDeobfuscator, GhidraAnnotationPlanner
        )
        if cmd == "match-pcode":
            parser = argparse.ArgumentParser(description="Match two functions using Ghidra P-code")
            parser.add_argument("command")
            parser.add_argument("--func1", required=True, help="JSON file or inline JSON string of function 1 P-code ops")
            parser.add_argument("--func2", required=True, help="JSON file or inline JSON string of function 2 P-code ops")
            args = parser.parse_args()
            def _load_pcode(val):
                if os.path.exists(val):
                    with open(val, "r", encoding="utf-8") as f:
                        return json.load(f)
                try:
                    return json.loads(val)
                except Exception:
                    import ast
                    return ast.literal_eval(val)
            p1 = _load_pcode(args.func1)
            p2 = _load_pcode(args.func2)
            res = PcodeFunctionMatcher.match(p1, p2)
            print(json.dumps(res, indent=2))
            return
        elif cmd == "deobfuscate-pcode":
            parser = argparse.ArgumentParser(description="Detect and simplify P-code opaque predicates")
            parser.add_argument("command")
            parser.add_argument("--file", default=None, help="JSON file containing P-code ops")
            parser.add_argument("--pcode", default=None, help="Inline JSON string of P-code ops")
            args = parser.parse_args()
            if args.file and os.path.exists(args.file):
                with open(args.file, "r", encoding="utf-8") as f:
                    ops = json.load(f)
            elif args.pcode:
                ops = json.loads(args.pcode)
            else:
                print("Must provide --file or --pcode JSON")
                sys.exit(1)
            res = PcodeDeobfuscator.detect_opaque_predicates(ops)
            print(json.dumps(res, indent=2))
            return
        elif cmd == "ghidra-plan":
            parser = argparse.ArgumentParser(description="Generate Ghidra Program Database annotation plan")
            parser.add_argument("command")
            parser.add_argument("--address", required=True, help="Target function address")
            parser.add_argument("--name", required=True, help="Recovered function name")
            parser.add_argument("--return-type", default="void", help="Return type")
            parser.add_argument("--comment", default=None, help="Optional decompilation comment")
            args = parser.parse_args()
            plan = GhidraAnnotationPlanner.build_function_annotation_plan(
                args.address, args.name, return_type=args.return_type, comment=args.comment
            )
            print(json.dumps(plan, indent=2))
            return

    if cmd in BINARY_COMMANDS:
        if cmd == "patch-binary":
            sys.argv[1] = "patch"
        elif cmd == "match-functions":
            sys.argv[1] = "match"
        binary_neural_engine.main()

    elif cmd in WEIGHT_COMMANDS:
        if cmd == "patch-weights":
            sys.argv[1] = "patch"
        elif cmd == "decompile-circuit":
            sys.argv[1] = "decompile"
        elif cmd == "diff-weights":
            sys.argv[1] = "diff"
        rea_neural_engine.main()

    else:
        print(f"Unknown command '{cmd}'. Run 'cli.py help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
