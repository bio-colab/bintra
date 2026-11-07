#!/usr/bin/env python3
"""
REA-Neural Unified Command-Line Interface.
Dispatches to Binary Engine (deobfuscation, semantic matching, surgical binary patching, hybrid scanning)
or Weight-Space Engine (SVD, circuit decompilation, model weight surgery).
"""

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import binary_neural_engine
import rea_neural_engine

BINARY_COMMANDS = {"inspect", "deobfuscate", "match", "match-functions", "patch-binary", "scan-hybrid"}
WEIGHT_COMMANDS = {"subspace", "decompile", "decompile-circuit", "patch-weights", "diff", "diff-weights"}

def print_help():
    print("""
REA-Neural Unified CLI v7.0.0-neural.1
Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

Usage:
  python src/cli.py <command> [options]

Binary / Executable Commands:
  inspect           Inspect PE/ELF executable headers and sections
  deobfuscate       Detect and prune opaque predicates in machine code
  match             Semantically match functions across compilers / architectures
  patch-binary      Surgically patch a binary file on disk with stack preservation & PE checksum
  scan-hybrid       Scan an executable for verified embedded neural logic (ONNX, TFLite, etc.)

Weight-Space / Neural Commands:
  subspace          Extract truncated SVD singular modes from weight tensors
  decompile         Decompile an attention head slice into symbolic pseudocode
  patch-weights     Surgically patch a safetensors weight tensor without gradients
  diff-weights      Compare baseline and patched models with Frobenius diff
""")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)

    cmd = sys.argv[1]

    # Resolve disambiguation for 'patch'
    if cmd == "patch":
        if "--patch-hex" in sys.argv or "--offset" in sys.argv:
            cmd = "patch-binary"
        elif "--alpha" in sys.argv or "--mode-index" in sys.argv or "--tensor" in sys.argv:
            cmd = "patch-weights"
        else:
            print("Ambiguous command 'patch'. Please specify 'patch-binary' for PE files or 'patch-weights' for model tensors.")
            sys.exit(1)

    if cmd in BINARY_COMMANDS:
        # Translate aliases
        if cmd == "patch-binary":
            sys.argv[1] = "patch"
        elif cmd == "match-functions":
            sys.argv[1] = "match"
        binary_neural_engine.main()

    elif cmd in WEIGHT_COMMANDS:
        # Translate aliases
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
