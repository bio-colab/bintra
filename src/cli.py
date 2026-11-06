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

BINARY_COMMANDS = {"inspect", "deobfuscate", "match", "patch", "scan-hybrid"}
WEIGHT_COMMANDS = {"subspace", "decompile", "diff"}

def print_help():
    print("""
REA-Neural Unified CLI v7.0.0-neural.1
Autonomous Continuous Semantic Reverse Engineering & Binary Analysis

Usage:
  python src/cli.py <command> [options]

Binary / Executable Commands:
  inspect       Inspect PE/ELF executable headers and sections
  deobfuscate   Detect and prune opaque predicates in machine code
  match         Semantically match functions across compilers / architectures
  patch         Surgically patch a binary file on disk with stack preservation
  scan-hybrid   Scan an executable for embedded neural inference logic (ONNX, TFLite, etc.)

Weight-Space / Neural Commands:
  subspace      Extract truncated SVD singular modes from weight tensors
  decompile     Decompile attention/MLP circuits into symbolic pseudocode
  diff          Compare baseline and patched models with Frobenius diff
""")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd in BINARY_COMMANDS:
        # Re-route to binary engine
        sys.argv.pop(0) # remove cli.py, sys.argv[0] becomes command
        binary_neural_engine.main()
    elif cmd in WEIGHT_COMMANDS:
        sys.argv.pop(0)
        rea_neural_engine.main()
    else:
        print(f"Unknown command '{cmd}'. Run 'cli.py help' for usage.")
        sys.exit(1)

if __name__ == "__main__":
    main()
