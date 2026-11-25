"""Bintra CLI commands: PE inspection, deobfuscation, matching, patching and the 10-sense audit."""
import argparse
import json
import os
import sys
from typing import List

from binary_neural_engine import (
    BinaryFormatInspector,
    ContinuousDeobfuscator,
    HybridBinaryDissector,
    SemanticFunctionMatcher,
    SensoryCortex,
    SurgicalBinaryPatcher,
    _ensure_utf8_stdio,
)

from bintra_cli.commands._common import flag_value, guard_output_path, rename_flag

_IN_PLACE_BINARY = (
    "TARGET_WRITE_FORBIDDEN: Direct in-place modification of target binaries is strictly forbidden by "
    "Bintra Safety Policy. Specify a distinct --output file in the workspace."
)


def run_binary_engine(argv: List[str]) -> None:
    """Binary engine sub-CLI (`<prog> inspect|deobfuscate|dump|match|patch|scan-hybrid ...`)."""
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(description="Bintra Binary Reverse Engineering Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    insp_p = subparsers.add_parser("inspect", help="Inspect executable PE/ELF header")
    insp_p.add_argument("--file", required=True, help="Path to executable binary")

    deob_p = subparsers.add_parser("deobfuscate", help="Detect and prune opaque predicates in code bytes or binary file")
    deob_p.add_argument("--hex", default=None, help="Hex-encoded machine code bytes")
    deob_p.add_argument("--file", default=None, help="Path to executable binary")
    deob_p.add_argument("--offset", default=None, type=lambda x: int(x, 0), help="File offset to analyze (defaults to entry point)")
    deob_p.add_argument("--size", "--length", dest="size", default=4096, type=lambda x: int(x, 0), help="Number of bytes to analyze (default 4096)")

    dump_p = subparsers.add_parser("dump", help="Extract and preview raw bytes/assembly at an offset")
    dump_p.add_argument("--file", required=True, help="Path to executable binary")
    dump_p.add_argument("--offset", required=True, type=lambda x: int(x, 0), help="File offset (e.g. 0x4e0778)")
    dump_p.add_argument("--length", default=64, type=int, help="Length in bytes (default 64)")

    match_p = subparsers.add_parser("match", help="Match functions across architectures semantically")
    match_p.add_argument("--func1", required=True, help="First function bytecode hex")
    match_p.add_argument("--func2", required=True, help="Second function bytecode hex")

    patch_p = subparsers.add_parser("patch", help="Surgically patch binary file on disk")
    patch_p.add_argument("--source", required=True, help="Source executable")
    patch_p.add_argument("--output", required=True, help="Patched executable output")
    patch_p.add_argument("--offset", required=True, type=lambda x: int(x, 0), help="Byte offset (e.g. 0x1A00)")
    patch_p.add_argument("--patch-hex", required=True, help="Patch hex bytes")
    patch_p.add_argument("--enforce-nociception", dest="enforce_nociception", action="store_true", default=True, help="Abort patch if nociceptive pain is high (enabled by default)")
    patch_p.add_argument("--force", "--no-enforce-nociception", dest="enforce_nociception", action="store_false", help="Bypass nociceptive reflex check")

    hyb_p = subparsers.add_parser("scan-hybrid", help="Scan binary for embedded neural logic assets")
    hyb_p.add_argument("--file", required=True, help="Path to executable binary")

    args = parser.parse_args(argv[1:])

    if args.command == "inspect":
        res = BinaryFormatInspector.inspect(args.file)
    elif args.command == "deobfuscate":
        if args.hex:
            res = ContinuousDeobfuscator.deobfuscate_cfg(bytes.fromhex(args.hex.replace(" ", "")))
        elif args.file:
            res = ContinuousDeobfuscator.deobfuscate_file(args.file, offset=args.offset, length=args.size)
        else:
            print(json.dumps({"error": "Must provide either --hex or --file for deobfuscation."}))
            sys.exit(1)
    elif args.command == "dump":
        res = SurgicalBinaryPatcher.read_bytes(args.file, args.offset, args.length)
    elif args.command == "match":
        res = SemanticFunctionMatcher.match_functions(args.func1, args.func2)
    elif args.command == "patch":
        res = SurgicalBinaryPatcher.patch_file(
            args.source, args.output, args.offset, args.patch_hex,
            enforce_nociception=args.enforce_nociception
        )
    else:  # scan-hybrid
        res = HybridBinaryDissector.scan_for_embedded_logic(args.file)
    print(json.dumps(res, indent=2))


def cmd_sense(cmd: str) -> None:
    """bintra sense, sensory-audit"""
    parser = argparse.ArgumentParser(description="Bintra 10-Sense Diagnostic Audit")
    parser.add_argument("command", help="sense or sensory-audit")
    parser.add_argument("--file", "--binary", "--input", dest="file", default=None, help="Optional path to PE executable or .safetensors model")
    parser.add_argument("--hex", default=None, help="Optional hex string of machine code")
    args = parser.parse_args()
    report = SensoryCortex.evaluate_all_senses(file_path=args.file, code_hex=args.hex)
    print(json.dumps(report, indent=2, ensure_ascii=False))


def cmd_patch_binary(cmd: str) -> None:
    """bintra patch-binary"""
    argv = list(sys.argv)
    argv[1] = "patch"
    rename_flag(argv, ("--file", "--binary", "--input"), "--source")
    source = flag_value(argv, "--source")
    if "--source" in argv and "--output" not in argv:
        if source is not None:
            # No explicit destination: default to the authorised workspace, never next to the source.
            from security import ExecutionGuard
            scope = ExecutionGuard.get_current_scope()
            argv.extend(["--output", os.path.join(scope.workspace_dir, "patched_" + os.path.basename(source))])
    else:
        output = flag_value(argv, "--output")
        if source is not None and output is not None:
            guard_output_path(source, output, "patch-binary", _IN_PLACE_BINARY)
    rename_flag(argv, ("--patch",), "--patch-hex")
    run_binary_engine(argv)


def cmd_match_functions(cmd: str) -> None:
    """bintra match-functions"""
    argv = list(sys.argv)
    argv[1] = "match"
    run_binary_engine(argv)


def cmd_binary_engine(cmd: str) -> None:
    """bintra deobfuscate, dump, inspect, match, scan-hybrid"""
    argv = list(sys.argv)
    rename_flag(argv, ("-f", "--binary", "-b", "--input"), "--file")
    # Positional form: bintra inspect <file>
    if "--file" not in argv and len(argv) == 3 and not argv[2].startswith("-"):
        argv.insert(2, "--file")
    run_binary_engine(argv)
