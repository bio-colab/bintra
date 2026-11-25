"""Bintra CLI commands: Deep PE forensics, diffing, triage, evidence fusion, signatures and Python bytecode."""
import argparse
import json
import os
import sys




def cmd_evidence_graph(cmd: str) -> None:
    """bintra evidence-graph"""
    parser = argparse.ArgumentParser(description="Synthesize cross-layer evidence causality dossier and Mermaid graph")
    parser.add_argument("command")
    parser.add_argument("--target", "--file", dest="target", required=True, help="Target PE/DLL or dump path")
    parser.add_argument("--format", choices=["json", "mermaid"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="evidence-graph",
        target=args.target,
        capability=Capability.FILE_READ,
        access_mode="READ",
    )
    from windows_intelligence.evidence_engine import CausalitySynthesizer
    dossier = CausalitySynthesizer.synthesize_dossier(binary_path=args.target)
    if args.format == "mermaid":
        print(dossier.get("mermaid_diagram") or "flowchart TD")
    else:
        print(json.dumps(dossier, indent=2, default=str))
    return


def cmd_sig_verify(cmd: str) -> None:
    """bintra sig-verify"""
    parser = argparse.ArgumentParser(prog="bintra sig-verify", description="Verify Authenticode and Security Catalog (.cat) digital signatures")
    parser.add_argument("command")
    parser.add_argument("file_path", nargs="?", default=None, help="Target executable (.exe), DLL (.dll), or kernel driver (.sys)")
    parser.add_argument("--file", "-f", "--binary", "-b", "--path", "-p", "--target", "-t", dest="flag_file", default=None, help="Target file path")
    parser.add_argument("--no-catalog", action="store_true", help="Disable Windows Security Catalog (.cat) resolution")
    parser.add_argument("--verify-revocation", action="store_true", help="Enable online CRL/OCSP revocation checks")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[1:])

    target_file = args.flag_file or args.file_path
    if not target_file:
        parser.error("Target file path is required (positional or via --file / -f)")

    from windows_intelligence import WindowsSignatureIntelligence
    report = WindowsSignatureIntelligence.verify_file(
        target_file,
        check_catalog=not args.no_catalog,
        verify_revocation=args.verify_revocation
    )
    if args.format == "md":
        lines = [
            f"# Windows Digital Signature Intelligence: `{report.get('file_name')}`",
            f"- **Trust Status:** `{report.get('trust_status')}`",
            f"- **Signature Type:** `{report.get('signature_type')}`",
            f"- **Win32 Status Code:** `{report.get('win32_status_code')}`",
            f"- **Microsoft System Binary:** `{report.get('is_microsoft_system_binary')}`",
            f"- **WHQL Certified:** `{report.get('is_whql_certified')}`",
            f"- **Kernel Driver:** `{report.get('is_driver')}`"
        ]
        if report.get("catalog_file"):
            lines.append(f"- **Security Catalog:** `{os.path.basename(report['catalog_file'])}`")
        if report.get("primary_signer"):
            s = report["primary_signer"]
            lines.append(f"- **Primary Signer:** `{s.get('subject')}` (Issuer: `{s.get('issuer')}`)")
        if report.get("risk_flags"):
            lines.append("\n### Risk Flags:")
            for rf in report["risk_flags"]:
                lines.append(f"- ⚠️ `{rf}`")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_sig_audit(cmd: str) -> None:
    """bintra sig-audit"""
    parser = argparse.ArgumentParser(prog="bintra sig-audit", description="Audit digital signatures across a directory of executables or drivers")
    parser.add_argument("command")
    parser.add_argument("dir_path", nargs="?", default=None, help="Target directory path (e.g. C:\\Windows\\System32\\drivers)")
    parser.add_argument("--dir", "-d", "--path", "-p", "--target", "-t", dest="flag_dir", default=None, help="Target directory path")
    parser.add_argument("--pattern", default="*.sys", help="File glob pattern (default: *.sys)")
    parser.add_argument("--recursive", action="store_true", help="Recursively traverse subdirectories")
    parser.add_argument("--limit", type=int, default=100, help="Maximum files to audit (default: 100)")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args(sys.argv[1:])

    target_dir = args.flag_dir or args.dir_path
    if not target_dir:
        parser.error("Target directory path is required (positional or via --dir / -d)")

    from windows_intelligence import WindowsSignatureIntelligence
    report = WindowsSignatureIntelligence.audit_directory(
        target_dir,
        pattern=args.pattern,
        recursive=args.recursive,
        max_files=args.limit
    )
    if args.format == "md":
        m = report.get("metrics", {})
        lines = [
            f"# Directory Signature Audit: `{report.get('directory')}`",
            f"- **Pattern:** `{report.get('pattern')}`",
            f"- **Total Scanned:** {m.get('total_scanned')}",
            f"- **Trusted (Embedded):** {m.get('trusted_embedded')}",
            f"- **Trusted (Catalog):** {m.get('trusted_catalog')}",
            f"- **Unsigned:** {m.get('unsigned')}",
            f"- **Untrusted / Expired:** {m.get('untrusted_or_expired')}",
            f"- **Microsoft Binaries:** {m.get('microsoft_system_binaries')}"
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_slack_audit(cmd: str) -> None:
    """bintra slack-audit, overlay-inspect, inspect-slack"""
    parser = argparse.ArgumentParser(prog=f"bintra {cmd}", description="Audit binary slack space, PE overlays, and document EOF padding")
    parser.add_argument("command", help="Command name or positional argument")
    parser.add_argument("pos_file", nargs="?", default=None, help="Target file path (.exe, .dll, .rtf, .xml, etc.)")
    parser.add_argument("--file", "-f", "--binary", "-b", dest="flag_file", default=None, help="Target file path")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format (json or md)")
    args = parser.parse_args(sys.argv[1:])
    target_f = args.flag_file or args.pos_file
    if not target_f:
        parser.error("Target file path is required (positional or via -f / --file)")

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation=cmd,
        target=target_f,
        capability=Capability.FILE_READ,
        access_mode="READ",
        metadata={"command": cmd, "file_path": target_f}
    )

    from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector
    report = BinarySlackInspector.inspect_file(target_f)
    if args.format == "md":
        lines = [
            f"# Slack Space & Overlay Audit: `{target_f}`",
            f"- **Format:** `{report.get('format')}`",
            f"- **File Size:** {report.get('file_size')} bytes",
            f"- **Has Trailing Slack:** `{report.get('has_trailing_slack')}`",
            f"- **Slack Bytes Count:** {report.get('slack_bytes_count')} bytes",
            f"- **Slack Type:** `{report.get('slack_type')}`",
            f"- **Entropy:** {report.get('slack_entropy', 0.0)}",
            f"- **Diagnostic Note:** {report.get('diagnostic_note')}"
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_py_bytecode(cmd: str) -> None:
    """bintra py-bytecode, py-dissect"""
    ap = argparse.ArgumentParser(prog=f"bintra {cmd}")
    ap.add_argument("--file", "-f", "--path", "-p", dest="file", required=True, help="Path to .py, .pyc, or package directory")
    ap.add_argument("--compare-with", dest="compare_with", default=None, help="Optional second file for bytecode diffing")
    ap.add_argument("--limit", type=int, default=50, help="Maximum code objects to inspect (default 50)")
    ap.add_argument("--threshold", type=int, default=15, help="Complexity threshold for hotspots (default 15)")
    ns = ap.parse_args(sys.argv[2:])
    from python_intelligence import PythonBytecodeAnalyzer, PythonPackageArchitect
    if os.path.isdir(ns.file):
        print(json.dumps(PythonPackageArchitect.analyze_package(ns.file, complexity_threshold=ns.threshold), indent=2))
    elif ns.compare_with:
        print(json.dumps(PythonBytecodeAnalyzer.compare_bytecode(ns.file, ns.compare_with), indent=2))
    else:
        print(json.dumps(PythonBytecodeAnalyzer.analyze_file(ns.file, limit=ns.limit), indent=2))


def cmd_py_mem_inspect(cmd: str) -> None:
    """bintra py-mem-inspect"""
    ap = argparse.ArgumentParser(prog="bintra py-mem-inspect")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--type", default="pyobject", choices=["pyobject", "pydict", "pyascii", "pylong"])
    ns = ap.parse_args(sys.argv[2:])
    from windows_intelligence.runtime_telemetry.cpython_memory_forensics import CPythonMemoryForensics
    addr = int(ns.address, 16) if str(ns.address).startswith("0x") else int(ns.address)
    print(json.dumps(CPythonMemoryForensics.inspect_live_process(ns.pid, addr, ns.type), indent=2))


def cmd_pe_forensics(cmd: str) -> None:
    """bintra pe-forensics"""
    ap = argparse.ArgumentParser(prog="bintra pe-forensics")
    ap.add_argument("--file", "--binary", dest="file", required=True)
    ap.add_argument("--pdb", dest="pdb", default=None)
    ap.add_argument("--limit", type=int, default=500)
    ns = ap.parse_args(sys.argv[2:])
    from pe_deep_forensics import PeDeepForensicsInspector
    print(json.dumps(PeDeepForensicsInspector().inspect(ns.file, pdb_path=ns.pdb, limit=ns.limit), indent=2))


def cmd_diff_binaries(cmd: str) -> None:
    """bintra diff-binaries"""
    ap = argparse.ArgumentParser(prog="bintra diff-binaries")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", choices=["pe", "ghidra_export"], default="pe")
    ns = ap.parse_args(sys.argv[2:])
    from pe_deep_forensics import SemanticBinaryDiffer
    if ns.mode == "ghidra_export":
        from security import SafeFileAccess
        b_d = json.loads(SafeFileAccess.read_bytes(ns.baseline).decode("utf-8"))
        t_d = json.loads(SafeFileAccess.read_bytes(ns.target).decode("utf-8"))
        res = SemanticBinaryDiffer().diff_function_exports(b_d.get("functions", []), t_d.get("functions", []))
    else:
        res = SemanticBinaryDiffer().diff_pe_binaries(ns.baseline, ns.target)
    print(json.dumps(res, indent=2))


def cmd_fuse_evidence(cmd: str) -> None:
    """bintra fuse-evidence"""
    ap = argparse.ArgumentParser(prog="bintra fuse-evidence")
    ap.add_argument("--binary", default=None)
    ap.add_argument("--dmp", default=None)
    ap.add_argument("--ghidra-json", default=None)
    ap.add_argument("--function", default=None)
    ns = ap.parse_args(sys.argv[2:])
    from mcp_server import BintraMcpServer
    srv = BintraMcpServer()
    resp = srv.handle_tools_call({"name": "bintra_fuse_evidence", "arguments": {
        "binary_path": ns.binary,
        "dmp_path": ns.dmp,
        "ghidra_export_path": ns.ghidra_json,
        "function_name": ns.function,
    }})
    print(resp["content"][0]["text"])


def cmd_triage(cmd: str) -> None:
    """bintra triage, triage-binary"""
    ap = argparse.ArgumentParser(
        prog="bintra triage",
        description="Unified read-only binary triage (PE inspection, deep forensics, signature trust, obfuscation, slack space, optional crash RCA & Ghidra fusion)",
    )
    ap.add_argument("pos_file", nargs="?", default=None, help="Target binary file (.exe, .dll, .sys)")
    ap.add_argument("--file", "-f", "--binary", "-b", dest="flag_file", default=None, help="Target binary file (.exe, .dll, .sys)")
    ap.add_argument("--dmp", default=None, help="Optional MiniDump (.dmp) file for crash RCA correlation")
    ap.add_argument("--ghidra", default=None, help="Optional Ghidra export (.json, .jsonl, .db)")
    ap.add_argument("--function", default=None, help="Optional target function name for Ghidra slicing")
    ap.add_argument("--skip-deobf", action="store_true", help="Skip entry-point obfuscation analysis")
    ap.add_argument("--skip-sensory", action="store_true", help="Skip 10-sense Sensory Cortex perception stage")
    ap.add_argument("--skip-hybrid-scan", action="store_true", help="Skip embedded neural inference asset scan")
    ap.add_argument("--format", choices=["json", "md"], default="json", help="Output format (json or deterministic md report)")
    ap.add_argument("--output", "-o", default=None, help="Optional destination path to write output report")
    ns = ap.parse_args(sys.argv[2:])
    target_file = ns.flag_file or ns.pos_file
    if not target_file:
        ap.error("Target binary file is required (positional or via -f / --file)")

    from analysis_orchestrator import BinaryTriageOrchestrator
    res = BinaryTriageOrchestrator.triage_binary(
        file_path=target_file,
        dmp_path=ns.dmp,
        ghidra_export_path=ns.ghidra,
        function_name=ns.function,
        include_deobfuscation=not ns.skip_deobf,
        include_sensory=not ns.skip_sensory,
        include_hybrid_scan=not ns.skip_hybrid_scan,
    )
    if ns.format == "md":
        out_content = BinaryTriageOrchestrator.generate_markdown_report(res)
    else:
        out_content = json.dumps(res, indent=2, ensure_ascii=False)

    if ns.output:
        with open(ns.output, "w", encoding="utf-8") as out_f:
            out_f.write(out_content)
        print(f"[+] Written report to: {ns.output}")
    else:
        print(out_content)


def cmd_capabilities(cmd: str) -> None:
    """bintra capabilities"""
    ap = argparse.ArgumentParser(prog="bintra capabilities")
    ap.add_argument("--platform", choices=["all", "cross_platform", "windows_native", "ghidra_required"], default="all")
    ns = ap.parse_args(sys.argv[2:])
    from mcp_server import BintraMcpServer
    srv = BintraMcpServer()
    resp = srv.handle_tools_call({"name": "bintra_list_capabilities", "arguments": {"platform_filter": ns.platform}})
    print(resp["content"][0]["text"])

