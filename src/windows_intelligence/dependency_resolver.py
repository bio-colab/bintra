# -*- coding: utf-8 -*-
"""
Windows Safe DLL Search Order & Dependency Resolver.
Emulates Windows loader DLL resolution, WOW64 filesystem redirection,
API-Set virtual routing, and cross-checks imports against disk DLL export tables.
"""

import os
import sys
from typing import Dict, Any, List, Optional, Set

# Import PE inspector from parent binary engine
sys_path_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)

from binary_neural_engine import BinaryFormatInspector


class WindowsDependencyResolver:
    """
    Simulates the Windows OS loader dynamic linking mechanism to diagnose
    missing DLLs, architecture mismatches (x86 vs x64), and unexported APIs.
    """

    KNOWN_API_SET_FORWARDERS = {
        "api-ms-win-core-": "kernelbase.dll",
        "api-ms-win-crt-": "ucrtbase.dll",
        "api-ms-win-security-": "kernelbase.dll",
        "api-ms-win-service-": "sechost.dll",
        "api-ms-win-eventing-": "kernelbase.dll",
        "ext-ms-win-gdi-": "gdi32.dll",
        "ext-ms-win-ntuser-": "user32.dll"
    }

    @classmethod
    def get_search_directories(cls, binary_path: str, is_32bit_on_64bit: bool = False) -> List[str]:
        """
        Builds the ordered list of directories searched by the Windows dynamic loader
        under SafeDllSearchMode (enabled by default on all modern Windows versions).
        """
        app_dir = os.path.dirname(os.path.abspath(binary_path))
        windir = os.environ.get("WINDIR", r"C:\Windows")
        system_root = os.environ.get("SystemRoot", windir)

        # Handle WOW64 Redirection for 32-bit binaries running on 64-bit Windows
        if is_32bit_on_64bit:
            sys_dir = os.path.join(system_root, "SysWOW64")
            # If SysWOW64 doesn't exist (e.g. running on pure 32-bit OS), fallback to System32
            if not os.path.exists(sys_dir):
                sys_dir = os.path.join(system_root, "System32")
        else:
            sys_dir = os.path.join(system_root, "System32")

        sys16_dir = os.path.join(system_root, "System")

        search_dirs = [
            app_dir,
            sys_dir,
            sys16_dir,
            system_root,
            os.getcwd()
        ]

        # Append PATH environment variable entries
        path_env = os.environ.get("PATH", "")
        for p in path_env.split(os.pathsep):
            p_clean = p.strip().strip('"')
            if p_clean and os.path.isdir(p_clean) and p_clean not in search_dirs:
                search_dirs.append(p_clean)

        return search_dirs

    @classmethod
    def is_api_set(cls, dll_name: str) -> bool:
        """Determines if a DLL reference is a virtual MinWin API-Set contract."""
        lower = dll_name.lower()
        return lower.startswith("api-ms-win-") or lower.startswith("ext-ms-win-")

    @classmethod
    def resolve_api_set_target(cls, dll_name: str) -> str:
        """Maps virtual API-Set prefix to the canonical implementing Windows system library."""
        lower = dll_name.lower()
        for prefix, target in cls.KNOWN_API_SET_FORWARDERS.items():
            if lower.startswith(prefix):
                return target
        return "kernelbase.dll"

    @classmethod
    def locate_dll(cls, dll_name: str, search_dirs: List[str]) -> Optional[str]:
        """Searches for a DLL by name through the ordered directory hierarchy."""
        for d in search_dirs:
            candidate = os.path.join(d, dll_name)
            if os.path.isfile(candidate):
                return candidate
            # Case-insensitive scan for Windows filesystems
            try:
                for entry in os.listdir(d):
                    if entry.lower() == dll_name.lower():
                        return os.path.join(d, entry)
            except OSError:
                continue
        return None

    @classmethod
    def audit_dependencies(
        cls,
        binary_path: str,
        custom_imports: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """
        Performs deep verification of an executable's imports against host Windows DLLs.
        Detects:
        - Missing libraries (DLL_NOT_FOUND / 0xC0000135).
        - Architecture mismatch (attempting to load x64 DLL in x86 binary or vice-versa).
        - Missing exported procedures (PROCEDURE_NOT_FOUND / 0xC0000139).
        """
        if custom_imports is None and not os.path.isfile(binary_path):
            return {
                "status": "error",
                "error": f"File not found: {binary_path}"
            }

        pe_info = BinaryFormatInspector.inspect(binary_path) if os.path.isfile(binary_path) else {}
        if custom_imports is None and pe_info.get("format") != "PE":
            return {
                "status": "error",
                "error": "Target file is not a valid Portable Executable (PE)."
            }

        is_binary_64 = pe_info.get("pe_type", "").startswith("PE32+") if pe_info else False
        host_is_64 = (os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() in ("AMD64", "ARM64") or
                      os.environ.get("PROCESSOR_ARCHITEW6432", "").upper() in ("AMD64", "ARM64"))
        is_32bit_on_64bit = (not is_binary_64) and host_is_64

        search_dirs = cls.get_search_directories(binary_path, is_32bit_on_64bit=is_32bit_on_64bit)
        imports = custom_imports if custom_imports is not None else pe_info.get("imports", {}).get("modules", {})

        resolved_modules = []
        missing_modules = []
        architecture_mismatches = []
        missing_exports = []

        for dll_name, imported_funcs in imports.items():
            is_virtual_api_set = cls.is_api_set(dll_name)
            search_name = cls.resolve_api_set_target(dll_name) if is_virtual_api_set else dll_name
            located_path = cls.locate_dll(search_name, search_dirs)

            if not located_path:
                missing_modules.append({
                    "imported_name": dll_name,
                    "resolved_as": search_name,
                    "is_api_set": is_virtual_api_set,
                    "functions_count": len(imported_funcs),
                    "functions_preview": imported_funcs[:5]
                })
                continue

            # Verify DLL architecture
            try:
                dll_pe = BinaryFormatInspector.inspect(located_path)
                dll_is_64 = dll_pe.get("pe_type", "").startswith("PE32+")
                if dll_pe.get("format") == "PE" and dll_is_64 != is_binary_64:
                    architecture_mismatches.append({
                        "dll_name": dll_name,
                        "located_path": located_path,
                        "binary_arch": "PE32+ (64-bit)" if is_binary_64 else "PE32 (32-bit)",
                        "dll_arch": "PE32+ (64-bit)" if dll_is_64 else "PE32 (32-bit)"
                    })

                # Verify exported functions
                if dll_pe.get("format") == "PE" and not is_virtual_api_set:
                    exported_list = dll_pe.get("exports", {}).get("functions", [])
                    exported_names: Set[str] = {e["name"] for e in exported_list if e.get("name")}
                    exported_ordinals: Set[int] = {e["ordinal"] for e in exported_list if e.get("ordinal") is not None}

                    for fn in imported_funcs:
                        if fn.startswith("Ordinal_"):
                            try:
                                ord_num = int(fn.split("_")[1])
                                if ord_num not in exported_ordinals:
                                    missing_exports.append({
                                        "dll_name": dll_name,
                                        "located_path": located_path,
                                        "missing_symbol": fn
                                    })
                            except (IndexError, ValueError):
                                pass
                        else:
                            if fn and fn not in exported_names:
                                missing_exports.append({
                                    "dll_name": dll_name,
                                    "located_path": located_path,
                                    "missing_symbol": fn
                                })

            except Exception:
                pass

            resolved_modules.append({
                "imported_name": dll_name,
                "is_api_set": is_virtual_api_set,
                "located_path": located_path,
                "imported_functions_count": len(imported_funcs)
            })

        has_critical_failure = (len(missing_modules) > 0 or len(architecture_mismatches) > 0 or len(missing_exports) > 0)
        verdict = "HEALTHY" if not has_critical_failure else "DEPENDENCY_INTEGRITY_FAILURE"

        return {
            "status": "success",
            "binary_path": binary_path,
            "binary_architecture": "PE32+ (64-bit)" if is_binary_64 else "PE32 (32-bit)",
            "loader_mode": "WOW64 (32-on-64)" if is_32bit_on_64bit else "Native",
            "verdict": verdict,
            "total_imported_dlls": len(imports),
            "resolved_dlls_count": len(resolved_modules),
            "missing_dlls_count": len(missing_modules),
            "architecture_mismatches_count": len(architecture_mismatches),
            "missing_exports_count": len(missing_exports),
            "resolved_dlls": resolved_modules,
            "missing_dlls": missing_modules,
            "architecture_mismatches": architecture_mismatches,
            "missing_exports": missing_exports,
            "search_directories": search_dirs[:8]
        }
