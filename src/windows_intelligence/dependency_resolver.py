# -*- coding: utf-8 -*-
"""
Windows Safe DLL Search Order & Dependency Resolver.
Emulates Windows loader DLL resolution, WOW64 filesystem redirection,
KnownDLLs registry evaluation, API-Set virtual routing, and cross-checks imports
against disk DLL export tables.
"""

import os
import sys
import re
import glob
from typing import Dict, Any, List, Optional, Set

try:
    import winreg
except ImportError:
    winreg = None

# Import PE inspector from parent binary engine
sys_path_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)

from binary_neural_engine import BinaryFormatInspector


class WindowsDependencyResolver:
    """
    Simulates the Windows OS loader dynamic linking mechanism (SafeDllSearchMode)
    to diagnose missing DLLs, architecture mismatches (x86 vs x64), unexported APIs,
    and KnownDLLs priority.
    """

    KNOWN_API_SET_FORWARDERS = {
        "api-ms-win-core-": "kernelbase.dll",
        "api-ms-win-crt-": "ucrtbase.dll",
        "api-ms-win-security-": "kernelbase.dll",
        "api-ms-win-service-": "sechost.dll",
        "api-ms-win-eventing-": "kernelbase.dll",
        "api-ms-win-power-": "powrprof.dll",
        "api-ms-win-shcore-": "shcore.dll",
        "api-ms-win-shell-": "shell32.dll",
        "api-ms-win-devices-": "cfgmgr32.dll",
        "api-ms-win-dx-": "d3d11.dll",
        "ext-ms-win-gdi-": "gdi32.dll",
        "ext-ms-win-ntuser-": "user32.dll",
        "ext-ms-win-rtcore-": "user32.dll",
        "ext-ms-win-kernel32-": "kernel32.dll",
        "ext-ms-win-advapi32-": "advapi32.dll",
        "ext-ms-win-ole32-": "ole32.dll",
        "ext-ms-win-com-": "combase.dll",
    }

    SXS_ASSEMBLY_MAP = {
        "comctl32.dll": "microsoft.windows.common-controls",
        "gdiplus.dll": "microsoft.windows.gdiplus",
        "msvcr90.dll": "microsoft.vc90.crt",
        "msvcp90.dll": "microsoft.vc90.crt",
        "msvcm90.dll": "microsoft.vc90.crt",
        "msvcr80.dll": "microsoft.vc80.crt",
        "msvcp80.dll": "microsoft.vc80.crt"
    }

    @classmethod
    def get_known_dlls(cls) -> Set[str]:
        """
        Retrieves the Windows KnownDLLs list from the registry:
        HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs
        Windows loader always loads KnownDLLs from System32/SysWOW64, bypassing the application directory.
        """
        if not winreg:
            return set()
        known = set()
        path = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
                idx = 0
                while True:
                    try:
                        _, val_data, _ = winreg.EnumValue(k, idx)
                        idx += 1
                        if isinstance(val_data, str) and val_data.lower().endswith(".dll"):
                            known.add(val_data.lower())
                    except OSError:
                        break
        except Exception:
            pass
        return known

    @classmethod
    def get_search_directories(
        cls,
        binary_path: str,
        is_32bit_on_64bit: bool = False,
        app_dir: Optional[str] = None
    ) -> List[str]:
        """
        Builds the ordered list of directories searched by the Windows dynamic loader
        under SafeDllSearchMode (enabled by default on all modern Windows versions).
        """
        target_dir = os.path.dirname(os.path.abspath(binary_path))
        windir = os.environ.get("WINDIR", r"C:\Windows")
        system_root = os.environ.get("SystemRoot", windir)

        # Handle WOW64 Redirection for 32-bit binaries running on 64-bit Windows
        if is_32bit_on_64bit:
            sys_dir = os.path.join(system_root, "SysWOW64")
            if not os.path.exists(sys_dir):
                sys_dir = os.path.join(system_root, "System32")
        else:
            sys_dir = os.path.join(system_root, "System32")

        sys16_dir = os.path.join(system_root, "System")

        search_dirs: List[str] = []

        # 1. Primary loader host directory (app_dir override or auto-discovered host executable directory)
        effective_app_dir = app_dir
        if not effective_app_dir:
            cand_parent = os.path.dirname(target_dir)
            cand_root = os.path.dirname(cand_parent)
            p_name = os.path.basename(cand_parent).lower()
            if p_name in ("obs-plugins", "plugins"):
                sub = os.path.basename(target_dir)
                sibling_bin = os.path.join(cand_root, "bin", sub)
                if os.path.isdir(sibling_bin):
                    effective_app_dir = sibling_bin
            elif p_name == "core" or os.path.basename(os.path.dirname(cand_parent)).lower() == "core":
                # OBS 33 modular structure: OBS_ROOT\core\<plugin>\<plugin>.dll or OBS_ROOT\core\<plugin>\data\<sub.dll>
                app_root = cand_root if p_name == "core" else os.path.dirname(cand_root)
                for b_cand in (
                    os.path.join(app_root, "bin", "64bit"),
                    os.path.join(app_root, "bin", "32bit"),
                    os.path.join(app_root, "bin"),
                ):
                    if os.path.isdir(b_cand):
                        effective_app_dir = b_cand
                        break

        if effective_app_dir:
            can_app = os.path.abspath(effective_app_dir)
            if can_app not in search_dirs:
                search_dirs.append(can_app)

        # 2. Binary target directory
        if target_dir not in search_dirs:
            search_dirs.append(target_dir)

        search_dirs.extend([
            sys_dir,
            sys16_dir,
            system_root,
            os.getcwd()
        ])

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
    def resolve_api_set(cls, dll_name: str) -> Dict[str, Any]:
        """
        Maps virtual API-Set contract to the implementing system library, returning
        explicit epistemic provenance metadata distinguishing verified prefix matches
        from default fallbacks.
        """
        lower = dll_name.lower()
        for prefix, target in cls.KNOWN_API_SET_FORWARDERS.items():
            if lower.startswith(prefix):
                return {
                    "api_set": dll_name,
                    "target_dll": target,
                    "is_heuristic": True,
                    "resolution_method": "CANONICAL_FORWARDER_PREFIX_MAP",
                    "matched_prefix": prefix,
                    "disclaimer": (
                        "Approximated via canonical API-Set forwarder schema table; "
                        "not dynamically parsed from live Windows PEB ApiSetMap schema."
                    ),
                }
        return {
            "api_set": dll_name,
            "target_dll": "kernelbase.dll",
            "is_heuristic": True,
            "resolution_method": "DEFAULT_FALLBACK",
            "matched_prefix": None,
            "disclaimer": (
                "Unrecognized API-Set contract; defaulted to kernelbase.dll. "
                "Empirical approximation."
            ),
        }

    @classmethod
    def resolve_api_set_target(cls, dll_name: str) -> str:
        """Backwards-compatible string target resolver."""
        return cls.resolve_api_set(dll_name)["target_dll"]

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
    def extract_manifest_text(cls, binary_path: str) -> str:
        """
        Extracts application manifest XML text from an external .manifest file or
        by scanning embedded resource data in the PE binary.
        """
        if not binary_path:
            return ""
        # 1. External manifest file (e.g., target.exe.manifest)
        ext_manifest = binary_path + ".manifest"
        if os.path.isfile(ext_manifest):
            try:
                with open(ext_manifest, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except Exception:
                pass

        # 2. Embedded manifest inside PE file
        if os.path.isfile(binary_path):
            try:
                with open(binary_path, "rb") as f:
                    # Read up to first 25MB (covers headers and resources of almost all PEs)
                    data = f.read(25 * 1024 * 1024)
                # Look for <assembly ... </assembly>
                m = re.search(rb"(<assembly\b[\s\S]*?</assembly>)", data)
                if m:
                    return m.group(1).decode("utf-8", errors="ignore")
                # Fallback: look for dependentAssembly blocks
                m = re.search(rb"(<dependentAssembly[\s\S]*?</dependentAssembly>)", data)
                if m:
                    return m.group(1).decode("utf-8", errors="ignore")
            except Exception:
                pass
        return ""

    @classmethod
    def resolve_sxs_dll(
        cls,
        dll_name: str,
        binary_path: str = "",
        is_64bit: bool = True,
        manifest_text: Optional[str] = None
    ) -> Optional[str]:
        r"""
        Resolves a Side-by-Side (SxS) assembly DLL from C:\Windows\WinSxS based on
        application manifest declarations, exact assemblyIdentity attributes
        (name, version, publicKeyToken, processorArchitecture), and architecture.
        """
        dll_lower = dll_name.lower()
        assembly_name = cls.SXS_ASSEMBLY_MAP.get(dll_lower)
        if not assembly_name:
            return None

        if manifest_text is None:
            manifest_text = cls.extract_manifest_text(binary_path) if binary_path else ""

        lower_manifest = manifest_text.lower() if manifest_text else ""

        # For common-controls: if a manifest is present but does not declare Common-Controls v6,
        # the Windows loader intentionally loads the legacy v5.82 DLL from System32.
        if assembly_name == "microsoft.windows.common-controls":
            if manifest_text and "microsoft.windows.common-controls" not in lower_manifest:
                return None

        # Extract precise assembly identity attributes from manifest
        req_token = None
        req_ver_major = None
        if manifest_text:
            m = re.search(
                rf'<assemblyIdentity\b[^>]*\bname=["\'](?:[^"\']*\.)?{re.escape(assembly_name.split(".")[-1])}["\'][^>]*>',
                manifest_text,
                re.IGNORECASE
            )
            if not m:
                m = re.search(
                    rf'<assemblyIdentity\b[^>]*\bname=["\']{re.escape(assembly_name)}["\'][^>]*>',
                    manifest_text,
                    re.IGNORECASE
                )
            if m:
                tag = m.group(0)
                tok_m = re.search(r'publicKeyToken=["\']([a-fA-F0-9]+)["\']', tag)
                if tok_m:
                    req_token = tok_m.group(1).lower()
                ver_m = re.search(r'version=["\']([0-9]+(?:\.[0-9]+)*)["\']', tag)
                if ver_m:
                    req_ver_major = ver_m.group(1).split(".")[0]

        arch_prefix = "amd64" if is_64bit else "x86"
        winsxs_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "WinSxS")
        if not os.path.isdir(winsxs_dir):
            return None

        pattern = os.path.join(winsxs_dir, f"{arch_prefix}_{assembly_name}_*")
        candidates = glob.glob(pattern)
        if not candidates and not is_64bit:
            candidates = glob.glob(os.path.join(winsxs_dir, f"wow64_{assembly_name}_*"))

        if not candidates:
            return None

        # Filter by publicKeyToken from manifest if present
        if req_token:
            token_cands = [c for c in candidates if req_token in os.path.basename(c).lower()]
            if token_cands:
                candidates = token_cands

        # Filter by requested major version (e.g. 6.0)
        if req_ver_major:
            ver_cands = [c for c in candidates if f"_{req_ver_major}." in os.path.basename(c)]
            if ver_cands:
                candidates = ver_cands
        elif assembly_name == "microsoft.windows.common-controls" and ("6.0" in lower_manifest):
            v6_cands = [c for c in candidates if "_6.0." in os.path.basename(c)]
            if v6_cands:
                candidates = v6_cands

        # Highest version candidate first
        candidates.sort(reverse=True)
        for cand in candidates:
            target = os.path.join(cand, dll_name)
            if os.path.isfile(target):
                return target
            try:
                for entry in os.listdir(cand):
                    if entry.lower() == dll_lower:
                        return os.path.join(cand, entry)
            except OSError:
                pass

        return None

    @classmethod
    def _audit_module_map(
        cls,
        modules_map: Dict[str, List[str]],
        binary_path: str,
        is_binary_64: bool,
        search_dirs: List[str],
        known_dlls: Set[str],
        manifest_text: str,
        app_dirs_to_skip: Set[str],
        is_delay_load: bool = False,
    ) -> Dict[str, Any]:
        """Resolves a DLL import dictionary (static IAT or delay-load) against WinSxS, KnownDLLs, and search paths."""
        resolved_modules = []
        missing_modules = []
        architecture_mismatches = []
        missing_exports = []

        for dll_name, imported_funcs in modules_map.items():
            is_virtual_api_set = cls.is_api_set(dll_name)
            is_known = dll_name.lower() in known_dlls
            search_name = cls.resolve_api_set_target(dll_name) if is_virtual_api_set else dll_name

            # 1. Check Side-by-Side (SxS) assembly context first (e.g. COMCTL32 v6, GDI+, CRT)
            sxs_path = cls.resolve_sxs_dll(
                search_name,
                binary_path=binary_path,
                is_64bit=is_binary_64,
                manifest_text=manifest_text
            )
            is_sxs = sxs_path is not None

            if sxs_path:
                located_path = sxs_path
            else:
                # KnownDLLs are loaded directly from system directory, bypassing all application directories
                effective_search_dirs = (
                    [d for d in search_dirs if os.path.abspath(d) not in app_dirs_to_skip]
                    if is_known
                    else search_dirs
                )
                located_path = cls.locate_dll(search_name, effective_search_dirs)

            if not located_path:
                missing_modules.append({
                    "imported_name": dll_name,
                    "resolved_as": search_name,
                    "is_api_set": is_virtual_api_set,
                    "is_known_dll": is_known,
                    "is_sxs_assembly": False,
                    "is_delay_load": is_delay_load,
                    "functions_count": len(imported_funcs),
                    "functions_preview": imported_funcs[:5]
                })
                continue

            # Verify DLL architecture and exported symbols
            try:
                dll_pe = BinaryFormatInspector.inspect(located_path)
                dll_is_64 = dll_pe.get("pe_type", "").startswith("PE32+")
                if dll_pe.get("format") == "PE" and dll_is_64 != is_binary_64:
                    architecture_mismatches.append({
                        "dll_name": dll_name,
                        "located_path": located_path,
                        "is_delay_load": is_delay_load,
                        "binary_arch": "PE32+ (64-bit)" if is_binary_64 else "PE32 (32-bit)",
                        "dll_arch": "PE32+ (64-bit)" if dll_is_64 else "PE32 (32-bit)"
                    })

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
                                        "is_delay_load": is_delay_load,
                                        "missing_symbol": fn
                                    })
                            except (IndexError, ValueError):
                                pass
                        else:
                            if fn and fn not in exported_names:
                                missing_exports.append({
                                    "dll_name": dll_name,
                                    "located_path": located_path,
                                    "is_delay_load": is_delay_load,
                                    "missing_symbol": fn
                                })

            except Exception:
                pass

            resolved_modules.append({
                "imported_name": dll_name,
                "is_api_set": is_virtual_api_set,
                "is_known_dll": is_known,
                "is_sxs_assembly": is_sxs,
                "is_delay_load": is_delay_load,
                "located_path": located_path,
                "imported_functions_count": len(imported_funcs)
            })

        return {
            "resolved": resolved_modules,
            "missing": missing_modules,
            "architecture_mismatches": architecture_mismatches,
            "missing_exports": missing_exports,
        }

    @classmethod
    def audit_dependencies(
        cls,
        binary_path: str,
        custom_imports: Optional[Dict[str, List[str]]] = None,
        app_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Performs static heuristic verification of an executable's static and delay-load imports
        against host Windows DLLs.
        Detects:
        - Missing libraries (DLL_NOT_FOUND / 0xC0000135).
        - Architecture mismatch (attempting to load x64 DLL in x86 binary or vice-versa).
        - Missing exported procedures (PROCEDURE_NOT_FOUND / 0xC0000139).
        - KnownDLLs priority enforcement.
        """
        if sys.platform != "win32":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "WindowsDependencyResolver requires a Windows host system."
            }

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

        search_dirs = cls.get_search_directories(
            binary_path,
            is_32bit_on_64bit=is_32bit_on_64bit,
            app_dir=app_dir
        )
        imports = custom_imports if custom_imports is not None else pe_info.get("imports", {}).get("modules", {})
        delay_imports = {} if custom_imports is not None else (pe_info.get("delay_imports", {}) or {}).get("modules", {})
        known_dlls = cls.get_known_dlls()
        manifest_text = cls.extract_manifest_text(binary_path) if os.path.isfile(binary_path) else ""
        app_dirs_to_skip = {
            os.path.abspath(d)
            for d in (app_dir, os.path.dirname(os.path.abspath(binary_path)))
            if d
        }

        static_res = cls._audit_module_map(
            imports,
            binary_path=binary_path,
            is_binary_64=is_binary_64,
            search_dirs=search_dirs,
            known_dlls=known_dlls,
            manifest_text=manifest_text,
            app_dirs_to_skip=app_dirs_to_skip,
            is_delay_load=False,
        )
        delay_res = cls._audit_module_map(
            delay_imports,
            binary_path=binary_path,
            is_binary_64=is_binary_64,
            search_dirs=search_dirs,
            known_dlls=known_dlls,
            manifest_text=manifest_text,
            app_dirs_to_skip=app_dirs_to_skip,
            is_delay_load=True,
        ) if delay_imports else {
            "resolved": [], "missing": [], "architecture_mismatches": [], "missing_exports": []
        }

        resolved_modules = static_res["resolved"]
        missing_modules = static_res["missing"]
        architecture_mismatches = static_res["architecture_mismatches"]
        missing_exports = static_res["missing_exports"]

        has_critical_failure = (len(missing_modules) > 0 or len(architecture_mismatches) > 0 or len(missing_exports) > 0)
        has_delay_failure = (
            len(delay_res["missing"]) > 0
            or len(delay_res["architecture_mismatches"]) > 0
            or len(delay_res["missing_exports"]) > 0
        )
        verdict = "HEALTHY" if not has_critical_failure else "DEPENDENCY_INTEGRITY_FAILURE"
        delay_verdict = (
            "NO_DELAY_IMPORTS"
            if not delay_imports
            else ("DELAY_DEPENDENCY_ISSUES_DETECTED" if has_delay_failure else "HEALTHY")
        )

        return {
            "status": "success",
            "audit_scope": "STATIC_HEURISTIC_AUDIT",
            "binary_path": binary_path,
            "binary_architecture": "PE32+ (64-bit)" if is_binary_64 else "PE32 (32-bit)",
            "loader_mode": "WOW64 (32-on-64)" if is_32bit_on_64bit else "Native",
            "known_dlls_enforced": len(known_dlls),
            "verdict": verdict,
            "delay_dependency_health": delay_verdict,
            "total_imported_dlls": len(imports),
            "resolved_dlls_count": len(resolved_modules),
            "missing_dlls_count": len(missing_modules),
            "architecture_mismatches_count": len(architecture_mismatches),
            "missing_exports_count": len(missing_exports),
            "sxs_assemblies_count": sum(1 for m in resolved_modules if m.get("is_sxs_assembly", False)),
            "delay_imported_dlls_count": len(delay_imports),
            "resolved_delay_dlls_count": len(delay_res["resolved"]),
            "missing_delay_dlls_count": len(delay_res["missing"]),
            "resolved_dlls": resolved_modules,
            "missing_dlls": missing_modules,
            "architecture_mismatches": architecture_mismatches,
            "missing_exports": missing_exports,
            "resolved_delay_dlls": delay_res["resolved"],
            "missing_delay_dlls": delay_res["missing"],
            "delay_architecture_mismatches": delay_res["architecture_mismatches"],
            "delay_missing_exports": delay_res["missing_exports"],
            "search_directories": search_dirs[:8]
        }
