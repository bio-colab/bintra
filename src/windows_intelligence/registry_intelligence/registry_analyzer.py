# -*- coding: utf-8 -*-
"""
Windows Registry Anomaly and Security Policy Analyzer.
Evaluates registry configurations across the 11 functional domains to detect
disabled security controls, DLL search vulnerabilities, and WOW64 view conflicts.
"""

from typing import Dict, Any, List, Optional
from .registry_catalog import RegistryCatalog, RegistryKeySpec
from .registry_reader import WindowsRegistryReader


class WindowsRegistryAnalyzer:
    """
    Performs structured, rule-based auditing of Windows Registry configurations
    to detect environmental failure hazards and policy conflicts.
    """

    @classmethod
    def audit_domain(cls, domain_name: str) -> Dict[str, Any]:
        """Audits all registered keys within a specific functional domain."""
        specs = RegistryCatalog.get_specs_for_domain(domain_name)
        if not specs:
            return {
                "status": "error",
                "domain": domain_name,
                "error": f"Domain '{domain_name}' is not recognized in RegistryCatalog."
            }

        key_results = []
        domain_discrepancies = []

        for spec in specs:
            res = WindowsRegistryReader.query_key_dual_view(
                hive=spec.hive,
                subkey=spec.subkey,
                target_values=spec.target_values,
                include_subkeys=getattr(spec, "include_subkeys", False)
            )
            key_entry = {
                "hive": spec.hive,
                "subkey": spec.subkey,
                "description": spec.description,
                "significance": spec.diagnostic_significance,
                "result": res
            }
            key_results.append(key_entry)

            if res.get("has_discrepancy"):
                domain_discrepancies.extend(res.get("discrepancies", []))

        return {
            "status": "success",
            "domain": domain_name.upper(),
            "keys_inspected": len(key_results),
            "discrepancies_count": len(domain_discrepancies),
            "discrepancies": domain_discrepancies,
            "keys": key_results
        }

    @classmethod
    def evaluate_critical_policies(cls, target_binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluates mission-critical Windows security and loader policies:
        - SafeDllSearchMode (DLL hijacking and search order priority)
        - UAC EnableLUA (Token virtualization status)
        - KnownDLLs integrity
        - Target binary AppCompatFlags shims
        """
        findings = []
        hazards = []
        sd_val = None
        lua_val = None

        # 1. SafeDllSearchMode Audit
        sd_res = WindowsRegistryReader.query_key_dual_view(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            target_values=("SafeDllSearchMode",)
        )
        v64_sd = sd_res.get("view_64", {})
        if v64_sd.get("error") == "AccessDenied" or v64_sd.get("access_denied"):
            sd_status = "ACCESS_DENIED (Insufficient Permissions to Query Registry)"
            findings.append("SafeDllSearchMode query failed: Access Denied.")
        else:
            sd_val = v64_sd.get("values", {}).get("SafeDllSearchMode", {}).get("value")
            if sd_val == 0:
                hazards.append({
                    "policy": "SafeDllSearchMode",
                    "severity": "WARNING",
                    "description": "SafeDllSearchMode is explicitly disabled (0). Current working directory is searched before system directories."
                })
                findings.append("SafeDllSearchMode is explicitly disabled (0).")
                sd_status = "EXPLICIT_DISABLED"
            elif sd_val == 1:
                findings.append("SafeDllSearchMode is explicitly enabled (1).")
                sd_status = "EXPLICIT_ENABLED"
            else:
                findings.append("SafeDllSearchMode is NOT_CONFIGURED (Defaulting to OS Default: Enabled on modern Windows).")
                sd_status = "NOT_CONFIGURED (OS_DEFAULT_ENABLED)"

        # 2. UAC EnableLUA Audit
        uac_res = WindowsRegistryReader.query_key_dual_view(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            target_values=("EnableLUA", "ConsentPromptBehaviorAdmin")
        )
        v64_uac = uac_res.get("view_64", {})
        if v64_uac.get("error") == "AccessDenied" or v64_uac.get("access_denied"):
            lua_status = "ACCESS_DENIED (Insufficient Permissions to Query Registry)"
            findings.append("UAC EnableLUA query failed: Access Denied.")
        else:
            lua_val = v64_uac.get("values", {}).get("EnableLUA", {}).get("value")
            if lua_val == 0:
                hazards.append({
                    "policy": "EnableLUA",
                    "severity": "WARNING",
                    "description": "UAC is explicitly disabled (EnableLUA=0). Token virtualization for legacy apps is inactive."
                })
                findings.append("UAC EnableLUA is explicitly disabled (0).")
                lua_status = "EXPLICIT_DISABLED"
            elif lua_val == 1:
                findings.append("UAC EnableLUA is explicitly enabled (1).")
                lua_status = "EXPLICIT_ENABLED"
            else:
                findings.append("UAC EnableLUA is NOT_CONFIGURED (Defaulting to OS Default: Enabled).")
                lua_status = "NOT_CONFIGURED (OS_DEFAULT_ENABLED)"

        # 3. KnownDLLs Verification
        kd_res = WindowsRegistryReader.query_key_dual_view(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        )
        kd_count = kd_res.get("view_64", {}).get("values_count", 0)
        findings.append(f"KnownDLLs contains {kd_count} protected system libraries.")

        # 4. Target AppCompatFlags Check if requested
        active_shims = []
        if target_binary_path:
            norm_b = target_binary_path.lower()
            for hive in ("HKCU", "HKLM"):
                subkey = (
                    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
                    if hive == "HKCU" else
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
                )
                compat_res = WindowsRegistryReader.query_key_dual_view(hive, subkey)
                for v_name, v_info in compat_res.get("view_64", {}).get("values", {}).items():
                    if norm_b in v_name.lower():
                        active_shims.append({
                            "hive": hive,
                            "path": v_name,
                            "flags": v_info.get("value")
                        })

            if active_shims:
                findings.append(f"Target binary has {len(active_shims)} compatibility shims active in registry.")
            else:
                findings.append("No compatibility shims registered for target binary.")

        return {
            "status": "success",
            "findings_count": len(findings),
            "findings": findings,
            "hazards_count": len(hazards),
            "hazards": hazards,
            "safedllsearch_mode": sd_val,
            "safedllsearch_mode_status": sd_status,
            "uac_enabled": bool(lua_val != 0) if lua_val is not None else True,
            "uac_enable_lua": lua_val,
            "uac_status": lua_status,
            "known_dlls_count": kd_count,
            "active_shims": active_shims
        }

    @classmethod
    def audit_all(cls, target_binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Runs complete inspection across all 11 registry domains."""
        domain_reports = {}
        total_keys = 0
        total_discrepancies = 0

        for dom in RegistryCatalog.DOMAINS:
            report = cls.audit_domain(dom)
            domain_reports[dom] = report
            total_keys += report.get("keys_inspected", 0)
            total_discrepancies += report.get("discrepancies_count", 0)

        policies = cls.evaluate_critical_policies(target_binary_path=target_binary_path)

        return {
            "status": "success",
            "total_domains_audited": len(domain_reports),
            "total_keys_inspected": total_keys,
            "total_discrepancies_detected": total_discrepancies,
            "critical_policies": policies,
            "domains": domain_reports
        }
