# -*- coding: utf-8 -*-
"""
Windows Registry Intelligence Catalog.
Organizes Windows registry keys across 11 functional domains with diagnostic
significance definitions, target values, and expected data types.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple


@dataclass(frozen=True)
class RegistryKeySpec:
    """Specification of a diagnostic registry key node."""
    domain: str
    hive: str
    subkey: str
    target_values: Tuple[str, ...]
    description: str
    diagnostic_significance: str
    include_subkeys: bool = False


class RegistryCatalog:
    """
    Catalog of diagnostic registry locations covering 11 core operating system domains.
    """

    DOMAINS = [
        "OPERATING_SYSTEM",
        "APPLICATION_COMPATIBILITY",
        "DLL_SEARCH_CONFIGURATION",
        "KNOWN_DLLS",
        "SERVICES_AND_DRIVERS",
        "DEVICE_CONFIGURATION",
        "SECURITY_POLICIES",
        "GRAPHICS_SUBSYSTEM",
        "COM_REGISTRATION",
        "BOOT_CONFIGURATION",
        "INSTALLED_SOFTWARE"
    ]

    CATALOG: List[RegistryKeySpec] = [
        # 1. Operating System
        RegistryKeySpec(
            domain="OPERATING_SYSTEM",
            hive="HKLM",
            subkey=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            target_values=("ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "UBR", "EditionID", "InstallationType"),
            description="Windows build, display version, update build revision (UBR), and edition",
            diagnostic_significance="Defines exact OS patch baseline to verify API and runtime availability"
        ),
        # 2. Application Compatibility
        RegistryKeySpec(
            domain="APPLICATION_COMPATIBILITY",
            hive="HKLM",
            subkey=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            target_values=(),  # Enumerates all active executable paths
            description="System-wide application compatibility shims (e.g. WINXPSP3, RUNASADMIN, 640X480)",
            diagnostic_significance="Detects OS emulation shims that alter loader, memory, or display behaviors"
        ),
        RegistryKeySpec(
            domain="APPLICATION_COMPATIBILITY",
            hive="HKCU",
            subkey=r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            target_values=(),
            description="User-specific application compatibility shims",
            diagnostic_significance="Identifies user-configured compatibility overrides applied to executables"
        ),
        # 3. DLL Search Configuration
        RegistryKeySpec(
            domain="DLL_SEARCH_CONFIGURATION",
            hive="HKLM",
            subkey=r"SYSTEM\CurrentControlSet\Control\Session Manager",
            target_values=("SafeDllSearchMode", "CWDIllegalInDllSearch"),
            description="Dynamic link library search mode and current working directory restrictions",
            diagnostic_significance="SafeDllSearchMode=0 allows DLL hijacking from current working directory"
        ),
        # 4. Known DLLs
        RegistryKeySpec(
            domain="KNOWN_DLLS",
            hive="HKLM",
            subkey=r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
            target_values=(),  # All value entries are known DLLs
            description="Canonical list of system libraries loaded directly from system directory",
            diagnostic_significance="Overrides local application DLLs; cannot be substituted in app folder"
        ),
        # 5. Services and Drivers
        RegistryKeySpec(
            domain="SERVICES_AND_DRIVERS",
            hive="HKLM",
            subkey=r"SYSTEM\CurrentControlSet\Services",
            target_values=("Type", "Start", "ErrorControl", "ImagePath"),
            description="Windows service configurations, driver binaries, and startup policies",
            diagnostic_significance="Detects disabled or misconfigured dependency services and driver roots",
            include_subkeys=True
        ),
        # 6. Device Configuration
        RegistryKeySpec(
            domain="DEVICE_CONFIGURATION",
            hive="HKLM",
            subkey=r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}",
            target_values=("DriverDesc", "DriverVersion", "ProviderName", "MatchingDeviceId"),
            description="Display adapter driver class registry nodes",
            diagnostic_significance="Identifies GPU hardware ID, vendor, and installed driver release",
            include_subkeys=True
        ),
        # 7. Security Policies
        RegistryKeySpec(
            domain="SECURITY_POLICIES",
            hive="HKLM",
            subkey=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            target_values=("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop", "ValidateAdminCodeSignatures"),
            description="UAC elevation behavior, token filtering, and secure desktop enforcement",
            diagnostic_significance="EnableLUA=0 disables UAC and Directory Virtualization for legacy apps"
        ),
        # 8. Graphics Subsystem
        RegistryKeySpec(
            domain="GRAPHICS_SUBSYSTEM",
            hive="HKLM",
            subkey=r"SOFTWARE\Microsoft\DirectX",
            target_values=("Version", "InstalledVersion"),
            description="DirectX core runtime version registry configuration",
            diagnostic_significance="Validates DirectX runtime installation and legacy graphics foundation"
        ),
        # 9. COM Registration
        RegistryKeySpec(
            domain="COM_REGISTRATION",
            hive="HKCR",
            subkey=r"CLSID",
            target_values=("InprocServer32",),
            description="Component Object Model class identifier mappings and implementing DLLs",
            diagnostic_significance="Diagnoses REGDB_E_CLASSNOTREG (0x80040154) when COM objects fail to instantiate",
            include_subkeys=True
        ),
        # 10. Boot Configuration
        RegistryKeySpec(
            domain="BOOT_CONFIGURATION",
            hive="HKLM",
            subkey=r"SYSTEM\CurrentControlSet\Control",
            target_values=("SystemStartOptions",),
            description="Windows boot options and kernel execution flags",
            diagnostic_significance="Reveals whether SafeMode, Debugging, or TestSigning modes are active"
        ),
        # 11. Installed Software
        RegistryKeySpec(
            domain="INSTALLED_SOFTWARE",
            hive="HKLM",
            subkey=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            target_values=("DisplayName", "DisplayVersion", "Publisher", "InstallLocation"),
            description="Installed software inventory, runtimes, and redistributable packages",
            diagnostic_significance="Verifies presence of Visual C++ Redistributable packages and DirectX runtimes",
            include_subkeys=True
        )
    ]

    @classmethod
    def get_specs_for_domain(cls, domain: str) -> List[RegistryKeySpec]:
        """Retrieves all registry key specifications matching a domain name."""
        d_upper = domain.upper()
        return [spec for spec in cls.CATALOG if spec.domain == d_upper]

    @classmethod
    def get_all_specs(cls) -> List[RegistryKeySpec]:
        """Returns the full list of diagnostic registry key specifications."""
        return list(cls.CATALOG)
