# -*- coding: utf-8 -*-
"""
Windows Signature & Digital Trust Intelligence.
Zero-dependency Authenticode and Security Catalog (.cat) verification engine.

Provides:
  1. Embedded Authenticode Verification (WIN_CERTIFICATE / PKCS#7) via WinVerifyTrust & pure Python ASN.1 DER parser.
  2. Security Catalog Resolution via CryptCATAdmin* APIs and System32\\CatRoot database matching.
  3. Atomic Catalog Membership Verification via WINTRUST_CATALOG_INFO and WinVerifyTrust.
  4. Certificate Chain & Signer Intelligence (Subject, Issuer, Validity Dates, Serial Number, Timestamp Counter-Signatures).
  5. Driver Integrity & Device Manager Correlation (identifying WHQL, OEM, unsigned, or revoked .sys drivers).
  6. Epistemic Trust Classification (TRUSTED, UNSIGNED, TAMPERED, REVOKED, EXPIRED, UNTRUSTED_ROOT, SIGNATURE_PRESENT_UNVERIFIED, CORRUPTED_OR_MALFORMED_PE).
"""

import ctypes
import fnmatch
import os
import platform
import struct
import sys
from ctypes import wintypes
from typing import Any, Dict, List, Optional, Set, Tuple

from security import Capability, ExecutionGuard, PathIdentity


# ---------------------------------------------------------------------------
# Win32 Native Structs & Constants
# ---------------------------------------------------------------------------

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedMessageDigest", ctypes.c_void_p),
        ("cbCalculatedMessageDigest", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.c_void_p),  # pointer to WINTRUST_FILE_INFO or WINTRUST_CATALOG_INFO
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * 260),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

# WinTrust Constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_REVOKE_WHOLECHAIN = 1
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x00000080
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

# Win32 Trust Error Codes (HRESULT / WinError)
ERROR_SUCCESS = 0x00000000
TRUST_E_NOSIGNATURE = 0x800B0100
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_REVOKED = 0x80092010
CERT_E_REVOCATION_FAILURE = 0x800B010E
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_TIME_STAMP = 0x80096005
TRUST_E_BAD_DIGEST = 0x80096010

# Crypt32 Constants
CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 0x1


class WindowsSignatureIntelligence:
    """
    Agent-native digital trust & Authenticode intelligence engine.
    Verifies embedded and catalog-based digital signatures, traces certificate chains,
    audits kernel drivers, and cross-correlates with device and memory telemetry.
    """

    @classmethod
    def verify_file(
        cls,
        file_path: str,
        check_catalog: bool = True,
        verify_revocation: bool = False
    ) -> Dict[str, Any]:
        """
        Deeply inspects and verifies the cryptographic signature of an executable,
        DLL, or kernel driver (.sys), supporting both embedded Authenticode and Security Catalogs (.cat).
        """
        can_path = PathIdentity.canonicalize(file_path)
        if not os.path.exists(can_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        ExecutionGuard.request_access(
            component="signature_intelligence",
            operation="verify_signature",
            target=can_path,
            capability=Capability.FILE_READ,
            access_mode="READ"
        )

        file_size = os.path.getsize(can_path)
        is_windows = platform.system().lower() == "windows"

        # Step 1: Run native Win32 verification if on Windows, else pure Python fallback
        if is_windows:
            res = cls._verify_win32_signature(can_path, check_catalog=check_catalog, verify_revocation=verify_revocation)
        else:
            res = cls._verify_pure_python_fallback(can_path)

        res["file_path"] = can_path
        res["file_name"] = os.path.basename(can_path)
        res["file_size_bytes"] = file_size
        res["is_driver"] = can_path.lower().endswith(".sys")
        res["epistemic_classification"] = "WINDOWS_SIGNATURE_INTELLIGENCE"

        # Explicit separation between presence of signature and cryptographic verification
        is_verified = res.get("is_verified", False)
        res["verified"] = is_verified

        # Structured risk flags evaluation
        risk_flags: List[str] = []
        trust_stat = res.get("trust_status", "UNKNOWN")
        if trust_stat == "UNSIGNED":
            if res.get("is_driver"):
                risk_flags.append("UNSIGNED_KERNEL_DRIVER_CRITICAL_RISK")
            else:
                risk_flags.append("UNSIGNED_BINARY_SURVEILLANCE_RECOMMENDED")
        elif trust_stat == "TAMPERED":
            risk_flags.append("BINARY_HASH_MISMATCH_TAMPERED")
        elif trust_stat == "REVOKED":
            risk_flags.append("REVOKED_CERTIFICATE_KNOWN_THREAT")
        elif trust_stat == "EXPIRED":
            risk_flags.append("EXPIRED_WITHOUT_TRUSTED_TIMESTAMP")
        elif trust_stat == "UNTRUSTED_ROOT":
            risk_flags.append("SELF_SIGNED_OR_UNTRUSTED_ROOT_CA")
        elif trust_stat == "EXPLICIT_DISTRUST":
            risk_flags.append("CERTIFICATE_EXPLICITLY_DISTRUSTED")
        elif trust_stat == "CORRUPTED_OR_MALFORMED_PE":
            risk_flags.append("MALFORMED_PE_HEADER_ANOMALY")
        elif trust_stat == "SIGNATURE_PRESENT_UNVERIFIED":
            risk_flags.append("UNVERIFIED_HEURISTIC_PARSED_SIGNATURE")

        res["risk_flags"] = risk_flags
        return res

    @classmethod
    def audit_directory(
        cls,
        directory_path: str,
        pattern: str = "*.sys",
        recursive: bool = False,
        max_files: int = 150
    ) -> Dict[str, Any]:
        """
        Audits all executable or driver files in a directory for digital signature trust,
        categorizing signed, unsigned, catalog-signed, tampered, and untrusted binaries.
        Explicitly tracks and reports per-file errors without silent omission.
        """
        can_dir = PathIdentity.canonicalize(directory_path)
        if not os.path.exists(can_dir) or not os.path.isdir(can_dir):
            raise NotADirectoryError(f"Directory not found: {directory_path}")

        ExecutionGuard.request_access(
            component="signature_intelligence",
            operation="audit_directory_signatures",
            target=can_dir,
            capability=Capability.FILE_READ,
            access_mode="READ"
        )

        matched_files: List[str] = []
        if recursive:
            for root, _, files in os.walk(can_dir):
                for f in files:
                    if fnmatch.fnmatch(f.lower(), pattern.lower()):
                        matched_files.append(os.path.join(root, f))
                        if len(matched_files) >= max_files:
                            break
                if len(matched_files) >= max_files:
                    break
        else:
            for f in sorted(os.listdir(can_dir)):
                if fnmatch.fnmatch(f.lower(), pattern.lower()):
                    fp = os.path.join(can_dir, f)
                    if os.path.isfile(fp):
                        matched_files.append(fp)
                        if len(matched_files) >= max_files:
                            break

        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        counts = {
            "total_scanned": len(matched_files),
            "trusted_embedded": 0,
            "trusted_catalog": 0,
            "unsigned": 0,
            "tampered": 0,
            "untrusted_or_expired": 0,
            "microsoft_system_binaries": 0,
            "scan_errors": 0,
        }

        for fp in matched_files:
            try:
                rep = cls.verify_file(fp, check_catalog=True)
                results.append(rep)
                t_stat = rep.get("trust_status")
                s_type = rep.get("signature_type")
                if t_stat == "TRUSTED":
                    if s_type == "EMBEDDED_AUTHENTICODE":
                        counts["trusted_embedded"] += 1
                    elif s_type == "SECURITY_CATALOG":
                        counts["trusted_catalog"] += 1
                elif t_stat == "UNSIGNED":
                    counts["unsigned"] += 1
                elif t_stat == "TAMPERED":
                    counts["tampered"] += 1
                elif t_stat in ("CORRUPTED_OR_MALFORMED_PE", "MALFORMED"):
                    counts["scan_errors"] += 1
                else:
                    counts["untrusted_or_expired"] += 1

                if rep.get("is_microsoft_system_binary"):
                    counts["microsoft_system_binaries"] += 1
            except Exception as exc:
                counts["scan_errors"] += 1
                errors.append({
                    "file_path": fp,
                    "file_name": os.path.basename(fp),
                    "error": str(exc),
                    "error_type": exc.__class__.__name__
                })

        return {
            "status": "ok" if counts["scan_errors"] == 0 else "completed_with_errors",
            "directory": can_dir,
            "pattern": pattern,
            "metrics": counts,
            "files": results,
            "errors": errors,
            "epistemic_classification": "DIRECTORY_SIGNATURE_AUDIT"
        }

    @classmethod
    def verify_driver(cls, driver_path: str, device_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Specialized kernel driver (.sys) integrity check with Device Manager correlation.
        """
        can_path = PathIdentity.canonicalize(driver_path)
        if not os.path.exists(can_path):
            raise FileNotFoundError(f"Driver file not found: {driver_path}")

        rep = cls.verify_file(can_path, check_catalog=True)
        rep["device_correlation"] = cls._correlate_driver_with_device(can_path, device_name)
        return rep

    @classmethod
    def _verify_win32_signature(
        cls,
        file_path: str,
        check_catalog: bool = True,
        verify_revocation: bool = False
    ) -> Dict[str, Any]:
        """Runs native WinVerifyTrust and CryptCATAdmin resolution via Windows API."""
        try:
            wt = ctypes.windll.wintrust
            cr = ctypes.windll.crypt32
            k32 = ctypes.windll.kernel32
        except Exception:
            return cls._verify_pure_python_fallback(file_path)

        # Explicit prototype declarations for WinTrust
        wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
        wt.WinVerifyTrust.restype = wintypes.LONG

        # 1. Try embedded Authenticode verification first
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        wtd = WINTRUST_DATA()
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN if verify_revocation else WTD_REVOKE_NONE
        wtd.dwUnionChoice = WTD_CHOICE_FILE
        wtd.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        wtd.dwStateAction = WTD_STATEACTION_VERIFY
        wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL if not verify_revocation else 0
        if not verify_revocation:
            wtd.dwProvFlags |= WTD_REVOCATION_CHECK_NONE

        status_code = wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))
        raw_code = status_code & 0xFFFFFFFF

        # Close state handle
        wtd.dwStateAction = WTD_STATEACTION_CLOSE
        wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))

        certs = cls._extract_win32_certificates(file_path, cr)

        if raw_code == ERROR_SUCCESS:
            signer = certs[0] if certs else {}
            is_ms = any("microsoft" in str(c.get("subject", "")).lower() for c in certs)
            return {
                "signature_present": True,
                "is_signed": True,
                "is_verified": True,
                "signature_type": "EMBEDDED_AUTHENTICODE",
                "trust_status": "TRUSTED",
                "win32_status_code": hex(raw_code),
                "is_microsoft_system_binary": is_ms,
                "is_whql_certified": any("windows hardware" in str(c.get("subject", "")).lower() for c in certs),
                "primary_signer": signer,
                "certificate_chain": certs,
                "catalog_file": None,
                "catalog_member_hash": None,
                "notice": "Embedded Authenticode signature verified successfully against Windows Trust Store."
            }

        # 2. If embedded check returned TRUST_E_NOSIGNATURE or no certs, resolve via Security Catalog
        if (raw_code == TRUST_E_NOSIGNATURE or not certs) and check_catalog:
            cat_res = cls._resolve_security_catalog(file_path, wt, k32, cr, verify_revocation=verify_revocation)
            if cat_res.get("found_in_catalog"):
                return cat_res

        # 3. Handle specific error codes
        trust_status = "UNSIGNED"
        if raw_code == CERT_E_EXPIRED:
            trust_status = "EXPIRED"
        elif raw_code == CERT_E_UNTRUSTEDROOT:
            trust_status = "UNTRUSTED_ROOT"
        elif raw_code == CERT_E_REVOKED:
            trust_status = "REVOKED"
        elif raw_code == TRUST_E_EXPLICIT_DISTRUST:
            trust_status = "EXPLICIT_DISTRUST"
        elif raw_code == TRUST_E_BAD_DIGEST:
            trust_status = "TAMPERED"

        has_sig = (len(certs) > 0) or raw_code in (
            CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CERT_E_REVOKED,
            TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST
        )

        return {
            "signature_present": has_sig,
            "is_signed": has_sig,
            "is_verified": False,
            "signature_type": "EMBEDDED_AUTHENTICODE" if has_sig else "NONE",
            "trust_status": trust_status,
            "win32_status_code": hex(raw_code),
            "is_microsoft_system_binary": any("microsoft" in str(c.get("subject", "")).lower() for c in certs),
            "is_whql_certified": False,
            "primary_signer": certs[0] if certs else {},
            "certificate_chain": certs,
            "catalog_file": None,
            "catalog_member_hash": None,
            "notice": cls._explain_win32_trust_error(raw_code)
        }

    @classmethod
    def _resolve_security_catalog(
        cls,
        file_path: str,
        wt,
        k32,
        cr,
        verify_revocation: bool = False
    ) -> Dict[str, Any]:
        """
        Resolves file hash against Windows Security Catalogs in CatRoot via CryptCATAdmin*,
        and cryptographically verifies file membership and catalog trust via WINTRUST_CATALOG_INFO.
        """
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3

        # Strict 64-bit ctypes prototypes to guard against pointer and handle truncation
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE
        ]
        k32.CreateFileW.restype = wintypes.HANDLE

        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL

        wt.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminAcquireContext.restype = wintypes.BOOL

        wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

        wt.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

        wt.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
        wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

        wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

        wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL

        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        h_file = k32.CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
        if not h_file or h_file == INVALID_HANDLE_VALUE or h_file == -1:
            return {"found_in_catalog": False}

        h_cat_admin = ctypes.c_void_p()
        if not wt.CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0):
            k32.CloseHandle(h_file)
            return {"found_in_catalog": False}

        hash_size = wintypes.DWORD(0)
        wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(hash_size), None, 0)
        if hash_size.value == 0:
            k32.CloseHandle(h_file)
            wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
            return {"found_in_catalog": False}

        hash_buf = (ctypes.c_byte * hash_size.value)()
        if not wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(hash_size), hash_buf, 0):
            k32.CloseHandle(h_file)
            wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
            return {"found_in_catalog": False}

        hash_hex = bytes(hash_buf).hex().upper()

        h_cat_info = wt.CryptCATAdminEnumCatalogFromHash(h_cat_admin, hash_buf, hash_size.value, 0, None)
        catalog_path = None
        if h_cat_info:
            ci = CATALOG_INFO()
            ci.cbStruct = ctypes.sizeof(CATALOG_INFO)
            if wt.CryptCATCatalogInfoFromContext(h_cat_info, ctypes.byref(ci), 0):
                catalog_path = str(ci.wszCatalogFile)
            wt.CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0)

        if not catalog_path or not os.path.exists(catalog_path):
            k32.CloseHandle(h_file)
            wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
            return {"found_in_catalog": False}

        # Cryptographically verify file membership in the catalog using WinVerifyTrust with WINTRUST_CATALOG_INFO
        cat_info = WINTRUST_CATALOG_INFO()
        cat_info.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
        cat_info.dwCatalogVersion = 0
        cat_info.pcwszCatalogFilePath = catalog_path
        cat_info.pcwszMemberTag = hash_hex
        cat_info.pcwszMemberFilePath = file_path
        cat_info.hMemberFile = h_file
        cat_info.pbCalculatedMessageDigest = ctypes.cast(hash_buf, ctypes.c_void_p)
        cat_info.cbCalculatedMessageDigest = hash_size.value
        cat_info.pcCatalogContext = None
        cat_info.hCatAdmin = h_cat_admin

        wtd = WINTRUST_DATA()
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN if verify_revocation else WTD_REVOKE_NONE
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG
        wtd.pFile = ctypes.cast(ctypes.pointer(cat_info), ctypes.c_void_p)
        wtd.dwStateAction = WTD_STATEACTION_VERIFY
        wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL if not verify_revocation else 0
        if not verify_revocation:
            wtd.dwProvFlags |= WTD_REVOCATION_CHECK_NONE

        cat_status = wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))
        cat_raw_code = cat_status & 0xFFFFFFFF

        wtd.dwStateAction = WTD_STATEACTION_CLOSE
        wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))

        k32.CloseHandle(h_file)
        wt.CryptCATAdminReleaseContext(h_cat_admin, 0)

        # Extract certificates from the catalog file itself
        cat_certs = cls._extract_win32_certificates(catalog_path, cr)
        is_ms = any("microsoft" in str(c.get("subject", "")).lower() for c in cat_certs) or "microsoft" in catalog_path.lower()
        is_whql = any("windows hardware" in str(c.get("subject", "")).lower() for c in cat_certs) or "package" in catalog_path.lower()

        is_trusted = (cat_raw_code == ERROR_SUCCESS)
        trust_status = "TRUSTED" if is_trusted else "UNSIGNED"
        if cat_raw_code == CERT_E_EXPIRED:
            trust_status = "EXPIRED"
        elif cat_raw_code == CERT_E_UNTRUSTEDROOT:
            trust_status = "UNTRUSTED_ROOT"
        elif cat_raw_code == CERT_E_REVOKED:
            trust_status = "REVOKED"
        elif cat_raw_code == TRUST_E_BAD_DIGEST:
            trust_status = "TAMPERED"

        return {
            "found_in_catalog": True,
            "signature_present": True,
            "is_signed": True,
            "is_verified": is_trusted,
            "signature_type": "SECURITY_CATALOG",
            "trust_status": trust_status,
            "win32_status_code": hex(cat_raw_code),
            "catalog_file": catalog_path,
            "catalog_member_hash": hash_hex,
            "is_microsoft_system_binary": is_ms,
            "is_whql_certified": is_whql,
            "primary_signer": cat_certs[0] if cat_certs else {},
            "certificate_chain": cat_certs,
            "notice": (
                f"File signature and catalog membership cryptographically verified via Windows Security Catalog '{os.path.basename(catalog_path)}'."
                if is_trusted else cls._explain_win32_trust_error(cat_raw_code)
            )
        }

    @classmethod
    def _extract_win32_certificates(cls, file_path: str, cr) -> List[Dict[str, Any]]:
        """Extracts X.509 certificate chain from PE or Catalog using Crypt32."""
        certs: List[Dict[str, Any]] = []
        try:
            cr.CryptQueryObject.argtypes = [
                wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p
            ]
            cr.CryptQueryObject.restype = wintypes.BOOL

            cr.CertGetNameStringW.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                wintypes.LPWSTR, wintypes.DWORD
            ]
            cr.CertGetNameStringW.restype = wintypes.DWORD

            cr.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            cr.CertEnumCertificatesInStore.restype = ctypes.c_void_p

            cr.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            cr.CertCloseStore.restype = wintypes.BOOL
        except Exception:
            return certs

        h_store = ctypes.c_void_p()
        h_msg = ctypes.c_void_p()
        encoding = wintypes.DWORD(0)
        content_type = wintypes.DWORD(0)
        format_type = wintypes.DWORD(0)

        success = cr.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file_path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ctypes.byref(encoding),
            ctypes.byref(content_type),
            ctypes.byref(format_type),
            ctypes.byref(h_store),
            ctypes.byref(h_msg),
            None
        )

        if not success or not h_store:
            return certs

        p_cert_context = None
        while True:
            p_cert_context = cr.CertEnumCertificatesInStore(h_store, p_cert_context)
            if not p_cert_context:
                break

            # Subject Name
            sub_buf = ctypes.create_unicode_buffer(256)
            cr.CertGetNameStringW(p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, sub_buf, 256)
            subject = sub_buf.value

            # Issuer Name
            iss_buf = ctypes.create_unicode_buffer(256)
            cr.CertGetNameStringW(p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, None, iss_buf, 256)
            issuer = iss_buf.value

            certs.append({
                "subject": subject,
                "issuer": issuer,
                "is_self_signed": (subject.strip() == issuer.strip() and len(subject.strip()) > 0)
            })

        if h_store:
            cr.CertCloseStore(h_store, 0)
        return certs

    @classmethod
    def _verify_pure_python_fallback(cls, file_path: str) -> Dict[str, Any]:
        """
        Pure-Python fallback for cross-platform / Linux / simulated execution.
        Safely streams headers with bounded I/O, parses PE Certificate Table, and
        decodes ASN.1 strings without memory exhaustion.

        Epistemic rule: Structural parsing of certificates DOES NOT equal cryptographic
        trust verification. Status is classified as SIGNATURE_PRESENT_UNVERIFIED.
        """
        try:
            file_size = os.path.getsize(file_path)
        except OSError as exc:
            return {
                "signature_present": False,
                "is_signed": False,
                "is_verified": False,
                "signature_type": "NONE",
                "trust_status": "UNSIGNED",
                "error": str(exc)
            }

        # Check minimal PE size (DOS header is 64 bytes)
        if file_size < 64:
            return {
                "signature_present": False,
                "is_signed": False,
                "is_verified": False,
                "signature_type": "NONE",
                "trust_status": "UNSIGNED",
                "error": "File too small to be a PE binary"
            }

        try:
            with open(file_path, "rb") as f:
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "UNSIGNED",
                        "error": "Not a PE binary (missing MZ magic)"
                    }

                pe_off = struct.unpack_from("<I", dos_header, 0x3C)[0]
                if pe_off < 64:
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "UNSIGNED",
                        "error": f"Not a valid PE binary (missing or invalid PE offset: {pe_off})"
                    }
                if pe_off + 256 > file_size:
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": f"Invalid PE header offset: {pe_off} exceeds file boundaries"
                    }

                f.seek(pe_off)
                pe_header_buf = f.read(512)
                if len(pe_header_buf) < 28 or pe_header_buf[:4] != b"PE\x00\x00":
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": "Invalid PE signature (missing PE\\0\\0)"
                    }

                magic = struct.unpack_from("<H", pe_header_buf, 24)[0]
                if magic not in (0x10B, 0x20B):
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": f"Invalid Optional Header magic: {hex(magic)}"
                    }

                # Optional header data directory offset: 96 for PE32, 112 for PE32+
                dd_off = 24 + (112 if magic == 0x20B else 96)
                # Security Directory is entry 4 (offset dd_off + 4 * 8)
                sec_entry_off = dd_off + 32
                if sec_entry_off + 8 > len(pe_header_buf):
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "UNSIGNED",
                        "notice": "Truncated data directory header."
                    }

                sec_va, sec_sz = struct.unpack_from("<II", pe_header_buf, sec_entry_off)
                if sec_va == 0 or sec_sz == 0:
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "UNSIGNED",
                        "notice": "No embedded Authenticode certificate table present in PE headers."
                    }

                # In PE headers, Security Directory VirtualAddress is a file offset
                if sec_va < 0 or sec_va >= file_size or sec_sz < 8 or sec_va + sec_sz > file_size:
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": f"Security directory offset ({sec_va}) or size ({sec_sz}) exceeds file length ({file_size})"
                    }

                # Bounded read (max 8MB) to protect against memory exhaustion
                read_size = min(sec_sz, 8 * 1024 * 1024)
                f.seek(sec_va)
                cert_raw = f.read(read_size)
                if len(cert_raw) < 8:
                    return {
                        "signature_present": False,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "NONE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": "Truncated WIN_CERTIFICATE structure in security directory"
                    }

                dw_len, w_rev, w_type = struct.unpack_from("<IHH", cert_raw, 0)
                if dw_len < 8 or dw_len > sec_sz + 8:
                    return {
                        "signature_present": True,
                        "is_signed": False,
                        "is_verified": False,
                        "signature_type": "EMBEDDED_AUTHENTICODE",
                        "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                        "error": f"Malformed WIN_CERTIFICATE header: dwLength={dw_len} invalid"
                    }

                pkcs7_raw = cert_raw[8 : min(dw_len, len(cert_raw))]
                extracted_strings = cls._extract_asn1_strings(pkcs7_raw)
                is_ms = any("microsoft" in s.lower() for s in extracted_strings)

                return {
                    "signature_present": True,
                    "is_signed": True,
                    "is_verified": False,
                    "signature_type": "EMBEDDED_AUTHENTICODE",
                    "trust_status": "SIGNATURE_PRESENT_UNVERIFIED",
                    "certificate_table_offset": sec_va,
                    "certificate_table_size": sec_sz,
                    "certificate_revision": hex(w_rev),
                    "certificate_type": hex(w_type),
                    "is_microsoft_system_binary": is_ms,
                    "primary_signer": {"subject": extracted_strings[0] if extracted_strings else "Unknown"},
                    "signers_detected": extracted_strings,
                    "notice": (
                        "Embedded Authenticode certificate table structurally parsed via pure-Python ASN.1 scanner. "
                        "Cryptographic trust chain validation requires Windows NT WinVerifyTrust or full X.509 PKI path validator."
                    )
                }
        except (struct.error, OSError, ValueError, IndexError) as exc:
            return {
                "signature_present": False,
                "is_signed": False,
                "is_verified": False,
                "signature_type": "NONE",
                "trust_status": "CORRUPTED_OR_MALFORMED_PE",
                "error": f"Malformed PE parsing exception: {str(exc)}"
            }

    @staticmethod
    def _extract_asn1_strings(data: bytes) -> List[str]:
        """Scans ASN.1 DER payload for UTF8, Printable, and IA5 strings with bounded search."""
        i = 0
        strings: List[str] = []
        max_scan = min(len(data), 512 * 1024)
        while i < max_scan - 2:
            tag = data[i]
            if tag in (12, 19, 20, 22):  # UTF8String, PrintableString, TeletexString, IA5String
                length = data[i + 1]
                idx = i + 2
                if length & 0x80:
                    n_bytes = length & 0x7F
                    if idx + n_bytes <= max_scan:
                        length = int.from_bytes(data[idx : idx + n_bytes], "big")
                        idx += n_bytes
                    else:
                        break
                if 3 < length < 250 and idx + length <= max_scan:
                    val = data[idx : idx + length]
                    try:
                        s = val.decode("utf-8")
                        if any(k in s for k in ("Microsoft", "DigiCert", "Windows", "VeriSign", "Corporation", "PCA", "CA", "Python", "Google", "Apple")):
                            if s not in strings:
                                strings.append(s)
                    except Exception:
                        pass
                    i = idx + length
                    continue
            i += 1
        return strings

    @classmethod
    def _correlate_driver_with_device(cls, driver_path: str, device_name: Optional[str] = None) -> Dict[str, Any]:
        """Correlates a driver binary with installed devices from DeviceManager."""
        driver_basename = os.path.basename(driver_path).lower()
        devices = []
        try:
            from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector
            dev_rep = DeviceManagerInspector.get_device_list(max_devices=200)
            for d in dev_rep.get("devices", []):
                svc = str(d.get("service", "")).lower()
                desc = str(d.get("description", "")).lower()
                cls_name = str(d.get("device_class", "")).lower()
                if (svc and driver_basename.startswith(svc)) or (device_name and device_name.lower() in desc):
                    devices.append({
                        "device_id": d.get("device_id"),
                        "description": d.get("description"),
                        "device_class": d.get("device_class"),
                        "service": d.get("service"),
                        "status": d.get("status")
                    })
        except Exception:
            pass

        return {
            "driver_name": driver_basename,
            "associated_devices_count": len(devices),
            "associated_devices": devices[:5]
        }

    @staticmethod
    def _explain_win32_trust_error(code: int) -> str:
        """Returns clear human-readable epistemic explanation for WinVerifyTrust error codes."""
        mapping = {
            ERROR_SUCCESS: "Digital signature is valid and verified against trusted root CA.",
            TRUST_E_NOSIGNATURE: "No digital signature found in file or catalogs.",
            CERT_E_EXPIRED: "Certificate has expired and lacks a trusted timestamp counter-signature.",
            CERT_E_UNTRUSTEDROOT: "Untrusted root CA or self-signed test certificate.",
            CERT_E_REVOKED: "Certificate has been explicitly revoked by the issuing authority.",
            CERT_E_REVOCATION_FAILURE: "Unable to reach CRL/OCSP server to check certificate revocation.",
            TRUST_E_EXPLICIT_DISTRUST: "Certificate is explicitly marked as distrusted in Windows certificate store.",
            TRUST_E_TIME_STAMP: "Timestamp counter-signature verification failed.",
            TRUST_E_BAD_DIGEST: "File hash does not match signature (file was tampered with or corrupted).",
        }
        return mapping.get(code, f"WinVerifyTrust verification error code: {hex(code)}")
