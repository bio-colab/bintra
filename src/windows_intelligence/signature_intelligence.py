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
from ctypes import wintypes
from typing import Any, Dict, List, Optional

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
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
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
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1 << 8
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 0x1

# CMS / X.509 Signer & EKU Constants
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CMSG_SIGNER_INFO_PARAM = 6
CERT_FIND_SUBJECT_CERT = 0x000B0000
ERROR_NOT_FOUND = 1168
ERROR_NO_MORE_ITEMS = 259
MAX_CATALOG_CANDIDATES = 64

# Authoritative Authenticode / WHQL / Timestamp OIDs
OID_WHQL_CRYPTO = "1.3.6.1.4.1.311.10.3.5"       # Windows Hardware Driver Verification (WHQL)
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"           # id-kp-codeSigning
OID_PKCS9_COUNTERSIGN = "1.2.840.113549.1.9.6"   # szOID_RSA_counterSign
OID_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1"  # szOID_RFC3161_counterSign


class CRYPT_INTEGER_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
    ]


class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("Parameters", CRYPT_INTEGER_BLOB),
    ]


class CRYPT_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("cValue", wintypes.DWORD),
        ("rgValue", ctypes.c_void_p),
    ]


class CRYPT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("cAttr", wintypes.DWORD),
        ("rgAttr", ctypes.POINTER(CRYPT_ATTRIBUTE)),
    ]


class CMSG_SIGNER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("Issuer", CRYPT_INTEGER_BLOB),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("EncryptedHash", CRYPT_INTEGER_BLOB),
        ("AuthAttrs", CRYPT_ATTRIBUTES),
        ("UnauthAttrs", CRYPT_ATTRIBUTES),
    ]


class CERT_INFO_MINIMAL(ctypes.Structure):
    """Minimal CERT_INFO header matching WinCrypt.h up through Subject for CERT_FIND_SUBJECT_CERT."""
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CRYPT_INTEGER_BLOB),
    ]


class CERT_CONTEXT_MINIMAL(ctypes.Structure):
    """Minimal CERT_CONTEXT header matching WinCrypt.h for time validity check."""
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.c_void_p),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


class CTL_USAGE(ctypes.Structure):
    _fields_ = [
        ("cUsageIdentifier", wintypes.DWORD),
        ("rgpszUsageIdentifier", ctypes.POINTER(ctypes.c_char_p)),
    ]


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

        # Schema-contract normalization: every verification path (unsigned, corrupt,
        # catalog-miss, early-return) MUST expose the temporal trust fields so that
        # downstream consumers (triage orchestrator, evidence graph, MCP clients)
        # can rely on a stable key contract. Values default to UNKNOWN when no
        # certificate chain could be inspected at all.
        res.setdefault("timestamp_status", "UNKNOWN")
        res.setdefault("expiration_status", "UNKNOWN")

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
            if res.get("timestamp_status") == "MISSING":
                risk_flags.append("EXPIRED_WITHOUT_TRUSTED_TIMESTAMP")
            elif res.get("timestamp_status") == "INVALID":
                risk_flags.append("EXPIRED_WITH_INVALID_TIMESTAMP")
            else:
                risk_flags.append("EXPIRED_CERTIFICATE_TIMESTAMP_UNVERIFIED")
        elif trust_stat == "INVALID_TIMESTAMP":
            risk_flags.append("INVALID_TIMESTAMP_COUNTERSIGNATURE")
        elif trust_stat == "UNTRUSTED_ROOT":
            risk_flags.append("SELF_SIGNED_OR_UNTRUSTED_ROOT_CA")
        elif trust_stat == "EXPLICIT_DISTRUST":
            risk_flags.append("CERTIFICATE_EXPLICITLY_DISTRUSTED")
        elif trust_stat == "CORRUPTED_OR_MALFORMED_PE":
            risk_flags.append("MALFORMED_PE_HEADER_ANOMALY")
        elif trust_stat == "SIGNATURE_PRESENT_UNVERIFIED":
            risk_flags.append("UNVERIFIED_HEURISTIC_PARSED_SIGNATURE")
        elif trust_stat == "REVOCATION_UNKNOWN":
            risk_flags.append("REVOCATION_CHECK_UNAVAILABLE")
        elif trust_stat == "NOT_AUTHENTICODE_FORMAT":
            risk_flags.append("NON_AUTHENTICODE_FILE_FORMAT")
        elif trust_stat == "VERIFICATION_ERROR":
            risk_flags.append("WINTRUST_VERIFICATION_ERROR")

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
            "unsupported_format": 0,
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
                elif t_stat == "NOT_AUTHENTICODE_FORMAT":
                    counts["unsupported_format"] += 1
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

        try:
            status_code = wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))
            raw_code = status_code & 0xFFFFFFFF
        finally:
            wtd.dwStateAction = WTD_STATEACTION_CLOSE
            wt.WinVerifyTrust(None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))

        sig_info = cls._extract_win32_signer_and_certificates(file_path, cr)
        certs = sig_info["certificate_chain"]
        primary_signer = sig_info["primary_signer"]
        attribution_method = sig_info["signer_attribution_method"]
        ts_eval = cls._classify_timestamp_and_expiration(
            raw_code=raw_code,
            timestamp_present=sig_info["timestamp_present"],
            cert_expired=sig_info.get("signer_cert_expired"),
        )

        if raw_code == ERROR_SUCCESS:
            signer_subj = str(primary_signer.get("subject", "")).lower()
            signer_ekus = primary_signer.get("ekus", [])
            is_ms = (attribution_method == "CMS_SIGNER_INFO_MATCH") and ("microsoft" in signer_subj)
            is_whql = (attribution_method == "CMS_SIGNER_INFO_MATCH") and (OID_WHQL_CRYPTO in signer_ekus)
            return {
                "signature_present": True,
                "is_signed": True,
                "is_verified": True,
                "signature_type": "EMBEDDED_AUTHENTICODE",
                "trust_status": "TRUSTED",
                "trust_classification": "TRUSTED_EMBEDDED",
                "win32_status_code": hex(raw_code),
                "is_microsoft_system_binary": is_ms,
                "is_whql_certified": is_whql,
                "signer_attribution_method": attribution_method,
                "primary_signer": primary_signer,
                "certificate_chain": certs,
                "timestamp_present": sig_info["timestamp_present"],
                "timestamp_status": ts_eval["timestamp_status"],
                "expiration_status": ts_eval["expiration_status"],
                "catalog_file": None,
                "catalog_member_hash": None,
                "notice": "Embedded Authenticode signature verified successfully against Windows Trust Store."
            }

        # 2. If embedded check returned TRUST_E_NOSIGNATURE or no certs, resolve via Security Catalog
        if (raw_code == TRUST_E_NOSIGNATURE or not certs) and check_catalog:
            cat_res = cls._resolve_security_catalog(file_path, wt, k32, cr, verify_revocation=verify_revocation)
            if cat_res.get("found_in_catalog"):
                return cat_res

        # 3. Handle specific error codes without misclassifying unknown/revocation errors as UNSIGNED
        trust_status = cls._classify_win32_trust_status(raw_code)

        has_sig = (len(certs) > 0) or raw_code in (
            CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CERT_E_REVOKED,
            CERT_E_REVOCATION_FAILURE, TRUST_E_TIME_STAMP,
            TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST
        )

        return {
            "signature_present": has_sig,
            "is_signed": has_sig,
            "is_verified": False,
            "signature_type": "EMBEDDED_AUTHENTICODE" if has_sig else "NONE",
            "trust_status": trust_status,
            "trust_classification": trust_status,
            "win32_status_code": hex(raw_code),
            "is_microsoft_system_binary": False,
            "is_whql_certified": False,
            "signer_attribution_method": attribution_method,
            "primary_signer": primary_signer,
            "certificate_chain": certs,
            "timestamp_present": sig_info["timestamp_present"],
            "timestamp_status": ts_eval["timestamp_status"],
            "expiration_status": ts_eval["expiration_status"],
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

        wt.CryptCATAdminEnumCatalogFromHash.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
        ]
        wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

        wt.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
        wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

        wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

        wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL

        has_sha256_api = (
            hasattr(wt, "CryptCATAdminAcquireContext2")
            and hasattr(wt, "CryptCATAdminCalcHashFromFileHandle2")
        )
        if has_sha256_api:
            wt.CryptCATAdminAcquireContext2.argtypes = [
                ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD
            ]
            wt.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
            wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
                ctypes.c_void_p, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD
            ]
            wt.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL

        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        h_file = k32.CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
        if not h_file or h_file == INVALID_HANDLE_VALUE or h_file == -1:
            return {"found_in_catalog": False, "catalog_enumeration_complete": False, "catalog_error": "CreateFileW failed"}

        selected_catalog_path: Optional[str] = None
        selected_raw_code: int = TRUST_E_NOSIGNATURE
        selected_hash_hex: str = ""
        selected_algo: str = "SHA1"
        candidates_checked: List[Dict[str, Any]] = []
        enumeration_complete = True
        enumeration_error: Optional[int] = None

        algos_to_try = (["SHA256", "SHA1"] if has_sha256_api else ["SHA1"])

        try:
            for algo in algos_to_try:
                h_cat_admin = ctypes.c_void_p()
                cat_admin_acquired = False
                active_cat_ctx = None
                try:
                    if algo == "SHA256":
                        ok_ctx = wt.CryptCATAdminAcquireContext2(ctypes.byref(h_cat_admin), None, "SHA256", None, 0)
                    else:
                        ok_ctx = wt.CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0)
                    if not ok_ctx:
                        continue
                    cat_admin_acquired = True

                    hash_size = wintypes.DWORD(0)
                    if algo == "SHA256":
                        wt.CryptCATAdminCalcHashFromFileHandle2(h_cat_admin, h_file, ctypes.byref(hash_size), None, 0)
                    else:
                        wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(hash_size), None, 0)
                    if hash_size.value == 0:
                        continue

                    hash_buf = (wintypes.BYTE * hash_size.value)()
                    if algo == "SHA256":
                        ok_hash = wt.CryptCATAdminCalcHashFromFileHandle2(
                            h_cat_admin, h_file, ctypes.byref(hash_size), hash_buf, 0
                        )
                    else:
                        ok_hash = wt.CryptCATAdminCalcHashFromFileHandle(
                            h_file, ctypes.byref(hash_size), hash_buf, 0
                        )
                    if not ok_hash:
                        continue

                    hash_hex = bytes(hash_buf).hex().upper()

                    # Enumerate ALL matching catalogs by advancing phPrevCatInfo
                    prev_cat = ctypes.c_void_p(0)
                    for _ in range(MAX_CATALOG_CANDIDATES):
                        h_cat_info = wt.CryptCATAdminEnumCatalogFromHash(
                            h_cat_admin, hash_buf, hash_size.value, 0, ctypes.byref(prev_cat)
                        )
                        if not h_cat_info:
                            # Previous context (if any) was released by EnumCatalogFromHash
                            active_cat_ctx = None
                            last_err = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
                            if last_err not in (0, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS):
                                enumeration_complete = False
                                enumeration_error = last_err
                            break

                        active_cat_ctx = h_cat_info
                        prev_cat = ctypes.c_void_p(h_cat_info)

                        ci = CATALOG_INFO()
                        ci.cbStruct = ctypes.sizeof(CATALOG_INFO)
                        cat_path = None
                        if wt.CryptCATCatalogInfoFromContext(h_cat_info, ctypes.byref(ci), 0):
                            cat_path = str(ci.wszCatalogFile)

                        if not cat_path or not os.path.exists(cat_path):
                            candidates_checked.append({
                                "catalog_file": cat_path,
                                "hash_algorithm": algo,
                                "exists_on_disk": False,
                                "is_verified": False,
                                "trust_status": "VERIFICATION_ERROR",
                            })
                            continue

                        # Cryptographically verify file membership and catalog signature via WinVerifyTrust
                        cat_info = WINTRUST_CATALOG_INFO()
                        cat_info.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                        cat_info.dwCatalogVersion = 0
                        cat_info.pcwszCatalogFilePath = cat_path
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

                        try:
                            cat_status = wt.WinVerifyTrust(
                                None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd)
                            )
                            cand_raw_code = cat_status & 0xFFFFFFFF
                        finally:
                            wtd.dwStateAction = WTD_STATEACTION_CLOSE
                            wt.WinVerifyTrust(
                                None, ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd)
                            )

                        cand_status = cls._classify_win32_trust_status(cand_raw_code)
                        cand_verified = (cand_raw_code == ERROR_SUCCESS)
                        candidates_checked.append({
                            "catalog_file": cat_path,
                            "hash_algorithm": algo,
                            "exists_on_disk": True,
                            "win32_status_code": hex(cand_raw_code),
                            "trust_status": cand_status,
                            "is_verified": cand_verified,
                        })

                        if selected_catalog_path is None or cand_verified:
                            selected_catalog_path = cat_path
                            selected_raw_code = cand_raw_code
                            selected_hash_hex = hash_hex
                            selected_algo = algo

                        if cand_verified:
                            # Trusted catalog found; release active context and stop enumeration
                            wt.CryptCATAdminReleaseCatalogContext(h_cat_admin, active_cat_ctx, 0)
                            active_cat_ctx = None
                            break
                    else:
                        enumeration_complete = False
                finally:
                    if active_cat_ctx is not None and cat_admin_acquired:
                        wt.CryptCATAdminReleaseCatalogContext(h_cat_admin, active_cat_ctx, 0)
                    if cat_admin_acquired:
                        wt.CryptCATAdminReleaseContext(h_cat_admin, 0)

                if selected_raw_code == ERROR_SUCCESS:
                    break
        finally:
            k32.CloseHandle(h_file)

        if not selected_catalog_path:
            return {
                "found_in_catalog": False,
                "catalog_membership_found": False,
                "catalog_verified": False,
                "catalog_candidates_checked": len(candidates_checked),
                "catalog_candidates": candidates_checked,
                "catalog_enumeration_complete": enumeration_complete,
                "catalog_enumeration_error": hex(enumeration_error) if enumeration_error else None,
            }

        # Extract CMS signer & certificate chain from the selected catalog file
        sig_info = cls._extract_win32_signer_and_certificates(selected_catalog_path, cr)
        cat_certs = sig_info["certificate_chain"]
        primary_signer = sig_info["primary_signer"]
        attribution_method = sig_info["signer_attribution_method"]
        ts_eval = cls._classify_timestamp_and_expiration(
            raw_code=selected_raw_code,
            timestamp_present=sig_info["timestamp_present"],
            cert_expired=sig_info.get("signer_cert_expired"),
        )

        is_trusted = (selected_raw_code == ERROR_SUCCESS)
        signer_subj = str(primary_signer.get("subject", "")).lower()
        signer_ekus = primary_signer.get("ekus", [])
        is_ms = is_trusted and (attribution_method == "CMS_SIGNER_INFO_MATCH") and ("microsoft" in signer_subj)
        is_whql = is_trusted and (attribution_method == "CMS_SIGNER_INFO_MATCH") and (OID_WHQL_CRYPTO in signer_ekus)

        trust_status = cls._classify_win32_trust_status(selected_raw_code)
        trust_classification = "TRUSTED_CATALOG" if is_trusted else trust_status

        return {
            "found_in_catalog": True,
            "catalog_membership_found": True,
            "catalog_verified": is_trusted,
            "catalog_hash_algorithm": selected_algo,
            "catalog_candidates_checked": len(candidates_checked),
            "catalog_candidates": candidates_checked,
            "catalog_enumeration_complete": enumeration_complete,
            "catalog_enumeration_error": hex(enumeration_error) if enumeration_error else None,
            "signature_present": True,
            "is_signed": True,
            "is_verified": is_trusted,
            "signature_type": "SECURITY_CATALOG",
            "trust_status": trust_status,
            "trust_classification": trust_classification,
            "win32_status_code": hex(selected_raw_code),
            "catalog_file": selected_catalog_path,
            "catalog_member_hash": selected_hash_hex,
            "is_microsoft_system_binary": is_ms,
            "is_whql_certified": is_whql,
            "signer_attribution_method": attribution_method,
            "primary_signer": primary_signer,
            "certificate_chain": cat_certs,
            "timestamp_present": sig_info["timestamp_present"],
            "timestamp_status": ts_eval["timestamp_status"],
            "expiration_status": ts_eval["expiration_status"],
            "notice": (
                f"File signature and catalog membership cryptographically verified via Windows Security Catalog '{os.path.basename(selected_catalog_path)}'."
                if is_trusted else cls._explain_win32_trust_error(selected_raw_code)
            )
        }

    @classmethod
    def _extract_cert_ekus(cls, p_cert_context: Any, cr: Any) -> List[str]:
        """Extracts Enhanced Key Usage (EKU) OIDs from a PCCERT_CONTEXT via CertGetEnhancedKeyUsage."""
        ekus: List[str] = []
        if not hasattr(cr, "CertGetEnhancedKeyUsage"):
            return ekus
        try:
            cr.CertGetEnhancedKeyUsage.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
            ]
            cr.CertGetEnhancedKeyUsage.restype = wintypes.BOOL
            cb_usage = wintypes.DWORD(0)
            if not cr.CertGetEnhancedKeyUsage(p_cert_context, 0, None, ctypes.byref(cb_usage)) or cb_usage.value == 0:
                return ekus
            buf = ctypes.create_string_buffer(cb_usage.value)
            if not cr.CertGetEnhancedKeyUsage(p_cert_context, 0, buf, ctypes.byref(cb_usage)):
                return ekus
            usage = CTL_USAGE.from_buffer(buf)
            for idx in range(min(usage.cUsageIdentifier, 64)):
                oid_raw = usage.rgpszUsageIdentifier[idx]
                if oid_raw:
                    ekus.append(oid_raw.decode("ascii", errors="replace"))
        except Exception:
            pass
        return ekus

    @classmethod
    def _extract_win32_signer_and_certificates(cls, file_path: str, cr: Any) -> Dict[str, Any]:
        """
        Extracts the CMS SignerInfo-attributed signer certificate, certificate store entries,
        EKU OIDs (including WHQL), and counter-signature timestamp presence via Crypt32.
        Never selects an arbitrary store certificate as primary_signer.
        """
        certs: List[Dict[str, Any]] = []
        primary_signer: Dict[str, Any] = {}
        signer_attribution_method = "UNRESOLVED_STORE_ONLY"
        timestamp_present: Optional[bool] = None
        signer_cert_expired: Optional[bool] = None

        try:
            cr.CryptQueryObject.argtypes = [
                wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
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

            if hasattr(cr, "CryptMsgClose"):
                cr.CryptMsgClose.argtypes = [ctypes.c_void_p]
                cr.CryptMsgClose.restype = wintypes.BOOL
        except Exception:
            return {
                "primary_signer": primary_signer,
                "signer_attribution_method": signer_attribution_method,
                "certificate_chain": certs,
                "timestamp_present": timestamp_present,
                "signer_cert_expired": None,
            }

        h_store = ctypes.c_void_p()
        h_msg = ctypes.c_void_p()
        encoding = wintypes.DWORD(0)
        content_type = wintypes.DWORD(0)
        format_type = wintypes.DWORD(0)

        success = cr.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file_path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ctypes.byref(encoding),
            ctypes.byref(content_type),
            ctypes.byref(format_type),
            ctypes.byref(h_store),
            ctypes.byref(h_msg),
            None
        )

        def _read_cert_entry(p_ctx: Any, role: str = "STORE_CERT") -> Dict[str, Any]:
            sub_buf = ctypes.create_unicode_buffer(256)
            cr.CertGetNameStringW(p_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, sub_buf, 256)
            subject = sub_buf.value

            iss_buf = ctypes.create_unicode_buffer(256)
            cr.CertGetNameStringW(p_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, None, iss_buf, 256)
            issuer = iss_buf.value

            is_self = (subject.strip() == issuer.strip() and len(subject.strip()) > 0)
            ekus = cls._extract_cert_ekus(p_ctx, cr)
            return {
                "subject": subject,
                "issuer": issuer,
                "is_self_signed": is_self,
                "role": "SELF_SIGNED_ROOT" if (role != "SIGNER" and is_self) else role,
                "ekus": ekus,
                "has_whql_eku": OID_WHQL_CRYPTO in ekus,
                "has_code_signing_eku": OID_CODE_SIGNING in ekus,
            }

        try:
            if not success or not h_store.value:
                return {
                    "primary_signer": primary_signer,
                    "signer_attribution_method": signer_attribution_method,
                    "certificate_chain": certs,
                    "timestamp_present": timestamp_present,
                    "signer_cert_expired": None,
                }

            # 1. Resolve actual CMS SignerInfo certificate and counter-signature attributes
            if h_msg.value and hasattr(cr, "CryptMsgGetParam"):
                try:
                    cr.CryptMsgGetParam.argtypes = [
                        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
                    ]
                    cr.CryptMsgGetParam.restype = wintypes.BOOL
                    cb_signer = wintypes.DWORD(0)
                    if cr.CryptMsgGetParam(h_msg, CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(cb_signer)) and cb_signer.value >= ctypes.sizeof(CMSG_SIGNER_INFO):
                        si_buf = ctypes.create_string_buffer(cb_signer.value)
                        if cr.CryptMsgGetParam(h_msg, CMSG_SIGNER_INFO_PARAM, 0, si_buf, ctypes.byref(cb_signer)):
                            signer_info = CMSG_SIGNER_INFO.from_buffer(si_buf)

                            # Inspect UnauthAttrs for PKCS#9 or RFC 3161 timestamp counter-signatures
                            ts_found = False
                            unauth_count = min(signer_info.UnauthAttrs.cAttr, 64)
                            if signer_info.UnauthAttrs.rgAttr:
                                for a_idx in range(unauth_count):
                                    attr_oid_raw = signer_info.UnauthAttrs.rgAttr[a_idx].pszObjId
                                    if attr_oid_raw:
                                        attr_oid = attr_oid_raw.decode("ascii", errors="replace")
                                        if attr_oid in (OID_PKCS9_COUNTERSIGN, OID_RFC3161_TIMESTAMP):
                                            ts_found = True
                                            break
                            timestamp_present = ts_found

                            # Match signer certificate in store via Issuer + SerialNumber
                            if hasattr(cr, "CertFindCertificateInStore"):
                                cr.CertFindCertificateInStore.argtypes = [
                                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p, ctypes.c_void_p
                                ]
                                cr.CertFindCertificateInStore.restype = ctypes.c_void_p
                                target_ci = CERT_INFO_MINIMAL()
                                target_ci.Issuer = signer_info.Issuer
                                target_ci.SerialNumber = signer_info.SerialNumber
                                p_signer_ctx = cr.CertFindCertificateInStore(
                                    h_store,
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    0,
                                    CERT_FIND_SUBJECT_CERT,
                                    ctypes.byref(target_ci),
                                    None,
                                )
                                if p_signer_ctx:
                                    try:
                                        primary_signer = _read_cert_entry(p_signer_ctx, role="SIGNER")
                                        signer_attribution_method = "CMS_SIGNER_INFO_MATCH"
                                        if hasattr(cr, "CertVerifyTimeValidity"):
                                            cr.CertVerifyTimeValidity.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                                            cr.CertVerifyTimeValidity.restype = wintypes.LONG
                                            ctx_struct = CERT_CONTEXT_MINIMAL.from_address(p_signer_ctx)
                                            if ctx_struct.pCertInfo:
                                                time_res = cr.CertVerifyTimeValidity(None, ctx_struct.pCertInfo)
                                                signer_cert_expired = bool(time_res == 1)
                                                primary_signer["is_expired"] = signer_cert_expired
                                    finally:
                                        if hasattr(cr, "CertFreeCertificateContext"):
                                            cr.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
                                            cr.CertFreeCertificateContext.restype = wintypes.BOOL
                                            cr.CertFreeCertificateContext(p_signer_ctx)
                except Exception:
                    pass

            # 2. Enumerate all certificates in store for chain visibility
            p_cert_context = None
            while True:
                p_cert_context = cr.CertEnumCertificatesInStore(h_store, p_cert_context)
                if not p_cert_context:
                    break
                entry = _read_cert_entry(p_cert_context, role="INTERMEDIATE_OR_CHAIN")
                if primary_signer and entry["subject"] == primary_signer.get("subject") and entry["issuer"] == primary_signer.get("issuer"):
                    entry["role"] = "SIGNER"
                certs.append(entry)
        finally:
            if h_store.value:
                cr.CertCloseStore(h_store, 0)
            if h_msg.value and hasattr(cr, "CryptMsgClose"):
                cr.CryptMsgClose(h_msg)

        return {
            "primary_signer": primary_signer,
            "signer_attribution_method": signer_attribution_method,
            "certificate_chain": certs,
            "timestamp_present": timestamp_present,
            "signer_cert_expired": signer_cert_expired,
        }

    @classmethod
    def _extract_win32_certificates(cls, file_path: str, cr) -> List[Dict[str, Any]]:
        """Backward-compatible wrapper returning enumerated X.509 certificates from PE or Catalog."""
        return cls._extract_win32_signer_and_certificates(file_path, cr)["certificate_chain"]

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

                # Optional header NumberOfRvaAndSizes (offset 92 for PE32, 108 for PE32+)
                num_rva_off = 24 + (108 if magic == 0x20B else 92)
                if num_rva_off + 4 <= len(pe_header_buf):
                    num_rva_and_sizes = struct.unpack_from("<I", pe_header_buf, num_rva_off)[0]
                    if 0 < num_rva_and_sizes <= 4:
                        return {
                            "signature_present": False,
                            "is_signed": False,
                            "is_verified": False,
                            "signature_type": "NONE",
                            "trust_status": "UNSIGNED",
                            "notice": "PE optional header does not declare a Security Directory (NumberOfRvaAndSizes <= 4)."
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
                if dw_len < 8 or dw_len > sec_sz:
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
                    "is_microsoft_system_binary": False,
                    "is_whql_certified": False,
                    "signer_attribution_method": "UNVERIFIED_ASN1_SCAN_ONLY",
                    "primary_signer": {},
                    "timestamp_present": None,
                    "timestamp_status": "UNKNOWN",
                    "expiration_status": "UNKNOWN",
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
            # list_devices() is the real API (get_device_list never existed, so the
            # AttributeError was silently swallowed and correlation was always empty).
            dev_rep = DeviceManagerInspector.list_devices(limit=0)
            for d in dev_rep.get("devices", []):
                svc = str(d.get("service") or "").lower()
                desc = str(d.get("friendly_name") or d.get("description") or "").lower()
                if (svc and os.path.splitext(driver_basename)[0] == svc) or (device_name and device_name.lower() in desc):
                    devices.append({
                        "device_id": d.get("device_instance_id"),
                        "description": d.get("friendly_name") or d.get("description"),
                        "device_class": d.get("class"),
                        "service": d.get("service"),
                        "status": d.get("problem_name")
                    })
        except Exception:
            pass

        return {
            "driver_name": driver_basename,
            "associated_devices_count": len(devices),
            "associated_devices": devices[:5]
        }

    @staticmethod
    def _classify_win32_trust_status(raw_code: int) -> str:
        """Maps WinVerifyTrust status code to a distinct, evidence-based trust classification."""
        if raw_code == ERROR_SUCCESS:
            return "TRUSTED"
        if raw_code == TRUST_E_NOSIGNATURE:
            return "UNSIGNED"
        if raw_code == CERT_E_EXPIRED:
            return "EXPIRED"
        if raw_code == CERT_E_UNTRUSTEDROOT:
            return "UNTRUSTED_ROOT"
        if raw_code == CERT_E_REVOKED:
            return "REVOKED"
        if raw_code == CERT_E_REVOCATION_FAILURE:
            return "REVOCATION_UNKNOWN"
        if raw_code == TRUST_E_EXPLICIT_DISTRUST:
            return "EXPLICIT_DISTRUST"
        if raw_code == TRUST_E_BAD_DIGEST:
            return "TAMPERED"
        if raw_code == TRUST_E_TIME_STAMP:
            return "INVALID_TIMESTAMP"
        if raw_code == TRUST_E_SUBJECT_FORM_UNKNOWN:
            return "NOT_AUTHENTICODE_FORMAT"
        return "VERIFICATION_ERROR"

    @staticmethod
    def _classify_timestamp_and_expiration(
        raw_code: int,
        timestamp_present: Optional[bool],
        cert_expired: Optional[bool] = None,
    ) -> Dict[str, str]:
        """
        Explicitly separates certificate expiration, trusted timestamp validity,
        missing timestamps, invalid timestamps, and chain trust failures.
        """
        if raw_code == ERROR_SUCCESS:
            if cert_expired is True:
                return {
                    "timestamp_status": "VALID_TRUSTED",
                    "expiration_status": "EXPIRED_WITH_VALID_TIMESTAMP",
                }
            if timestamp_present is True:
                return {
                    "timestamp_status": "VALID_TRUSTED",
                    "expiration_status": "VALID_CURRENT",
                }
            if timestamp_present is False:
                return {
                    "timestamp_status": "MISSING",
                    "expiration_status": "VALID_CURRENT",
                }
            return {
                "timestamp_status": "UNKNOWN",
                "expiration_status": "VALID_CURRENT",
            }

        if raw_code == TRUST_E_TIME_STAMP:
            return {
                "timestamp_status": "INVALID",
                "expiration_status": "EXPIRED_INVALID_TIMESTAMP" if cert_expired else "INVALID_TIMESTAMP",
            }

        if raw_code == CERT_E_EXPIRED:
            if timestamp_present is False:
                return {
                    "timestamp_status": "MISSING",
                    "expiration_status": "EXPIRED_NO_TRUSTED_TIMESTAMP",
                }
            if timestamp_present is True:
                return {
                    "timestamp_status": "UNTRUSTED_OR_INVALID",
                    "expiration_status": "EXPIRED_INVALID_TIMESTAMP",
                }
            return {
                "timestamp_status": "UNKNOWN",
                "expiration_status": "EXPIRED_TIMESTAMP_UNKNOWN",
            }

        if raw_code in (CERT_E_UNTRUSTEDROOT, CERT_E_REVOKED, TRUST_E_EXPLICIT_DISTRUST):
            ts_stat = "PRESENT_UNVERIFIED" if timestamp_present is True else ("MISSING" if timestamp_present is False else "UNKNOWN")
            return {
                "timestamp_status": ts_stat,
                "expiration_status": "CHAIN_TRUST_FAILURE",
            }

        return {
            "timestamp_status": "PRESENT_UNVERIFIED" if timestamp_present is True else ("MISSING" if timestamp_present is False else "UNKNOWN"),
            "expiration_status": "UNKNOWN",
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
            TRUST_E_SUBJECT_FORM_UNKNOWN: "File format is not a supported Authenticode container (e.g. non-PE binary or data plugin).",
        }
        return mapping.get(code, f"WinVerifyTrust verification error code: {hex(code)}")
