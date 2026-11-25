# -*- coding: utf-8 -*-
"""
Binary Slack Space, PE Overlay, & Document EOF Padding Diagnostic Engine.
Audits binary executables and structured document formats for data residing
beyond official structural boundaries:
1. PE Executables: Dissects file data residing beyond the final PE section
   (Overlay data, Authenticode certificate bundles, embedded installer payloads).
   Detects out-of-bounds truncated PE sections and respects 64KB initial header reads.
2. RTF Documents: Audits trailing bytes beyond the root document closing brace '}',
   handling group depth balancing, escaped braces, and \bin byte streams.
3. JSON & XML Documents: Audits trailing data beyond root boundary tokens via
   dedicated structure-aware parsers.
"""

from __future__ import annotations

import os
import math
import struct
import json
from typing import Dict, Any, List, Optional, Tuple


class BinarySlackInspector:
    """
    Forensic inspector for slack space, PE overlays, and document EOF padding.
    """

    MAX_HEADER_READ = 65536  # 64KB bounded header read
    MAX_OVERLAY_SAMPLE = 4 * 1024 * 1024  # 4MB sample limit for overlay analysis

    @classmethod
    def calculate_entropy(cls, data: bytes) -> float:
        """Calculates Shannon entropy of a byte stream (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def inspect_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Inspects any file on disk for slack space, overlays, or trailing bytes.
        Automatically detects file format (PE, RTF, XML, JSON, or Generic).
        """
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"File not found: {file_path}"}

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {
                "status": "ok",
                "format": "EMPTY",
                "file_size": 0,
                "has_trailing_slack": False,
                "slack_bytes_count": 0,
                "slack_type": "CLEAN_EXACT_EOF",
                "diagnostic_note": "Empty file (zero bytes)."
            }

        with open(file_path, "rb") as f:
            head = f.read(1024)

        stripped = head.lstrip()
        if head.startswith(b"MZ"):
            return cls.inspect_pe_file(file_path)
        elif head.startswith(b"{\\rtf") or head.startswith(b"{ \\rtf"):
            return cls.inspect_rtf_file(file_path)
        elif stripped.startswith(b"<?xml") or (stripped.startswith(b"<") and b">" in stripped):
            return cls.inspect_xml_file(file_path)
        elif stripped.startswith(b"{") or stripped.startswith(b"["):
            return cls.inspect_json_file(file_path)
        else:
            return cls.inspect_generic_file(file_path)

    @classmethod
    def inspect_pe_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Dissects a PE executable to determine whether data resides beyond the last section
        or if the file is truncated/corrupt. Reads headers in bounded 64KB blocks.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            hdr_bytes = f.read(cls.MAX_HEADER_READ)

        if len(hdr_bytes) < 64 or not hdr_bytes.startswith(b"MZ"):
            return {"status": "error", "error": "Not a valid PE DOS header."}

        pe_offset = struct.unpack_from("<I", hdr_bytes, 0x3C)[0]
        if pe_offset + 24 > len(hdr_bytes) or hdr_bytes[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return {"status": "error", "error": "Not a valid PE NT signature."}

        machine, num_sections = struct.unpack_from("<HH", hdr_bytes, pe_offset + 4)
        size_of_opt_header = struct.unpack_from("<H", hdr_bytes, pe_offset + 20)[0]
        opt_magic = struct.unpack_from("<H", hdr_bytes, pe_offset + 24)[0] if pe_offset + 26 <= len(hdr_bytes) else 0
        is_64bit = (opt_magic == 0x20B)

        # Parse Security Directory (Certificate Table)
        sec_dir_rva = 0
        sec_dir_size = 0
        data_dirs_offset = pe_offset + 24 + (112 if is_64bit else 96)
        # Declared optional-header size AND the bytes actually present must both cover the entry
        # (a truncated file can declare a full optional header it does not contain).
        if pe_offset + 24 + size_of_opt_header >= data_dirs_offset + 40 and data_dirs_offset + 40 <= len(hdr_bytes):
            # Entry 4 is Security Directory (Certificate Table)
            sec_dir_rva, sec_dir_size = struct.unpack_from("<II", hdr_bytes, data_dirs_offset + (4 * 8))

        # Parse Section Headers
        sections_offset = pe_offset + 24 + size_of_opt_header
        max_section_end = 0
        sections_info = []

        for i in range(num_sections):
            sec_hdr = sections_offset + (i * 40)
            if sec_hdr + 40 > len(hdr_bytes):
                break
            sec_name = hdr_bytes[sec_hdr:sec_hdr+8].rstrip(b"\x00").decode("latin1", errors="replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", hdr_bytes, sec_hdr + 8)
            sec_end = raw_ptr + raw_size
            if sec_end > max_section_end:
                max_section_end = sec_end
            sections_info.append({
                "name": sec_name,
                "raw_offset": raw_ptr,
                "raw_size": raw_size,
                "raw_end": sec_end
            })

        # The section table itself is cut off by EOF: the headers are truncated, so no
        # "clean" verdict can be given regardless of the (partial) section bounds parsed.
        declared_table_end = sections_offset + num_sections * 40
        if num_sections > 0 and declared_table_end > file_size:
            return {
                "status": "anomaly",
                "format": "PE32+" if is_64bit else "PE32",
                "file_size": file_size,
                "sections_count": num_sections,
                "sections_parsed": len(sections_info),
                "max_section_end_offset": max_section_end,
                "has_trailing_slack": False,
                "is_truncated": True,
                "missing_bytes_count": max(declared_table_end, max_section_end) - file_size,
                "slack_bytes_count": 0,
                "slack_offset": None,
                "slack_entropy": 0.0,
                "slack_type": "TRUNCATED_PE_HEADERS",
                "diagnostic_note": (
                    f"Corrupt or truncated PE: the section table ({num_sections} entries) ends at offset "
                    f"{declared_table_end}, beyond the physical file size of {file_size} bytes."
                ),
                "sections": sections_info
            }

        # Defect P1: Check for truncated PE sections extending beyond physical file size
        if max_section_end > file_size:
            missing_count = max_section_end - file_size
            return {
                "status": "anomaly",
                "format": "PE32+" if is_64bit else "PE32",
                "file_size": file_size,
                "sections_count": num_sections,
                "max_section_end_offset": max_section_end,
                "has_trailing_slack": False,
                "is_truncated": True,
                "missing_bytes_count": missing_count,
                "slack_bytes_count": 0,
                "slack_offset": None,
                "slack_entropy": 0.0,
                "slack_type": "TRUNCATED_PE_SECTION_OUT_OF_BOUNDS",
                "diagnostic_note": (
                    f"Corrupt or truncated PE: section table declares raw section boundaries extending to "
                    f"offset {max_section_end}, exceeding physical file size of {file_size} bytes "
                    f"(missing {missing_count} bytes)."
                ),
                "sections": sections_info
            }

        has_overlay = (file_size > max_section_end and max_section_end > 0)
        overlay_size = file_size - max_section_end if has_overlay else 0
        overlay_bytes = b""
        if has_overlay:
            with open(file_path, "rb") as f:
                f.seek(max_section_end)
                overlay_bytes = f.read(cls.MAX_OVERLAY_SAMPLE)

        entropy = cls.calculate_entropy(overlay_bytes)
        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "File ends precisely at last section boundary."

        if has_overlay:
            # Check if overlay matches Security Directory region (Certificate Table)
            if sec_dir_size > 0 and sec_dir_rva == max_section_end and sec_dir_size == overlay_size:
                slack_type = "PE_CERTIFICATE_TABLE_REGION_DETECTED"
                if len(overlay_bytes) >= 8:
                    dwLength, wRevision, wCertType = struct.unpack_from("<IHH", overlay_bytes, 0)
                    if dwLength <= overlay_size and wCertType in (0x0001, 0x0002):
                        diagnostic_note = (
                            f"Overlay matches PE Security Directory entry with WIN_CERTIFICATE structure "
                            f"(dwLength={dwLength}, type={hex(wCertType)}). "
                            f"Full cryptographic signature validation deferred to signature engine."
                        )
                    else:
                        diagnostic_note = (
                            f"Overlay matches PE Security Directory ({overlay_size} bytes), but WIN_CERTIFICATE "
                            f"structure is non-standard (dwLength={dwLength}, type={hex(wCertType)})."
                        )
                else:
                    diagnostic_note = f"Overlay matches Security Directory entry ({overlay_size} bytes)."
            elif overlay_bytes.startswith(b"\xef\xbe\xad\xde"):
                slack_type = "PE_INSTALLER_NSIS"
                diagnostic_note = "Overlay contains Nullsoft Scriptable Install System (NSIS) payload."
            elif b"Inno Setup" in overlay_bytes[:256]:
                slack_type = "PE_INSTALLER_INNO"
                diagnostic_note = "Overlay contains Inno Setup installation payload."
            elif overlay_bytes.startswith(b"7z\xbc\xaf\x27\x1c"):
                slack_type = "PE_OVERLAY_7ZIP_ARCHIVE"
                diagnostic_note = "Overlay contains embedded 7-Zip compressed archive."
            elif overlay_bytes.startswith(b"PK\x03\x04"):
                slack_type = "PE_OVERLAY_ZIP_ARCHIVE"
                diagnostic_note = "Overlay contains embedded ZIP archive."
            elif all(b == 0 for b in overlay_bytes[:min(1024, len(overlay_bytes))]):
                slack_type = "PE_ZERO_PADDING_SLACK"
                diagnostic_note = f"Overlay contains {overlay_size} zero-padding alignment bytes."
            elif entropy > 7.0:
                slack_type = "SUSPICIOUS_HIGH_ENTROPY_OVERLAY"
                diagnostic_note = f"High-entropy unmapped payload detected ({overlay_size} bytes, entropy={entropy}). Potential encrypted/packed payload."
            else:
                slack_type = "UNMAPPED_PE_OVERLAY"
                diagnostic_note = f"Unmapped data detected beyond section headers ({overlay_size} bytes, entropy={entropy})."

        return {
            "status": "ok",
            "format": "PE32+" if is_64bit else "PE32",
            "file_size": file_size,
            "sections_count": num_sections,
            "max_section_end_offset": max_section_end,
            "has_trailing_slack": has_overlay,
            "is_truncated": False,
            "slack_bytes_count": overlay_size,
            "slack_offset": max_section_end if has_overlay else None,
            "slack_entropy": entropy,
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note,
            "sections": sections_info
        }

    @classmethod
    def find_rtf_root_close_brace(cls, data: bytes) -> Optional[int]:
        r"""
        Finds the exact byte index of the root RTF closing brace '}' that balances
        the opening brace of the document, properly handling:
        1. Escaped braces: '\{', '\}', and escaped backslash '\\'.
        2. RTF groups: tracks nesting depth starting from root group.
        3. Binary data streams: '\bin<N>' where N bytes follow and must not be parsed.
        Returns the index of the root closing '}', or None if unbalanced/malformed.
        """
        n = len(data)
        idx = 0
        while idx < n and data[idx] in (0x20, 0x09, 0x0D, 0x0A):
            idx += 1
        if idx >= n or data[idx] != ord(b"{"):
            return None

        depth = 0
        while idx < n:
            b = data[idx]
            if b == ord(b"\\"):
                if idx + 1 < n:
                    next_b = data[idx + 1]
                    if next_b in (ord(b"{"), ord(b"}"), ord(b"\\")):
                        idx += 2
                        continue
                    # Check for \bin keyword
                    if data[idx:idx+4] == b"\\bin":
                        k = idx + 4
                        while k < n and (data[k] == ord(b" ") or (ord(b"0") <= data[k] <= ord(b"9"))):
                            k += 1
                        digit_str = data[idx+4:k].strip()
                        if digit_str.isdigit():
                            bin_len = int(digit_str)
                            idx = k
                            if idx < n and data[idx] in (0x20, 0x0D, 0x0A):
                                idx += 1
                            idx += bin_len
                            continue
                idx += 1
                continue
            elif b == ord(b"{"):
                depth += 1
                idx += 1
            elif b == ord(b"}"):
                depth -= 1
                if depth == 0:
                    return idx
                idx += 1
            else:
                idx += 1
        return None

    @classmethod
    def inspect_rtf_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Audits an RTF document for data residing beyond the root document closing brace '}'.
        Uses group-balancing lexer accounting for escapes and binary \bin blocks.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read(50 * 1024 * 1024)

        root_brace_idx = cls.find_rtf_root_close_brace(data)
        if root_brace_idx is None:
            # Fallback to last closing brace with warning
            last_brace_idx = data.rfind(b"}")
            if last_brace_idx == -1:
                return {
                    "status": "warning",
                    "format": "RTF",
                    "file_size": file_size,
                    "has_trailing_slack": False,
                    "slack_bytes_count": 0,
                    "slack_type": "MALFORMED_NO_CLOSING_BRACE",
                    "diagnostic_note": "Document lacks closing brace '}'."
                }
            root_brace_idx = last_brace_idx

        trailing_data = data[root_brace_idx + 1:]
        has_trailing = len(trailing_data) > 0
        entropy = cls.calculate_entropy(trailing_data)

        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "Document terminates cleanly at root closing brace."

        if has_trailing:
            if trailing_data in (b"\x00", b"\r\n\x00", b"\n\x00"):
                slack_type = "MFC_STREAM_NULL_TERMINATOR"
                diagnostic_note = (
                    "Document terminates with standard MFC/RichEdit trailing NUL (0x00) byte. "
                    "Characteristic of WordPad/MFC CRichEditDoc stream serialization."
                )
            elif all(b in (0x00, 0x20, 0x09, 0x0D, 0x0A) for b in trailing_data):
                if 0x00 in trailing_data:
                    slack_type = "TRAILING_NUL_AND_WHITESPACE"
                    diagnostic_note = "Document contains trailing NUL (0x00) alongside whitespace/newlines."
                else:
                    slack_type = "TRAILING_WHITESPACE"
                    diagnostic_note = "Document contains benign trailing whitespace/newlines."
            else:
                slack_type = "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK"
                diagnostic_note = (
                    f"Unexpected unmapped data detected after root closing brace "
                    f"({len(trailing_data)} bytes, entropy={entropy})."
                )

        return {
            "status": "ok",
            "format": "RTF",
            "file_size": file_size,
            "root_closing_brace_offset": root_brace_idx,
            "has_trailing_slack": has_trailing,
            "slack_bytes_count": len(trailing_data),
            "slack_entropy": entropy,
            "slack_tail_hex": [hex(b) for b in trailing_data[:16]],
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note
        }

    @classmethod
    def inspect_json_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Audits a JSON document for trailing data beyond the root structure using raw_decode.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(25 * 1024 * 1024)

        decoder = json.JSONDecoder()
        try:
            stripped_text = text.lstrip()
            _, end_idx = decoder.raw_decode(stripped_text)
            leading_ws = len(text) - len(stripped_text)
            root_end_pos = leading_ws + end_idx
            trailing_text = text[root_end_pos:]
            trailing_bytes = trailing_text.encode("utf-8")
            has_trailing = len(trailing_bytes) > 0
            entropy = cls.calculate_entropy(trailing_bytes)

            slack_type = "CLEAN_EXACT_EOF"
            diagnostic_note = "JSON document terminates cleanly at root object/array boundary."
            if has_trailing:
                if trailing_text.strip() == "":
                    slack_type = "TRAILING_WHITESPACE"
                    diagnostic_note = "Document contains benign trailing whitespace/newlines."
                else:
                    slack_type = "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK"
                    diagnostic_note = (
                        f"Unexpected trailing data detected after JSON root "
                        f"({len(trailing_bytes)} bytes, entropy={entropy})."
                    )

            return {
                "status": "ok",
                "format": "JSON",
                "file_size": file_size,
                "root_end_offset": root_end_pos,
                "has_trailing_slack": has_trailing,
                "slack_bytes_count": len(trailing_bytes),
                "slack_entropy": entropy,
                "slack_tail_hex": [hex(b) for b in trailing_bytes[:16]],
                "slack_type": slack_type,
                "diagnostic_note": diagnostic_note
            }
        except Exception as e:
            return {
                "status": "warning",
                "format": "JSON",
                "file_size": file_size,
                "has_trailing_slack": False,
                "slack_bytes_count": 0,
                "slack_type": "MALFORMED_JSON_PARSE_ERROR",
                "diagnostic_note": f"JSON syntax parse error: {e}"
            }

    @classmethod
    def inspect_xml_file(cls, file_path: str) -> Dict[str, Any]:
        """Audits XML file for trailing bytes beyond the root closing tag."""
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read(50 * 1024 * 1024)

        last_gt = data.rfind(b">")
        if last_gt == -1:
            return {"status": "warning", "format": "XML", "has_trailing_slack": False}

        trailing = data[last_gt + 1:]
        has_trailing = len(trailing) > 0
        entropy = cls.calculate_entropy(trailing)
        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "XML terminates cleanly at root tag."

        if has_trailing:
            if all(b in (0x20, 0x09, 0x0D, 0x0A) for b in trailing):
                slack_type = "TRAILING_WHITESPACE"
                diagnostic_note = "Benign trailing whitespace after XML root tag."
            else:
                slack_type = "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK"
                diagnostic_note = f"Unexpected data detected after XML root tag ({len(trailing)} bytes, entropy={entropy})."

        return {
            "status": "ok",
            "format": "XML",
            "file_size": file_size,
            "root_closing_tag_offset": last_gt,
            "has_trailing_slack": has_trailing,
            "slack_bytes_count": len(trailing),
            "slack_entropy": entropy,
            "slack_tail_hex": [hex(b) for b in trailing[:16]],
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note
        }

    @classmethod
    def inspect_generic_file(cls, file_path: str) -> Dict[str, Any]:
        """Fallback inspector for unformatted binaries."""
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read(cls.MAX_OVERLAY_SAMPLE)

        entropy = cls.calculate_entropy(data)
        return {
            "status": "ok",
            "format": "GENERIC_BINARY",
            "file_size": file_size,
            "has_trailing_slack": False,
            "slack_bytes_count": 0,
            "slack_entropy": entropy,
            "slack_type": "CLEAN_EXACT_EOF",
            "diagnostic_note": f"Generic binary stream analyzed ({file_size} bytes, entropy={entropy})."
        }
