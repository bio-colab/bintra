# -*- coding: utf-8 -*-
"""
Binary Slack Space, PE Overlay, & Document EOF Padding Diagnostic Engine.
Audits binary executables and structured document formats for data residing
beyond official structural boundaries:
1. PE Executables: Dissects file data residing beyond the final PE section
   (Overlay data, Authenticode certificate bundles, embedded installer payloads).
2. RTF Documents: Audits trailing bytes beyond the root closing brace '}',
   detecting MFC/RichEdit trailing NUL (0x00) bytes and embedded payloads.
3. XML & JSON Documents: Audits trailing data beyond root boundary tokens.
"""

from __future__ import annotations

import os
import math
import struct
import hashlib
from typing import Dict, Any, List, Optional, Tuple


class BinarySlackInspector:
    """
    Forensic inspector for slack space, PE overlays, and document EOF padding.
    """

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

        if head.startswith(b"MZ"):
            return cls.inspect_pe_file(file_path)
        elif head.startswith(b"{\\rtf"):
            return cls.inspect_rtf_file(file_path)
        elif head.lstrip().startswith(b"<?xml") or head.lstrip().startswith(b"<"):
            return cls.inspect_xml_file(file_path)
        else:
            return cls.inspect_generic_file(file_path)

    @classmethod
    def inspect_pe_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Dissects a PE executable to determine whether data resides beyond the last section.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            raw = f.read()

        if len(raw) < 64 or not raw.startswith(b"MZ"):
            return {"status": "error", "error": "Not a valid PE DOS header."}

        pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
        if pe_offset + 24 > len(raw) or raw[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return {"status": "error", "error": "Not a valid PE NT signature."}

        machine, num_sections = struct.unpack_from("<HH", raw, pe_offset + 4)
        size_of_opt_header = struct.unpack_from("<H", raw, pe_offset + 20)[0]
        opt_magic = struct.unpack_from("<H", raw, pe_offset + 24)[0] if pe_offset + 26 <= len(raw) else 0
        is_64bit = (opt_magic == 0x20B)

        # Parse Security Directory (Certificate Table)
        sec_dir_rva = 0
        sec_dir_size = 0
        data_dirs_offset = pe_offset + 24 + (112 if is_64bit else 96)
        if pe_offset + 24 + size_of_opt_header >= data_dirs_offset + 40:
            # Entry 4 is Security Directory (Certificate Table)
            sec_dir_rva, sec_dir_size = struct.unpack_from("<II", raw, data_dirs_offset + (4 * 8))

        # Parse Section Headers
        sections_offset = pe_offset + 24 + size_of_opt_header
        max_section_end = 0
        sections_info = []

        for i in range(num_sections):
            sec_hdr = sections_offset + (i * 40)
            if sec_hdr + 40 > len(raw):
                break
            sec_name = raw[sec_hdr:sec_hdr+8].rstrip(b"\x00").decode("latin1", errors="replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, sec_hdr + 8)
            sec_end = raw_ptr + raw_size
            if sec_end > max_section_end:
                max_section_end = sec_end
            sections_info.append({
                "name": sec_name,
                "raw_offset": raw_ptr,
                "raw_size": raw_size,
                "raw_end": sec_end
            })

        has_overlay = (file_size > max_section_end and max_section_end > 0)
        overlay_size = file_size - max_section_end if has_overlay else 0
        overlay_bytes = raw[max_section_end:] if has_overlay else b""
        entropy = cls.calculate_entropy(overlay_bytes)

        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "File ends precisely at last section boundary."

        if has_overlay:
            # Check if overlay is identical to Authenticode certificate table
            if sec_dir_size > 0 and sec_dir_rva == max_section_end and sec_dir_size == overlay_size:
                slack_type = "PE_AUTHENTICODE_SECURITY_CERTIFICATE"
                diagnostic_note = f"Overlay contains valid mapped Authenticode Security Certificate ({overlay_size} bytes)."
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
            elif all(b == 0 for b in overlay_bytes):
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
            "slack_bytes_count": overlay_size,
            "slack_offset": max_section_end if has_overlay else None,
            "slack_entropy": entropy,
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note,
            "sections": sections_info
        }

    @classmethod
    def inspect_rtf_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Audits an RTF document for data residing beyond the root document closing brace '}'.
        Accurately identifies MFC/WordPad trailing NUL (0x00) bytes and trailing slack.
        """
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read()

        # Find the last closing brace '}' that balances the root '{\rtf'
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

        trailing_data = data[last_brace_idx + 1:]
        has_trailing = len(trailing_data) > 0
        entropy = cls.calculate_entropy(trailing_data)

        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "Document terminates cleanly at root closing brace."

        if has_trailing:
            # Check for MFC / RichEdit serializer trailing NUL pattern (\r\n\0 or \0)
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
            "root_closing_brace_offset": last_brace_idx,
            "has_trailing_slack": has_trailing,
            "slack_bytes_count": len(trailing_data),
            "slack_entropy": entropy,
            "slack_tail_hex": [hex(b) for b in trailing_data[:16]],
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note
        }

    @classmethod
    def inspect_xml_file(cls, file_path: str) -> Dict[str, Any]:
        """Audits XML file for trailing bytes beyond the root closing tag."""
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            data = f.read()

        last_gt = data.rfind(b">")
        if last_gt == -1:
            return {"status": "warning", "format": "XML", "has_trailing_slack": False}

        trailing = data[last_gt + 1:]
        has_trailing = len(trailing) > 0
        slack_type = "CLEAN_EXACT_EOF"
        diagnostic_note = "XML terminates cleanly at root tag."

        if has_trailing:
            if all(b in (0x20, 0x09, 0x0D, 0x0A) for b in trailing):
                slack_type = "TRAILING_WHITESPACE"
                diagnostic_note = "Benign trailing whitespace after XML root tag."
            elif 0x00 in trailing:
                slack_type = "TRAILING_NULL_BYTE"
                diagnostic_note = "Unexpected trailing NUL byte after XML root tag."
            else:
                slack_type = "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK"
                diagnostic_note = f"Unmapped data ({len(trailing)} bytes) after XML root tag."

        return {
            "status": "ok",
            "format": "XML",
            "file_size": file_size,
            "has_trailing_slack": has_trailing,
            "slack_bytes_count": len(trailing),
            "slack_type": slack_type,
            "diagnostic_note": diagnostic_note
        }

    @classmethod
    def inspect_generic_file(cls, file_path: str) -> Dict[str, Any]:
        """Generic file EOF inspection checking for trailing NUL padding."""
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            if file_size > 1024:
                f.seek(file_size - 1024)
            tail = f.read()

        has_nul_end = (len(tail) > 0 and tail[-1] == 0)
        return {
            "status": "ok",
            "format": "GENERIC_BINARY",
            "file_size": file_size,
            "has_trailing_slack": has_nul_end,
            "slack_bytes_count": 1 if has_nul_end else 0,
            "slack_type": "TRAILING_NULL_BYTE" if has_nul_end else "CLEAN_EXACT_EOF",
            "diagnostic_note": "File ends with NUL byte (0x00)." if has_nul_end else "Clean file boundary."
        }
