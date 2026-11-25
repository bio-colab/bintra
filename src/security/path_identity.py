# -*- coding: utf-8 -*-
"""
Bintra Path Identity & Jail Boundary Enforcer.
Provides deterministic canonical path resolution, anti-traversal defense,
and protection against NTFS Junctions, Symbolic Links, and Alternate Data Streams (ADS).
"""

import os
import sys
from typing import Optional

from ._win32 import get_final_path_win32


class PathIdentity:
    """
    Validates, normalizes, and canonicalizes filesystem paths.
    Guarantees strict confinement within declared scope boundaries.
    """

    @classmethod
    def canonicalize(cls, path: str) -> str:
        """
        Resolves relative components, symlinks, and junction points to obtain
        the authoritative physical path.
        """
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string.")

        # Guard against NULL byte injection
        if "\x00" in path:
            raise ValueError("Path contains invalid NULL byte character.")

        # Guard against Alternate Data Streams (ADS)
        cls._validate_no_ads(path)

        # Guard against raw device / NT namespaces (including forward-slash and leading-whitespace variants)
        normalized_prefix = path.lstrip().replace("/", "\\")
        if normalized_prefix.startswith(("\\\\.\\", "\\\\?\\")):
            raise ValueError("Direct device and raw NT namespaces are prohibited.")

        norm_path = os.path.normpath(os.path.abspath(path))

        # On Windows, resolve reparse points (symlinks/junctions) via GetFinalPathNameByHandleW,
        # walking up to the nearest existing ancestor when the leaf path does not yet exist.
        if sys.platform == "win32":
            resolved = cls._resolve_win32_with_ancestors(norm_path)
            if resolved:
                return resolved

        return os.path.realpath(norm_path)

    @classmethod
    def _resolve_win32_with_ancestors(cls, norm_path: str) -> Optional[str]:
        if os.path.exists(norm_path):
            final_path = cls._get_final_path_win32(norm_path)
            if final_path:
                return final_path
            return None

        probe = norm_path
        pending_parts = []
        while True:
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            pending_parts.append(os.path.basename(probe))
            probe = parent
            if os.path.exists(probe):
                final_ancestor = cls._get_final_path_win32(probe)
                if final_ancestor:
                    return os.path.normpath(os.path.join(final_ancestor, *reversed(pending_parts)))
                break
        return None

    @classmethod
    def _validate_no_ads(cls, path: str) -> None:
        """Ensures the path does not target an Alternate Data Stream (:stream)."""
        # Only an ASCII drive letter colon (e.g. C:) is permitted at index 1
        has_drive_prefix = len(path) >= 2 and path[0].isascii() and path[0].isalpha() and path[1] == ":"
        tail = path[2:] if has_drive_prefix else path
        if ":" in tail:
            raise ValueError(f"Alternate Data Streams (:stream) are prohibited: '{path}'.")

    @classmethod
    def _get_final_path_win32(cls, file_path: str) -> Optional[str]:
        """Queries kernel for the true final volume path via GetFinalPathNameByHandleW."""
        return get_final_path_win32(file_path)

    @classmethod
    def is_within_directory(cls, candidate_path: str, parent_directory: str) -> bool:
        """
        Determines if candidate_path is strictly contained within parent_directory.
        Protects against path traversal (../) and escaping symlinks without rejecting
        legitimate filenames that begin with '..' (e.g. '..hidden').
        """
        try:
            can_cand = cls.canonicalize(candidate_path)
            can_parent = cls.canonicalize(parent_directory)
            rel = os.path.relpath(can_cand, can_parent)
            return rel != ".." and not rel.startswith(".." + os.sep) and not os.path.isabs(rel)
        except Exception:
            return False

    @classmethod
    def is_same_file(cls, path_a: str, path_b: str) -> bool:
        """Determines if two path strings point to the exact same canonical file on disk, including hard links."""
        try:
            can_a = cls.canonicalize(path_a)
            can_b = cls.canonicalize(path_b)
            if os.path.normcase(can_a) == os.path.normcase(can_b):
                return True
            if os.path.exists(can_a) and os.path.exists(can_b):
                return os.path.samefile(can_a, can_b)
            return False
        except Exception:
            return False

    @classmethod
    def is_same_or_within(cls, candidate_path: str, parent_directory: str) -> bool:
        """Returns True if candidate_path equals or lies inside parent_directory."""
        return cls.is_same_file(candidate_path, parent_directory) or cls.is_within_directory(
            candidate_path, parent_directory
        )
