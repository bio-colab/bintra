# -*- coding: utf-8 -*-
"""
REA-Neural Target Scope & Isolation Boundary.
Defines the boundary between read-only target binaries and controlled-write workspaces.
Maintains tamper-evident SHA-256 hash baselines to prove zero mutation.
"""

import os
import hashlib
from typing import Set, Dict, Optional, List, Any
from .path_identity import PathIdentity


class TargetScope:
    """
    Encapsulates the immutable target scope and the quarantined workspace.
    Guarantees that analysis results are never written into target directories.
    """

    def __init__(self, target_binary_path: Optional[str] = None, workspace_dir: Optional[str] = None):
        self._target_paths: Set[str] = set()
        self._target_dirs: Set[str] = set()
        self._target_hashes: Dict[str, str] = {}
        self._session_created_files: Set[str] = set()

        # Configure workspace directory
        if workspace_dir:
            self._workspace_dir = PathIdentity.canonicalize(workspace_dir)
        else:
            # Default to a designated 'reports' or 'artifacts' subdirectory in cwd
            default_ws = os.path.join(os.getcwd(), ".rea_workspace")
            os.makedirs(default_ws, exist_ok=True)
            self._workspace_dir = PathIdentity.canonicalize(default_ws)

        if target_binary_path:
            self.register_target(target_binary_path)

    @property
    def workspace_dir(self) -> str:
        """The canonical path to the authorized write workspace."""
        return self._workspace_dir

    def register_target(self, binary_path: str) -> str:
        """
        Registers an immutable target binary, computes its SHA-256 baseline,
        and shields its parent directory from output pollution.
        """
        can_path = PathIdentity.canonicalize(binary_path)
        self._target_paths.add(can_path)

        target_dir = PathIdentity.canonicalize(os.path.dirname(can_path))
        self._target_dirs.add(target_dir)

        # Disallow workspace from being the exact target directory
        if PathIdentity.is_same_file(self._workspace_dir, target_dir):
            safe_ws = os.path.join(os.path.expanduser("~"), ".rea_neural", "workspace")
            os.makedirs(safe_ws, exist_ok=True)
            self._workspace_dir = PathIdentity.canonicalize(safe_ws)

        # Compute baseline SHA-256 hash
        if os.path.exists(can_path) and os.path.isfile(can_path):
            self._target_hashes[can_path] = self.compute_sha256(can_path)

        return can_path

    @classmethod
    def compute_sha256(cls, file_path: str) -> str:
        """Calculates streaming SHA-256 hash of a file on disk."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def verify_target_integrity(self, binary_path: str) -> Dict[str, Any]:
        """
        Verifies that target binary has suffered zero byte modifications.
        Compares current hash against initial baseline.
        """
        can_path = PathIdentity.canonicalize(binary_path)
        if can_path not in self._target_hashes:
            return {
                "status": "error",
                "is_intact": False,
                "error": f"Target '{binary_path}' has no recorded baseline hash."
            }

        if not os.path.exists(can_path):
            return {
                "status": "tampered",
                "is_intact": False,
                "error": "Target file no longer exists on disk."
            }

        cur_hash = self.compute_sha256(can_path)
        orig_hash = self._target_hashes[can_path]
        is_intact = (cur_hash == orig_hash)

        return {
            "status": "success",
            "is_intact": is_intact,
            "baseline_sha256": orig_hash,
            "current_sha256": cur_hash,
            "tamper_detected": not is_intact
        }

    def is_target_file(self, file_path: str) -> bool:
        """Checks if a path matches any registered target binary."""
        try:
            can = PathIdentity.canonicalize(file_path)
            return any(PathIdentity.is_same_file(can, t) for t in self._target_paths)
        except Exception:
            return False

    def is_target_directory(self, dir_path: str) -> bool:
        """
        Checks if a path is located inside the directory of a target binary,
        excluding designated workspace subdirectories.
        """
        try:
            can = PathIdentity.canonicalize(dir_path)
            if self.is_inside_workspace(can):
                return False
            return any(
                PathIdentity.is_same_file(can, td) or PathIdentity.is_within_directory(can, td)
                for td in self._target_dirs
            )
        except Exception:
            return False

    def is_inside_workspace(self, file_path: str) -> bool:
        """Checks if a path is located strictly within the designated workspace."""
        return PathIdentity.is_within_directory(file_path, self._workspace_dir)

    def record_session_file(self, file_path: str) -> None:
        """Records a file created by REA during the current session."""
        try:
            self._session_created_files.add(PathIdentity.canonicalize(file_path))
        except Exception:
            pass

    def is_session_file(self, file_path: str) -> bool:
        """Verifies if a file was created by REA in the current session."""
        try:
            can = PathIdentity.canonicalize(file_path)
            return can in self._session_created_files
        except Exception:
            return False

    def get_session_files(self) -> List[str]:
        """Returns list of all files created during the current session."""
        return sorted(list(self._session_created_files))
