# -*- coding: utf-8 -*-
"""
Bintra Target Scope & Isolation Boundary.
Defines the boundary between read-only target binaries and controlled-write workspaces.
Maintains tamper-evident SHA-256 hash baselines to prove zero mutation.
Enforces read-scope and workspace confinement policies across all execution contexts.
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

    @classmethod
    def _is_unsafe_workspace_root(cls, can_ws: str) -> Optional[str]:
        """Rejects filesystem roots, home directory root, and OS system directories as mutable workspaces."""
        if os.path.dirname(can_ws) == can_ws:
            return "FILESYSTEM_ROOT"
        norm_ws = os.path.normcase(can_ws)
        try:
            home_dir = PathIdentity.canonicalize(os.path.expanduser("~"))
            if norm_ws == os.path.normcase(home_dir) or PathIdentity.is_same_file(can_ws, home_dir):
                return "USER_HOME_ROOT"
        except Exception:
            pass

        if os.name == "nt":
            sys_drive = os.environ.get("SystemDrive", "C:")
            users_root = os.path.join(sys_drive + os.sep, "Users")
            try:
                if PathIdentity.is_same_file(can_ws, users_root):
                    return "SYSTEM_USERS_ROOT"
            except Exception:
                pass
            win_sys_dirs = [
                os.environ.get("SystemRoot", r"C:\Windows"),
                os.environ.get("ProgramFiles", r"C:\Program Files"),
                os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                os.environ.get("ProgramData", r"C:\ProgramData"),
            ]
            for sys_dir in win_sys_dirs:
                if not sys_dir:
                    continue
                try:
                    can_sys = PathIdentity.canonicalize(sys_dir)
                    if PathIdentity.is_same_file(can_ws, can_sys) or PathIdentity.is_within_directory(can_ws, can_sys):
                        return "WINDOWS_SYSTEM_DIRECTORY"
                except Exception:
                    continue
        else:
            posix_sys_dirs = (
                "/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64",
                "/boot", "/root", "/dev", "/proc", "/sys",
            )
            for sys_dir in posix_sys_dirs:
                try:
                    if os.path.normcase(can_ws) == sys_dir or PathIdentity.is_within_directory(can_ws, sys_dir):
                        return "POSIX_SYSTEM_DIRECTORY"
                except Exception:
                    continue
            if os.path.normcase(can_ws) == "/var":
                return "POSIX_SYSTEM_DIRECTORY"
        return None

    def __init__(
        self,
        target_binary_path: Optional[str] = None,
        workspace_dir: Optional[str] = None,
        strict_read_scope: bool = False
    ):
        self._target_paths: Set[str] = set()
        self._target_dirs: Set[str] = set()
        self._target_hashes: Dict[str, str] = {}
        self._session_created_files: Set[str] = set()
        self.strict_read_scope = strict_read_scope

        if workspace_dir:
            can_ws = PathIdentity.canonicalize(workspace_dir)
            unsafe_reason = self._is_unsafe_workspace_root(can_ws)
            if unsafe_reason:
                raise PermissionError(
                    f"UNSAFE_WORKSPACE_ROOT ({unsafe_reason}): Refusing to designate '{can_ws}' as mutable workspace."
                )
            self._workspace_dir = can_ws
        else:
            default_ws = os.path.join(os.path.expanduser("~"), ".bintra", "workspace")
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

        # Disallow workspace from being equal to, inside, or an ancestor containing target directory
        if (
            PathIdentity.is_same_file(self._workspace_dir, target_dir)
            or PathIdentity.is_within_directory(self._workspace_dir, target_dir)
            or PathIdentity.is_within_directory(target_dir, self._workspace_dir)
        ):
            safe_ws = os.path.join(os.path.expanduser("~"), ".bintra", "workspace")
            if PathIdentity.is_within_directory(target_dir, safe_ws) or PathIdentity.is_same_file(target_dir, safe_ws):
                safe_ws = os.path.join(os.path.expanduser("~"), ".bintra", "isolated_workspace")
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

    def has_registered_targets(self) -> bool:
        """Returns True if one or more target binaries are registered."""
        return len(self._target_paths) > 0

    def is_target_file(self, file_path: str) -> bool:
        """Checks if a path matches any registered target binary."""
        try:
            can = PathIdentity.canonicalize(file_path)
            return any(PathIdentity.is_same_file(can, t) for t in self._target_paths)
        except Exception:
            return False

    def is_target_directory(self, dir_path: str) -> bool:
        """
        Checks if a path is or is inside any target binary directory.
        """
        try:
            can = PathIdentity.canonicalize(dir_path)
            return any(
                PathIdentity.is_same_file(can, td) or PathIdentity.is_within_directory(can, td)
                for td in self._target_dirs
            )
        except Exception:
            return False

    def is_inside_workspace(self, file_path: str) -> bool:
        """Checks if a path is located strictly within the designated workspace."""
        try:
            return PathIdentity.is_within_directory(file_path, self._workspace_dir)
        except Exception:
            return False

    def is_authorized_read_target(self, file_path: str) -> bool:
        """
        Checks if a file path is permitted for reading under current scope.
        In strict mode, permits registered targets, target directory contents, and workspace files.
        """
        if not self.strict_read_scope:
            return True
        return (
            self.is_target_file(file_path) or
            self.is_inside_workspace(file_path) or
            self.is_target_directory(file_path)
        )

    def record_session_file(self, file_path: str) -> None:
        """Records a file created by Bintra during the current session."""
        try:
            self._session_created_files.add(PathIdentity.canonicalize(file_path))
        except Exception:
            pass

    def is_session_file(self, file_path: str) -> bool:
        """Verifies if a file was created by Bintra in the current session."""
        try:
            can = PathIdentity.canonicalize(file_path)
            return can in self._session_created_files
        except Exception:
            return False

    def get_session_files(self) -> List[str]:
        """Returns list of all files created during the current session."""
        return sorted(list(self._session_created_files))
