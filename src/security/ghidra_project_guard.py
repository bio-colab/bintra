# -*- coding: utf-8 -*-
"""
Bintra Ghidra Project Guard & Safety Lifecycle Confinement.
Provides strict reference monitor enforcement for transient Ghidra projects:
1. Regex-validated project name sanitization (prevents path traversal / directory escaping).
2. Workspace boundary confinement (prevents project creation in system directories).
3. Capability-gated directory lifecycle (WORKSPACE_WRITE on setup, WORKSPACE_TEMP_CLEAN on cleanup).
4. Session-scoped provenance tracking (prevents arbitrary deletion of foreign projects).
5. Truthful filesystem absence verification on cleanup.
"""

from __future__ import annotations

import os
import re
import tempfile
import uuid
from typing import Optional, Set, Tuple

from .capability_registry import Capability
from .execution_guard import ExecutionGuard, SecurityViolationError
from .path_identity import PathIdentity
from .safe_file_access import SafeFileAccess


class GhidraProjectGuard:
    """
    Surgical safety boundary for Ghidra project creation and cleanup.
    Guarantees that all Ghidra headless project databases reside strictly within
    authorized workspace boundaries and cannot perform arbitrary filesystem mutations or deletions.
    """

    _PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")
    _MAX_NAME_LENGTH = 64

    # Tracks canonical (project_dir, project_name) tuples created within the current session
    _session_created_projects: Set[Tuple[str, str]] = set()

    @classmethod
    def sanitize_project_name(cls, project_name: Optional[str]) -> str:
        """
        Validates and sanitizes a Ghidra project name.
        Rejects path traversal tokens ('..', '/', '\\', ':', etc.) and unsafe characters.
        """
        if not project_name or not str(project_name).strip():
            return f"BintraHeadless_{uuid.uuid4().hex[:8]}"

        clean_name = str(project_name).strip()
        if len(clean_name) > cls._MAX_NAME_LENGTH:
            raise ValueError(
                f"Ghidra project name '{clean_name}' exceeds maximum permitted length of {cls._MAX_NAME_LENGTH} characters."
            )

        if not cls._PROJECT_NAME_REGEX.match(clean_name):
            raise ValueError(
                f"Invalid Ghidra project name '{clean_name}'. Must match ^[a-zA-Z0-9_-]+$ (no path traversal, slashes, or special characters)."
            )

        return clean_name

    @classmethod
    def resolve_project_dir(cls, requested_dir: Optional[str]) -> str:
        """
        Resolves and verifies the target directory for Ghidra projects.
        Guarantees that the project directory is strictly confined to the authorized workspace.
        """
        scope = ExecutionGuard.get_current_scope()

        if not requested_dir or not str(requested_dir).strip():
            if scope and getattr(scope, "workspace_dir", None):
                target_dir = os.path.join(scope.workspace_dir, "ghidra_projects")
            else:
                user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
                target_dir = os.path.join(user_home, ".bintra", "workspace", "ghidra_projects")
        else:
            target_dir = str(requested_dir).strip()

        can_dir = PathIdentity.canonicalize(target_dir)

        # Enforce workspace boundary if an active security scope is registered
        if scope:
            if not scope.is_inside_workspace(can_dir):
                raise SecurityViolationError(
                    f"Ghidra project directory '{requested_dir}' is outside authorized workspace '{scope.workspace_dir}'."
                )
            if scope.is_target_directory(can_dir) or scope.is_target_file(can_dir):
                raise SecurityViolationError(
                    f"Ghidra project directory '{requested_dir}' targets a protected target binary or directory."
                )

        return can_dir

    @classmethod
    def register_and_prepare_project(
        cls,
        component: str,
        proj_dir: str,
        proj_name: str
    ) -> Tuple[str, str]:
        """
        Prepares and registers a Ghidra project directory before execution.
        Requests Capability.WORKSPACE_WRITE and tracks the project in session provenance.
        Returns tuple of canonical (rep_dir_path, gpr_file_path).
        """
        can_proj_dir = PathIdentity.canonicalize(proj_dir)
        clean_name = cls.sanitize_project_name(proj_name)

        # Request write access to create the project directory
        ExecutionGuard.request_access(
            component=component,
            operation="create_ghidra_project",
            target=can_proj_dir,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE",
            metadata={"project_name": clean_name}
        )

        os.makedirs(can_proj_dir, exist_ok=True)

        rep_path = os.path.join(can_proj_dir, f"{clean_name}.rep")
        gpr_path = os.path.join(can_proj_dir, f"{clean_name}.gpr")

        # Record in session provenance
        cls._session_created_projects.add((can_proj_dir.lower(), clean_name))

        # Register paths with TargetScope so SafeFileAccess allows cleanup
        scope = ExecutionGuard.get_current_scope()
        if scope:
            scope.record_session_file(can_proj_dir)
            scope.record_session_file(rep_path)
            scope.record_session_file(gpr_path)

        return rep_path, gpr_path

    @classmethod
    def clean_transient_project(
        cls,
        component: str,
        proj_dir: str,
        proj_name: str
    ) -> bool:
        """
        Safely cleans up a transient Ghidra project (.rep directory and .gpr file).
        Enforces session provenance: only projects created by Bintra in the current session
        can be deleted. Returns True if the project artifacts are verified gone from disk.
        """
        try:
            can_proj_dir = PathIdentity.canonicalize(proj_dir)
        except Exception:
            return False

        key = (can_proj_dir.lower(), proj_name)

        # Enforce session provenance
        if key not in cls._session_created_projects:
            # Not created in this session - refuse deletion
            return False

        rep_dir = os.path.join(can_proj_dir, f"{proj_name}.rep")
        gpr_file = os.path.join(can_proj_dir, f"{proj_name}.gpr")

        try:
            if os.path.exists(rep_dir) and os.path.isdir(rep_dir):
                SafeFileAccess.delete_workspace_dir(rep_dir)
            if os.path.exists(gpr_file) and os.path.isfile(gpr_file):
                SafeFileAccess.delete_workspace_file(gpr_file)
        except Exception:
            pass

        # Verify true absence on disk
        rep_gone = not os.path.exists(rep_dir)
        gpr_gone = not os.path.exists(gpr_file)

        if rep_gone and gpr_gone:
            cls._session_created_projects.discard(key)
            return True

        return False
