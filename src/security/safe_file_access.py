# -*- coding: utf-8 -*-
"""
Bintra Safe File Access Gateway.
Mediates all filesystem reads and workspace writes through the ExecutionGuard.
Employs non-exclusive sharing and validates physical canonical paths against
authorized target and workspace boundaries.
"""

import os
import shutil
from typing import Optional, Union

from .capability_registry import Capability
from .execution_guard import ExecutionGuard, TargetMutationError
from .path_identity import PathIdentity


def _validate_slice_args(offset: int, length: Optional[int]) -> None:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError(f"offset must be a non-negative integer, got {offset!r}")
    if length is not None and (isinstance(length, bool) or not isinstance(length, int) or length < 0):
        raise ValueError(f"length must be None or a non-negative integer, got {length!r}")


class SafeFileAccess:
    """
    Authorized filesystem access gateway.
    Guarantees non-destructive read-only access to targets and quarantined workspace writes.
    """

    @classmethod
    def read_bytes(cls, file_path: str, offset: int = 0, length: Optional[int] = None) -> bytes:
        """
        Reads bytes from target file using non-exclusive sharing.
        Mediated via ExecutionGuard with Capability.FILE_READ.
        """
        _validate_slice_args(offset, length)

        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="read_bytes",
            target=file_path,
            capability=Capability.FILE_READ,
            access_mode="READ",
        )

        can_path = PathIdentity.canonicalize(file_path)
        if not os.path.exists(can_path):
            raise FileNotFoundError(f"File not found: '{can_path}'")
        if os.path.isdir(can_path):
            raise IsADirectoryError(f"Path is a directory, not a regular file: '{can_path}'")

        with open(can_path, "rb") as fh:
            if offset > 0:
                fh.seek(offset)
            if length is not None:
                return fh.read(length)
            return fh.read()

    @classmethod
    def read_text(cls, file_path: str, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Reads text from a file safely under Reference Monitor guard."""
        raw = cls.read_bytes(file_path)
        return raw.decode(encoding, errors=errors)

    @classmethod
    def write_workspace_file(
        cls,
        file_path: str,
        content: Union[str, bytes],
        overwrite: bool = True,
    ) -> str:
        """
        Writes content strictly inside the authorized Bintra workspace.
        Mediated via ExecutionGuard with Capability.WORKSPACE_WRITE.
        Attempts to write into target directory or target binary are unconditionally blocked.
        """
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="write_workspace_file",
            target=file_path,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE",
        )

        can_path = PathIdentity.canonicalize(file_path)
        scope = ExecutionGuard.get_current_scope()
        if scope and scope.is_target_file(can_path):
            raise TargetMutationError(
                f"TARGET_WRITE_FORBIDDEN: Path '{can_path}' references a strictly immutable target (hard-link alias)."
            )

        if os.path.isdir(can_path):
            raise IsADirectoryError(f"Cannot overwrite directory as workspace file: '{can_path}'")

        if os.path.exists(can_path) and not overwrite:
            raise FileExistsError(f"Workspace file already exists: '{can_path}'")

        parent = os.path.dirname(can_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"

        with open(can_path, mode, encoding=encoding) as fh:
            fh.write(content)

        if scope:
            scope.record_session_file(can_path)
        return can_path

    @classmethod
    def delete_workspace_file(cls, file_path: str) -> bool:
        """
        Deletes a temporary file created by Bintra in the current session.
        Attempts to delete target binaries or external system files are unconditionally blocked.
        """
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="delete_workspace_file",
            target=file_path,
            capability=Capability.WORKSPACE_TEMP_CLEAN,
            access_mode="DELETE",
        )

        can_path = PathIdentity.canonicalize(file_path)
        if os.path.exists(can_path) and not os.path.isdir(can_path):
            os.remove(can_path)
            return True
        return False

    @classmethod
    def delete_workspace_dir(cls, dir_path: str) -> bool:
        """
        Recursively deletes a temporary directory created by Bintra in the current session.
        Enforces Capability.WORKSPACE_TEMP_CLEAN, session provenance, and workspace boundary confinement.
        Attempts to delete target directories or external paths are unconditionally blocked.
        """
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="delete_workspace_dir",
            target=dir_path,
            capability=Capability.WORKSPACE_TEMP_CLEAN,
            access_mode="DELETE",
        )

        can_path = PathIdentity.canonicalize(dir_path)
        if os.path.exists(can_path) and os.path.isdir(can_path):
            shutil.rmtree(can_path, ignore_errors=True)
            return not os.path.exists(can_path)
        return False
