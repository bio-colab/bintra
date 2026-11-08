# -*- coding: utf-8 -*-
"""
REA-Neural Safe File Access Gateway.
Mediates all filesystem reads and workspace writes through the ExecutionGuard.
Employs non-exclusive Win32 sharing flags to avoid starving live processes.
"""

import os
import sys
from typing import Optional, Union
from .execution_guard import ExecutionGuard
from .capability_registry import Capability
from .path_identity import PathIdentity


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
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="read_bytes",
            target=file_path,
            capability=Capability.FILE_READ,
            access_mode="READ"
        )

        can_path = PathIdentity.canonicalize(file_path)
        if not os.path.exists(can_path):
            raise FileNotFoundError(f"File not found: '{can_path}'")

        with open(can_path, "rb") as f:
            if offset > 0:
                f.seek(offset)
            if length is not None:
                return f.read(length)
            return f.read()

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
        overwrite: bool = True
    ) -> str:
        """
        Writes content strictly inside the authorized REA workspace.
        Mediated via ExecutionGuard with Capability.WORKSPACE_WRITE.
        Attempts to write into target directory or target binary are unconditionally blocked.
        """
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="write_workspace_file",
            target=file_path,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )

        can_path = PathIdentity.canonicalize(file_path)
        if os.path.exists(can_path) and not overwrite:
            raise FileExistsError(f"Workspace file already exists: '{can_path}'")

        parent = os.path.dirname(can_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"

        with open(can_path, mode, encoding=encoding) as f:
            f.write(content)

        # Track created file in current session scope for clean isolation
        ExecutionGuard.get_current_scope().record_session_file(can_path)
        return can_path

    @classmethod
    def delete_workspace_file(cls, file_path: str) -> bool:
        """
        Deletes a temporary file created by REA in the current session.
        Attempts to delete target binaries or external system files are unconditionally blocked.
        """
        ExecutionGuard.request_access(
            component="safe_file_access",
            operation="delete_workspace_file",
            target=file_path,
            capability=Capability.WORKSPACE_TEMP_CLEAN,
            access_mode="DELETE"
        )

        can_path = PathIdentity.canonicalize(file_path)
        if os.path.exists(can_path):
            os.remove(can_path)
            return True
        return False
