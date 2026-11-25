# -*- coding: utf-8 -*-
"""
Inter-process file locking and exceptions for the Bintra Audit Logger.
"""

import os
import sys
import time
from typing import Callable, Optional

_IS_WINDOWS = sys.platform == "win32"


class AuditPersistenceError(RuntimeError):
    """Raised when an audit record fails to persist to durable storage."""


class AuditIntegrityError(PermissionError):
    """Raised when cryptographic audit log tampering is detected."""


class _ProcessFileLock:
    """Inter-process cross-process file lock using msvcrt (Windows) or fcntl (POSIX)."""

    def __init__(
        self,
        lock_file_path: str,
        timeout: float = 10.0,
        fail_closed: Optional[bool] = None,
        strict_getter: Optional[Callable[[], bool]] = None,
        on_degraded: Optional[Callable[[str], None]] = None,
    ):
        self.lock_file_path = lock_file_path
        self.timeout = timeout
        self.fail_closed = fail_closed
        self._strict_getter = strict_getter
        self._on_degraded = on_degraded
        self.acquired = False
        self._fd = None

    def _is_strict(self) -> bool:
        if self.fail_closed is not None:
            return bool(self.fail_closed)
        if self._strict_getter is not None:
            return bool(self._strict_getter())
        from .audit_logger import AuditLogger

        return AuditLogger.get_strict_persistence()

    def _report_degraded(self, reason: str) -> None:
        if self._on_degraded is not None:
            self._on_degraded(reason)
            return
        from .audit_logger import AuditLogger

        AuditLogger.mark_degraded(reason)

    def _close_fd(self) -> None:
        if self._fd is not None:
            try:
                self._fd.close()
            except Exception:
                pass
            self._fd = None

    def _lock_nonblocking(self) -> None:
        assert self._fd is not None
        if _IS_WINDOWS:
            import msvcrt

            self._fd.seek(0)
            msvcrt.locking(self._fd.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_quiet(self) -> None:
        if self._fd is None or not self.acquired:
            return
        try:
            if _IS_WINDOWS:
                import msvcrt

                self._fd.seek(0)
                msvcrt.locking(self._fd.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    def __enter__(self):
        if not self.lock_file_path:
            return self

        start = time.time()
        parent_dir = os.path.dirname(self.lock_file_path)
        if parent_dir:
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except Exception:
                pass

        strict = self._is_strict()
        try:
            self._fd = open(self.lock_file_path, "a+b")
        except Exception as open_err:
            self._fd = None
            self._report_degraded(f"Cannot open audit lock file: {open_err}")
            if strict:
                raise AuditPersistenceError(
                    f"CRITICAL: Failed to open inter-process audit lock file '{self.lock_file_path}': {open_err}"
                ) from open_err
            return self

        while True:
            try:
                self._lock_nonblocking()
                self.acquired = True
                return self
            except (BlockingIOError, OSError, PermissionError):
                if time.time() - start > self.timeout:
                    self._close_fd()
                    self._report_degraded(
                        f"Timeout ({self.timeout}s) waiting for audit lock '{self.lock_file_path}'"
                    )
                    if strict:
                        raise AuditPersistenceError(
                            f"CRITICAL: Timeout ({self.timeout}s) acquiring inter-process audit lock on '{self.lock_file_path}'"
                        )
                    break
                time.sleep(0.01)
            except Exception as lock_err:
                self._close_fd()
                self._report_degraded(f"Unexpected error acquiring audit lock: {lock_err}")
                if strict:
                    raise AuditPersistenceError(
                        f"CRITICAL: Unexpected error acquiring audit lock on '{self.lock_file_path}': {lock_err}"
                    ) from lock_err
                break
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._unlock_quiet()
        self._close_fd()
        self.acquired = False
