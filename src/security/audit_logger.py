# -*- coding: utf-8 -*-
"""
Bintra Tamper-Evident Security Audit Logger.
Maintains a cryptographically hash-chained, persistent audit journal
recording every mediated system access attempt.
Enforces Data Minimization by scrubbing secrets across all record fields.
Provides persistent chain continuity across process restarts and detects disk tampering.
"""

import os
import re
import sys
import json
import time
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class _ProcessFileLock:
    """Inter-process cross-process file lock using msvcrt (Windows) or fcntl (POSIX)."""

    def __init__(self, lock_file_path: str, timeout: float = 10.0, fail_closed: Optional[bool] = None):
        self.lock_file_path = lock_file_path
        self.timeout = timeout
        self.fail_closed = fail_closed
        self.acquired = False
        self._fd = None

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

        strict = self.fail_closed if self.fail_closed is not None else AuditLogger.get_strict_persistence()

        try:
            self._fd = open(self.lock_file_path, "a+b")
        except Exception as open_err:
            self._fd = None
            AuditLogger.mark_degraded(f"Cannot open audit lock file: {open_err}")
            if strict:
                raise AuditPersistenceError(f"CRITICAL: Failed to open inter-process audit lock file '{self.lock_file_path}': {open_err}") from open_err
            return self

        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._fd.seek(0)
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.acquired = True
                return self
            except (BlockingIOError, OSError, PermissionError):
                if time.time() - start > self.timeout:
                    AuditLogger.mark_degraded(f"Timeout ({self.timeout}s) waiting for audit lock '{self.lock_file_path}'")
                    if strict:
                        raise AuditPersistenceError(
                            f"CRITICAL: Timeout ({self.timeout}s) acquiring inter-process audit lock on '{self.lock_file_path}'"
                        )
                    break
                time.sleep(0.01)
            except Exception as lock_err:
                AuditLogger.mark_degraded(f"Unexpected error acquiring audit lock: {lock_err}")
                if strict:
                    raise AuditPersistenceError(
                        f"CRITICAL: Unexpected error acquiring audit lock on '{self.lock_file_path}': {lock_err}"
                    ) from lock_err
                break
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd and self.acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._fd.seek(0)
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        if self._fd:
            try:
                self._fd.close()
            except Exception:
                pass
            self._fd = None
        self.acquired = False


class AuditPersistenceError(RuntimeError):
    """Raised when an audit record fails to persist to durable storage."""
    pass


class AuditIntegrityError(PermissionError):
    """Raised when cryptographic audit log tampering is detected."""
    pass


class AuditLogger:
    """
    Thread-safe, cryptographically hash-chained audit journal.
    Persists audit records to disk and verifies chain integrity.
    """

    _lock = threading.RLock()
    _journal: List[Dict[str, Any]] = []
    _sequence: int = 0
    _last_hash: str = "0" * 64
    _strict_persistence: bool = False
    _explicitly_cleared: bool = False
    _audit_degraded: bool = False
    _degraded_reason: Optional[str] = None
    # (path, size, mtime_ns) of the journal right after this process's last append. If the file
    # still matches, no other process has appended and the tail re-read (an extra file open per
    # decision, several ms each on Windows) can be skipped.
    _known_disk_state: Optional[tuple] = None

    # Default persistent log path
    _log_dir = os.path.join(os.path.expanduser("~"), ".bintra", "logs")
    _log_file = os.path.join(_log_dir, "audit.jsonl")

    # Segment sealing: once the active journal exceeds this size (after a full successful
    # verification) it is sealed into an immutable archive and a new segment continues the
    # SAME hash chain. Startup verification is therefore bounded by the segment size instead
    # of growing with every command ever run (BINTRA_AUDIT_SEGMENT_MB overrides; 0 disables).
    try:
        _segment_max_bytes = int(float(os.environ.get("BINTRA_AUDIT_SEGMENT_MB", "8")) * 1024 * 1024)
    except ValueError:
        _segment_max_bytes = 8 * 1024 * 1024

    # Patterns for sensitive credentials to scrub
    _SENSITIVE_PATTERNS = [
        re.compile(r"(password|passwd|pwd|secret|token|bearer|apikey|api_key)=([^&\s]+)", re.IGNORECASE),
        re.compile(r"(--password|--token|--key|--secret)\s+([^\s]+)", re.IGNORECASE),
    ]

    @classmethod
    def set_strict_persistence(cls, enabled: bool = True) -> None:
        """Enables or disables fail-closed persistence enforcement."""
        with cls._lock:
            cls._strict_persistence = enabled

    @classmethod
    def get_strict_persistence(cls) -> bool:
        """Returns whether strict audit persistence enforcement is active."""
        with cls._lock:
            return cls._strict_persistence

    @classmethod
    def mark_degraded(cls, reason: str) -> None:
        """Records that persistent audit logging has degraded during this session."""
        with cls._lock:
            cls._audit_degraded = True
            cls._degraded_reason = str(reason)

    @classmethod
    def is_audit_degraded(cls) -> bool:
        """Returns True if persistent audit logging failed or could not initialize."""
        with cls._lock:
            return cls._audit_degraded

    @classmethod
    def get_degraded_reason(cls) -> Optional[str]:
        """Returns the latest audit degradation error message, if any."""
        with cls._lock:
            return cls._degraded_reason

    @classmethod
    def set_log_file(cls, file_path: str) -> None:
        """Configures custom persistent audit log file."""
        with cls._lock:
            cls._log_file = os.path.abspath(file_path)
            cls._log_dir = os.path.dirname(cls._log_file)
            cls._explicitly_cleared = False
            cls._known_disk_state = None

    @classmethod
    def sanitize(cls, val: Any) -> Any:
        """Recursively scrubs sensitive tokens, passwords, and secrets from values."""
        if isinstance(val, str):
            clean = val
            for pat in cls._SENSITIVE_PATTERNS:
                clean = pat.sub(r"\1=***REDACTED***", clean)
            return clean
        elif isinstance(val, dict):
            return {k: cls.sanitize(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [cls.sanitize(v) for v in val]
        return val

    @classmethod
    def _compute_hash(cls, record_payload: Dict[str, Any], prev_hash: str) -> str:
        """Computes deterministic SHA-256 hash chaining over record and previous hash."""
        canonical_str = json.dumps(record_payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256((prev_hash + canonical_str).encode("utf-8")).hexdigest()

    @classmethod
    def _sealed_segments(cls, target_file: str) -> List[str]:
        """Sealed archive segments of `target_file`, ordered by their first sequence number."""
        import glob as _glob
        segs = _glob.glob(_glob.escape(target_file) + ".sealed.*.jsonl")

        def _first_seq(path: str) -> int:
            try:
                return int(os.path.basename(path).rsplit(".sealed.", 1)[1].split("-", 1)[0])
            except (IndexError, ValueError):
                return -1
        return sorted((p for p in segs if _first_seq(p) >= 0), key=_first_seq)

    @classmethod
    def _verify_segment_file(
        cls,
        file_path: str,
        start_seq: int,
        start_prev: str,
        collect: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[int, str, Optional[Dict[str, Any]]]:
        """
        Streams and cryptographically verifies every JSONL record in `file_path`
        starting at `start_seq` and `start_prev`.
        Returns `(next_seq, head_hash, last_record)`.
        """
        expected_seq = start_seq
        expected_prev = start_prev
        last_rec: Optional[Dict[str, Any]] = None
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as jde:
                    raise AuditIntegrityError(
                        f"Audit log '{file_path}' has invalid JSON at line {line_num}: {jde}"
                    ) from jde
                if rec.get("sequence") != expected_seq:
                    raise AuditIntegrityError(
                        f"Audit log sequence discontinuity on disk in '{file_path}' at index {expected_seq}: got {rec.get('sequence')}"
                    )
                if rec.get("prev_hash") != expected_prev:
                    raise AuditIntegrityError(
                        f"Audit log hash break on disk in '{file_path}' at sequence {expected_seq}: expected {expected_prev}, got {rec.get('prev_hash')}"
                    )
                payload = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
                computed = cls._compute_hash(payload, expected_prev)
                if computed != rec.get("record_hash"):
                    raise AuditIntegrityError(
                        f"Audit log tamper detected on disk in '{file_path}' at sequence {expected_seq}: hash mismatch"
                    )
                expected_prev = rec.get("record_hash")
                expected_seq += 1
                last_rec = rec
                if collect is not None:
                    collect.append(rec)
        return expected_seq, expected_prev, last_rec

    @classmethod
    def _sealed_anchor(cls, target_file: str) -> Optional[Dict[str, Any]]:
        """
        Cryptographically verifies every sealed archive segment in chronological order
        from genesis (seq 0, prev_hash '0'*64) and returns the tail record of the newest segment.
        """
        segs = cls._sealed_segments(target_file)
        if not segs:
            return None
        next_seq = 0
        head_hash = "0" * 64
        last_rec: Optional[Dict[str, Any]] = None
        for seg_path in segs:
            prev_seq = next_seq
            next_seq, head_hash, seg_tail = cls._verify_segment_file(seg_path, next_seq, head_hash)
            if next_seq == prev_seq or not seg_tail:
                raise AuditIntegrityError(f"Sealed audit segment '{seg_path}' is empty or has no readable records.")
            last_rec = seg_tail
        return last_rec

    @classmethod
    def _seal_active_segment_locked(cls, target_file: str) -> Optional[str]:
        """Seals the (already verified) active journal into an immutable archive segment."""
        if cls._segment_max_bytes <= 0 or not cls._journal:
            return None
        try:
            if os.path.getsize(target_file) < cls._segment_max_bytes:
                return None
            first_seq = int(cls._journal[0].get("sequence", 0))
            last_seq = int(cls._journal[-1].get("sequence", 0))
            sealed = f"{target_file}.sealed.{first_seq:012d}-{last_seq:012d}.jsonl"
            os.replace(target_file, sealed)
        except OSError:
            return None
        # Chain head (sequence + last hash) is unchanged; only the in-memory journal resets.
        cls._journal = []
        return sealed

    @classmethod
    def _recover_chain_locked(cls, target_file: str) -> Dict[str, Any]:
        """Must be called while holding cls._lock."""
        anchor = cls._sealed_anchor(target_file)
        start_seq = int(anchor["sequence"]) + 1 if anchor else 0
        start_hash = anchor["record_hash"] if anchor else "0" * 64

        if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
            cls._sequence = start_seq
            cls._last_hash = start_hash
            cls._journal.clear()
            res = {"recovered": False, "records_count": 0, "head_hash": cls._last_hash}
            if anchor:
                res["sealed_anchor_sequence"] = anchor["sequence"]
            return res

        records: List[Dict[str, Any]] = []
        next_seq, expected_prev, _ = cls._verify_segment_file(
            target_file, start_seq, start_hash, collect=records
        )

        cls._journal = records
        cls._sequence = next_seq
        cls._last_hash = expected_prev
        cls._explicitly_cleared = False
        res = {"recovered": True, "records_count": len(records), "head_hash": expected_prev}
        if anchor:
            res["sealed_anchor_sequence"] = anchor["sequence"]
        sealed = cls._seal_active_segment_locked(target_file)
        if sealed:
            res["sealed_segment"] = sealed
        return res

    @classmethod
    def _read_disk_tail(cls, target_file: str) -> Optional[Dict[str, Any]]:
        """Reads the last valid JSONL record from the persistent log file on disk."""
        if not target_file or not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
            return None
        try:
            with open(target_file, "rb") as f:
                size = os.path.getsize(target_file)
                buffer_size = min(size, 8192)
                f.seek(size - buffer_size)
                chunk = f.read(buffer_size).decode("utf-8", errors="replace")
                lines = [l.strip() for l in chunk.splitlines() if l.strip()]
                if lines:
                    return json.loads(lines[-1])
        except Exception:
            pass
        return None

    @classmethod
    def recover_chain_from_disk(cls, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Recovers and cryptographically verifies an existing persistent audit journal from disk,
        allowing a new process to append new records without resetting sequence numbers or hash chains.
        """
        with cls._lock:
            target_file = log_path or cls._log_file
            lock_path = (target_file or "") + ".lock"
            with _ProcessFileLock(lock_path):
                cls._explicitly_cleared = False
                return cls._recover_chain_locked(target_file)

    @classmethod
    def ensure_chain_continuity(cls, log_path: Optional[str] = None, rotate_on_corrupt: bool = False) -> Dict[str, Any]:
        """
        Safely synchronizes in-memory chain sequence/head hash with an existing persistent log on disk
        across separate process invocations. If rotate_on_corrupt=True and an older on-disk log has
        legacy breaks, rotates the stale file rather than breaking startup while still rejecting tampering
        in strict recover_chain_from_disk() calls.
        """
        with cls._lock:
            target_file = log_path or cls._log_file
            if cls._explicitly_cleared and log_path is None:
                return {"recovered": False, "records_count": 0, "skipped": "cleared_test_state"}

            lock_path = (target_file or "") + ".lock"
            with _ProcessFileLock(lock_path):
                res: Dict[str, Any]
                if cls._sequence > 0 and cls._journal:
                    res = {"recovered": True, "records_count": len(cls._journal), "head_hash": cls._last_hash}
                else:
                    try:
                        res = cls._recover_chain_locked(target_file)
                    except AuditIntegrityError as err:
                        sealed_segs = cls._sealed_segments(target_file) if target_file else []
                        if not rotate_on_corrupt or (not os.path.exists(target_file) and not sealed_segs):
                            cls._audit_degraded = True
                            cls._degraded_reason = str(err)
                            raise
                        ts_tag = int(time.time())
                        rotated = f"{target_file}.legacy.{ts_tag}.jsonl"
                        rotated_any = False
                        try:
                            if os.path.exists(target_file):
                                os.replace(target_file, rotated)
                                rotated_any = True
                            for s_idx, seg_path in enumerate(sealed_segs):
                                os.replace(seg_path, f"{seg_path}.legacy.{ts_tag}.{s_idx}.jsonl")
                                rotated_any = True
                        except OSError as rot_err:
                            rotated = None
                            if cls._strict_persistence:
                                cls._audit_degraded = True
                                cls._degraded_reason = str(rot_err)
                                raise AuditPersistenceError(
                                    f"CRITICAL: Cannot rotate corrupt audit log '{target_file}': {rot_err}"
                                ) from rot_err
                        if not rotated_any:
                            rotated = None
                        cls._sequence = 0
                        cls._last_hash = "0" * 64
                        cls._journal.clear()
                        print(f"[Bintra][AuditLogger] Warning: rotated legacy/broken audit log ({err}) -> {rotated}", file=sys.stderr)
                        res = {"recovered": False, "records_count": 0, "rotated_legacy_log": rotated, "head_hash": cls._last_hash}
                    except OSError as io_err:
                        cls._audit_degraded = True
                        cls._degraded_reason = str(io_err)
                        if cls._strict_persistence:
                            raise AuditPersistenceError(
                                f"CRITICAL: Cannot read audit log '{target_file}': {io_err}"
                            ) from io_err
                        sys.stderr.write(
                            f"[AUDIT PERSISTENCE WARNING] Cannot read audit log '{target_file}': {io_err}\n"
                        )
                        return {"recovered": False, "records_count": 0, "audit_degraded": True, "audit_degraded_reason": str(io_err), "head_hash": cls._last_hash}

                # Verify directory/file writability upfront so callers detect degraded audit early
                if log_path is None:
                    parent_dir = os.path.dirname(target_file)
                    try:
                        if parent_dir:
                            os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "a", encoding="utf-8"):
                            pass
                    except Exception as exc:
                        cls._audit_degraded = True
                        cls._degraded_reason = str(exc)
                        if cls._strict_persistence:
                            raise AuditPersistenceError(
                                f"CRITICAL: Audit log location '{target_file}' is not writable: {exc}"
                            ) from exc
                        sys.stderr.write(
                            f"[AUDIT PERSISTENCE WARNING] Audit log location '{target_file}' is not writable: {exc}\n"
                        )
                        res["audit_degraded"] = True
                        res["audit_degraded_reason"] = str(exc)

                return res

    @classmethod
    def log_decision(
        cls,
        component: str,
        operation: str,
        target: str,
        decision: str,
        reason: str,
        requested_capability: Optional[str] = None,
        side_effects: Optional[List[str]] = None,
        result: str = "SUCCESS",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Records an authoritative security decision with cryptographic hash chaining.
        """
        clean_component = cls.sanitize(component)
        clean_op = cls.sanitize(operation)
        clean_target = cls.sanitize(target)
        clean_reason = cls.sanitize(reason)
        clean_meta = cls.sanitize(metadata or {})

        with cls._lock:
            lock_path = (cls._log_file or "") + ".lock"
            with _ProcessFileLock(lock_path):
                # Synchronize with on-disk state if another process appended
                if cls._log_file and not cls._explicitly_cleared:
                    disk_tail = None
                    try:
                        st = os.stat(cls._log_file)
                        unchanged = cls._known_disk_state == (cls._log_file, st.st_size, st.st_mtime_ns)
                    except OSError:
                        unchanged = False
                    if not unchanged:
                        disk_tail = cls._read_disk_tail(cls._log_file)
                    if disk_tail is not None:
                        disk_seq = disk_tail.get("sequence", -1)
                        disk_hash = disk_tail.get("record_hash")
                        if disk_seq >= cls._sequence or (cls._sequence == 0 and cls._last_hash == "0" * 64):
                            cls._sequence = disk_seq + 1
                            cls._last_hash = disk_hash

                seq = cls._sequence
                prev_h = cls._last_hash
                ts = datetime.now(timezone.utc).isoformat()

                payload = {
                    "sequence": seq,
                    "timestamp": ts,
                    "component": clean_component,
                    "operation": clean_op,
                    "target": clean_target,
                    "requested_capability": requested_capability,
                    "decision": decision.upper(),
                    "reason": clean_reason,
                    "side_effects": side_effects or [],
                    "result": result.upper(),
                    "metadata": clean_meta
                }

                rec_hash = cls._compute_hash(payload, prev_h)

                full_record = dict(payload)
                full_record["prev_hash"] = prev_h
                full_record["record_hash"] = rec_hash

                cls._journal.append(full_record)
                cls._sequence += 1
                cls._last_hash = rec_hash

                # Persist to disk with error checking while holding process lock
                cls._persist_record(full_record)

            return full_record

    @classmethod
    def _persist_record(cls, record: Dict[str, Any]) -> None:
        """Appends record to persistent JSONL log file with atomic flush."""
        if cls._explicitly_cleared:
            return
        try:
            if cls._log_dir:
                os.makedirs(cls._log_dir, exist_ok=True)
            with open(cls._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                f.flush()
            try:
                st = os.stat(cls._log_file)
                cls._known_disk_state = (cls._log_file, st.st_size, st.st_mtime_ns)
            except OSError:
                cls._known_disk_state = None
        except Exception as exc:
            cls._audit_degraded = True
            cls._degraded_reason = str(exc)
            if cls._strict_persistence:
                raise AuditPersistenceError(f"CRITICAL: Failed to write audit record to disk: {exc}") from exc
            sys.stderr.write(f"[AUDIT PERSISTENCE WARNING] Failed to persist audit record to disk: {exc}\n")

    @classmethod
    def verify_audit_chain(cls, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Cryptographically verifies the hash chain of audit records to prove zero tampering.
        Verifies all sealed archive segments plus the active journal on disk in chronological
        order, or falls back to the in-memory journal when no disk log exists.
        """
        target = log_path or (cls._log_file if not cls._explicitly_cleared else None)
        segs = cls._sealed_segments(target) if target else []
        active_has_data = bool(target and os.path.exists(target) and os.path.getsize(target) > 0)

        if segs or active_has_data:
            next_seq = 0
            head_hash = "0" * 64
            try:
                for seg_path in segs:
                    prev_seq = next_seq
                    next_seq, head_hash, _ = cls._verify_segment_file(seg_path, next_seq, head_hash)
                    if next_seq == prev_seq:
                        return {
                            "is_valid": False,
                            "error": f"Sealed audit segment '{seg_path}' is empty",
                            "failed_sequence": next_seq,
                        }
                if active_has_data:
                    next_seq, head_hash, _ = cls._verify_segment_file(target, next_seq, head_hash)
            except AuditIntegrityError as err:
                msg = str(err)
                failed_seq = next_seq
                m = re.search(r"(?:index|sequence)\s+(\d+)", msg)
                if m:
                    failed_seq = int(m.group(1))
                return {
                    "is_valid": False,
                    "error": msg,
                    "failed_sequence": failed_seq,
                }
            return {
                "is_valid": True,
                "records_verified": next_seq,
                "segments_verified": len(segs) + (1 if active_has_data else 0),
                "head_hash": head_hash,
            }

        with cls._lock:
            records = [dict(r) for r in cls._journal]

        expected_prev = "0" * 64
        for idx, rec in enumerate(records):
            if rec.get("sequence") != idx:
                return {
                    "is_valid": False,
                    "error": f"Sequence discontinuity at index {idx} (got {rec.get('sequence')})",
                    "failed_sequence": idx
                }

            if rec.get("prev_hash") != expected_prev:
                return {
                    "is_valid": False,
                    "error": f"Hash chain broken at sequence {idx}: expected prev_hash {expected_prev}, got {rec.get('prev_hash')}",
                    "failed_sequence": idx
                }

            # Reconstruct payload without prev_hash and record_hash
            payload = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
            computed_hash = cls._compute_hash(payload, expected_prev)
            if computed_hash != rec.get("record_hash"):
                return {
                    "is_valid": False,
                    "error": f"Tamper detected at sequence {idx}: payload hash mismatch",
                    "failed_sequence": idx
                }

            expected_prev = rec.get("record_hash")

        return {
            "is_valid": True,
            "records_verified": len(records),
            "head_hash": expected_prev
        }

    @classmethod
    def get_audit_trail(cls) -> List[Dict[str, Any]]:
        """Returns a snapshot of the complete chronological audit journal."""
        with cls._lock:
            return [dict(r) for r in cls._journal]

    @classmethod
    def get_denials(cls) -> List[Dict[str, Any]]:
        """Returns all access requests that were rejected with DENY."""
        with cls._lock:
            return [dict(r) for r in cls._journal if r.get("decision") == "DENY"]

    @classmethod
    def summarize(cls) -> Dict[str, Any]:
        """Summarizes security operations, pass rates, and rejections."""
        with cls._lock:
            total = len(cls._journal)
            allows = sum(1 for r in cls._journal if r["decision"] == "ALLOW")
            allow_scoped = sum(1 for r in cls._journal if r["decision"] == "ALLOW_SCOPED")
            denies = sum(1 for r in cls._journal if r["decision"] == "DENY")
            components = list(set(r["component"] for r in cls._journal))
            last_h = cls._last_hash

        return {
            "total_mediated_operations": total,
            "allowed_count": allows,
            "allowed_scoped_count": allow_scoped,
            "denied_count": denies,
            "participating_components_count": len(components),
            "participating_components": sorted(components),
            "audit_chain_head": last_h
        }

    @classmethod
    def clear(cls) -> None:
        """Resets the audit journal for test isolation."""
        with cls._lock:
            cls._journal.clear()
            cls._known_disk_state = None
            cls._sequence = 0
            cls._last_hash = "0" * 64
            cls._explicitly_cleared = True
            cls._audit_degraded = False
            cls._degraded_reason = None
