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
    _tamper_detected: bool = False
    _tamper_reason: Optional[str] = None
    # (path, size, mtime_ns) of the journal right after this process's last append. If the file
    # still matches, no other process has appended and the tail re-read (an extra file open per
    # decision, several ms each on Windows) can be skipped.
    _known_disk_state: Optional[tuple] = None

    # Default persistent log path
    _log_dir = os.path.join(os.path.expanduser("~"), ".bintra", "logs")
    _log_file = os.path.join(_log_dir, "audit.jsonl")

    # Segment sealing: once the active journal exceeds this size (after a full successful
    # verification) it is sealed into an immutable archive and a new segment continues the
    # SAME hash chain. Digest caching in `.sealedcache.json` skips JSON re-parsing on
    # intact archives at startup (still hashing archive digests), while
    # `recover_chain_from_disk()` and `verify_audit_chain(full_verify=True)` verify
    # every record unconditionally (BINTRA_AUDIT_SEGMENT_MB overrides; 0 disables).
    try:
        _segment_max_bytes = int(float(os.environ.get("BINTRA_AUDIT_SEGMENT_MB", "2")) * 1024 * 1024)
    except ValueError:
        _segment_max_bytes = 2 * 1024 * 1024

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
    def mark_tampered(cls, reason: str) -> None:
        """Permanently flags tamper detection for this session so downstream gates fail closed."""
        with cls._lock:
            cls._tamper_detected = True
            cls._tamper_reason = str(reason)
            cls._audit_degraded = True
            cls._degraded_reason = str(reason)

    @classmethod
    def is_tamper_detected(cls) -> bool:
        """Returns True if cryptographic audit tampering or log deletion was detected."""
        with cls._lock:
            return cls._tamper_detected

    @classmethod
    def get_tamper_reason(cls) -> Optional[str]:
        """Returns the recorded audit tamper/integrity violation message, if any."""
        with cls._lock:
            return cls._tamper_reason

    @staticmethod
    def _is_tamper_integrity_error(err: AuditIntegrityError) -> bool:
        """True when an AuditIntegrityError indicates active hash/sequence tampering rather than an unchained legacy format."""
        msg = str(err).lower()
        tamper_markers = (
            "tamper detected",
            "hash mismatch",
            "hash break",
            "hash chain broken",
            "sequence discontinuity",
            "bounds",
            "missing or truncated",
            "empty or has no readable",
            "corrupt json",
            "invalid json",
        )
        return any(m in msg for m in tamper_markers)

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
    def _sealed_filename_bounds(cls, path: str) -> Optional[Tuple[int, int]]:
        """Extract `(first_seq, last_seq)` from a sealed segment filename, if well-formed."""
        try:
            bounds_str = os.path.basename(path).rsplit(".sealed.", 1)[1].rsplit(".jsonl", 1)[0]
            first_s, last_s = bounds_str.split("-", 1)
            return int(first_s), int(last_s)
        except (IndexError, ValueError):
            return None

    @classmethod
    def _sealed_segments(cls, target_file: str) -> List[str]:
        """Sealed archive segments of `target_file`, ordered by their first sequence number."""
        import glob as _glob
        segs = _glob.glob(_glob.escape(target_file) + ".sealed.*.jsonl")

        def _first_seq(path: str) -> int:
            b = cls._sealed_filename_bounds(path)
            return b[0] if b else -1

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

    @staticmethod
    def _cache_entry_commitment(
        prev_commitment: str,
        key: str,
        digest: str,
        start_seq: int,
        start_prev: str,
        next_seq: int,
        head_hash: str,
        tail_hash: str,
    ) -> str:
        raw = f"{prev_commitment}|{key}|{digest}|{start_seq}|{start_prev}|{next_seq}|{head_hash}|{tail_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def _sealed_anchor(cls, target_file: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Cryptographically verifies every sealed archive segment in chronological order
        from genesis (seq 0, prev_hash '0'*64) and returns the tail record of the newest segment.
        When `use_cache=False`, skips the digest cache and verifies every record unconditionally.
        """
        segs = cls._sealed_segments(target_file)
        if not segs:
            return None
        cache = cls._load_sealed_cache(target_file) if use_cache else {}
        cache_dirty = False
        next_seq = 0
        head_hash = "0" * 64
        prev_commitment = "0" * 64
        last_rec: Optional[Dict[str, Any]] = None
        for seg_path in segs:
            prev_seq, prev_hash = next_seq, head_hash
            key = os.path.basename(seg_path)
            digest = cls._file_sha256(seg_path)
            bounds = cls._sealed_filename_bounds(seg_path)
            entry = cache.get(key) if use_cache else None
            cache_valid = False
            if (
                isinstance(entry, dict)
                and entry.get("sha256") == digest
                and entry.get("start_seq") == prev_seq
                and entry.get("start_prev") == prev_hash
                and isinstance(entry.get("tail"), dict)
                and isinstance(entry.get("next_seq"), int)
                and entry["next_seq"] > prev_seq
            ):
                tail = entry["tail"]
                expected_commit = cls._cache_entry_commitment(
                    prev_commitment,
                    key,
                    digest,
                    prev_seq,
                    prev_hash,
                    entry["next_seq"],
                    str(entry.get("head_hash", "")),
                    str(tail.get("record_hash", "")),
                )
                bounds_ok = (bounds is None or bounds == (prev_seq, entry["next_seq"] - 1))
                if (
                    bounds_ok
                    and tail.get("sequence") == entry["next_seq"] - 1
                    and tail.get("record_hash") == entry.get("head_hash")
                    and entry.get("chain_commitment") == expected_commit
                ):
                    cache_valid = True
                    next_seq, head_hash, seg_tail = entry["next_seq"], entry["head_hash"], tail
                    prev_commitment = expected_commit

            if not cache_valid:
                next_seq, head_hash, seg_tail = cls._verify_segment_file(seg_path, prev_seq, prev_hash)
                if next_seq == prev_seq or not seg_tail:
                    raise AuditIntegrityError(f"Sealed audit segment '{seg_path}' is empty or has no readable records.")
                if bounds is not None and bounds != (prev_seq, next_seq - 1):
                    raise AuditIntegrityError(
                        f"Sealed audit segment '{seg_path}' bounds {bounds} mismatch verified sequence range {(prev_seq, next_seq - 1)}."
                    )
                prev_commitment = cls._cache_entry_commitment(
                    prev_commitment,
                    key,
                    digest,
                    prev_seq,
                    prev_hash,
                    next_seq,
                    head_hash,
                    str(seg_tail.get("record_hash", "")),
                )
                if use_cache:
                    cache[key] = {
                        "sha256": digest,
                        "start_seq": prev_seq,
                        "start_prev": prev_hash,
                        "next_seq": next_seq,
                        "head_hash": head_hash,
                        "tail": seg_tail,
                        "chain_commitment": prev_commitment,
                    }
                    cache_dirty = True
            last_rec = seg_tail
        if cache_dirty:
            cls._store_sealed_cache(target_file, cache)
        return last_rec

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _sealed_cache_path(target_file: str) -> str:
        return f"{target_file}.sealedcache.json"

    @classmethod
    def _load_sealed_cache(cls, target_file: str) -> Dict[str, Any]:
        try:
            with open(cls._sealed_cache_path(target_file), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @classmethod
    def _store_sealed_cache(cls, target_file: str, cache: Dict[str, Any]) -> None:
        tmp = cls._sealed_cache_path(target_file) + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(cache, fh, ensure_ascii=False)
            os.replace(tmp, cls._sealed_cache_path(target_file))
        except OSError:
            pass  # the cache is an optimisation only; verification already succeeded

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
    def _recover_chain_locked(cls, target_file: str, allow_seal: bool = True, use_cache: bool = True) -> Dict[str, Any]:
        """
        Must be called while holding cls._lock. `allow_seal` must only be True for the active
        journal while the inter-process lock is held (archives are never re-sealed).
        """
        anchor = cls._sealed_anchor(target_file, use_cache=use_cache)
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
        try:
            st = os.stat(target_file)
            cls._known_disk_state = (target_file, st.st_size, st.st_mtime_ns)
        except OSError:
            cls._known_disk_state = None
        res = {"recovered": True, "records_count": len(records), "head_hash": expected_prev}
        if anchor:
            res["sealed_anchor_sequence"] = anchor["sequence"]
        sealed = cls._seal_active_segment_locked(target_file) if allow_seal else None
        if sealed:
            res["sealed_segment"] = sealed
            cls._known_disk_state = None
        return res

    @classmethod
    def _read_disk_tail(cls, target_file: str) -> Optional[Dict[str, Any]]:
        """Reads and hash-verifies the last JSONL record from the persistent log file on disk."""
        if not target_file or not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
            return None
        with open(target_file, "rb") as f:
            size = os.path.getsize(target_file)
            buf_size = 8192
            raw_line = b""
            while True:
                read_len = min(size, buf_size)
                offset = size - read_len
                f.seek(offset)
                chunk = f.read(read_len)
                # Trim trailing blank lines/CR/LF when splitting
                lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
                if not lines:
                    if offset == 0:
                        return None
                    buf_size *= 2
                    continue
                # Ensure we didn't bisect the final line unless offset reached start of file
                if len(lines) >= 2 or offset == 0 or chunk.startswith(b"\n"):
                    raw_line = lines[-1]
                    break
                buf_size *= 2

        try:
            rec = json.loads(raw_line.decode("utf-8"))
        except Exception as exc:
            raise AuditIntegrityError(
                f"Audit log tail record in '{target_file}' is corrupt JSON: {exc}"
            ) from exc
        if not isinstance(rec, dict) or "sequence" not in rec or "prev_hash" not in rec or "record_hash" not in rec:
            raise AuditIntegrityError(f"Audit log tail record in '{target_file}' lacks required hash-chain fields.")
        payload = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
        if cls._compute_hash(payload, str(rec["prev_hash"])) != rec.get("record_hash"):
            raise AuditIntegrityError(f"Audit log tail tamper detected in '{target_file}': hash mismatch.")
        return rec

    @classmethod
    def recover_chain_from_disk(cls, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Recovers and cryptographically verifies every record across sealed and active journals from disk,
        never trusting unverified digest caches, allowing safe multi-process chain continuation.
        """
        with cls._lock:
            target_file = log_path or cls._log_file
            lock_path = (target_file or "") + ".lock"
            with _ProcessFileLock(lock_path) as plock:
                cls._explicitly_cleared = False
                is_active = bool(cls._log_file) and os.path.abspath(target_file) == os.path.abspath(cls._log_file)
                return cls._recover_chain_locked(target_file, allow_seal=is_active and plock.acquired, use_cache=False)

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
            with _ProcessFileLock(lock_path) as plock:
                res: Dict[str, Any]
                disk_matches_mem = False
                if cls._sequence > 0 and cls._journal and target_file and cls._known_disk_state:
                    try:
                        st = os.stat(target_file)
                        disk_matches_mem = cls._known_disk_state == (target_file, st.st_size, st.st_mtime_ns)
                    except OSError:
                        if cls._known_disk_state[0] == target_file:
                            reason = f"Audit log tamper/deletion detected: previously verified file '{target_file}' vanished from disk"
                            cls.mark_tampered(reason)
                            raise AuditIntegrityError(reason)
                        disk_matches_mem = False

                if cls._sequence > 0 and cls._journal and (disk_matches_mem or not target_file):
                    res = {"recovered": True, "records_count": len(cls._journal), "head_hash": cls._last_hash}
                else:
                    try:
                        res = cls._recover_chain_locked(target_file, allow_seal=plock.acquired, use_cache=True)
                    except AuditIntegrityError as err:
                        is_tamper = cls._is_tamper_integrity_error(err)
                        if is_tamper:
                            cls.mark_tampered(str(err))
                        else:
                            cls._audit_degraded = True
                            cls._degraded_reason = str(err)
                        sealed_segs = cls._sealed_segments(target_file) if target_file else []
                        # Never rotate away tamper evidence (hash/sequence violations); only pre-chain legacy logs may rotate.
                        if is_tamper or not rotate_on_corrupt or (not os.path.exists(target_file) and not sealed_segs):
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
                        cls._known_disk_state = None
                        cls._journal.clear()
                        cls._audit_degraded = True
                        cls._degraded_reason = str(err)
                        print(f"[Bintra][AuditLogger] Warning: rotated legacy unchained audit log ({err}) -> {rotated}", file=sys.stderr)
                        res = {"recovered": False, "records_count": 0, "rotated_legacy_log": rotated, "audit_degraded": True, "head_hash": cls._last_hash}
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
        In-memory chain state is committed ONLY after durable disk persistence succeeds.
        """
        clean_component = cls.sanitize(component)
        clean_op = cls.sanitize(operation)
        clean_target = cls.sanitize(target)
        clean_reason = cls.sanitize(reason)
        clean_meta = cls.sanitize(metadata or {})

        with cls._lock:
            lock_path = (cls._log_file or "") + ".lock"
            with _ProcessFileLock(lock_path) as plock:
                if cls._log_file and cls._tamper_detected and not cls._explicitly_cleared:
                    if cls._strict_persistence:
                        raise AuditIntegrityError(
                            f"CRITICAL: Refusing to append to tampered audit log: {cls._tamper_reason or 'integrity violation'}"
                        )
                    return {
                        "sequence": None, "timestamp": datetime.now(timezone.utc).isoformat(),
                        "component": clean_component, "operation": clean_op, "target": clean_target,
                        "requested_capability": requested_capability, "decision": decision.upper(),
                        "reason": clean_reason, "side_effects": side_effects or [], "result": result.upper(),
                        "metadata": clean_meta, "persisted": False, "tamper_detected": True,
                    }
                if cls._log_file and not plock.acquired and not cls._explicitly_cleared:
                    # Never append without the inter-process lock: two writers would emit the
                    # same sequence number and silently break the hash chain on disk. The
                    # decision is reported (audit marked degraded) but not chained or persisted.
                    cls._audit_degraded = True
                    cls._degraded_reason = cls._degraded_reason or f"Audit lock '{lock_path}' not acquired; record not persisted."
                    return {
                        "sequence": None, "timestamp": datetime.now(timezone.utc).isoformat(),
                        "component": clean_component, "operation": clean_op, "target": clean_target,
                        "requested_capability": requested_capability, "decision": decision.upper(),
                        "reason": clean_reason, "side_effects": side_effects or [], "result": result.upper(),
                        "metadata": clean_meta, "persisted": False,
                    }
                # Synchronize with on-disk state if another process appended or sealed
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
                    elif cls._sequence == 0 and cls._last_hash == "0" * 64 and cls._sealed_segments(cls._log_file):
                        anchor = cls._sealed_anchor(cls._log_file, use_cache=True)
                        if anchor:
                            cls._sequence = int(anchor["sequence"]) + 1
                            cls._last_hash = anchor["record_hash"]

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

                # Persist BEFORE committing in-memory chain state so write failures never corrupt sequence/hash
                if cls._log_file and not cls._explicitly_cleared:
                    if not cls._persist_record(full_record):
                        return {
                            "sequence": None, "timestamp": ts,
                            "component": clean_component, "operation": clean_op, "target": clean_target,
                            "requested_capability": requested_capability, "decision": decision.upper(),
                            "reason": clean_reason, "side_effects": side_effects or [], "result": result.upper(),
                            "metadata": clean_meta, "persisted": False,
                        }

                cls._journal.append(full_record)
                cls._sequence += 1
                cls._last_hash = rec_hash

            return full_record

    @classmethod
    def _persist_record(cls, record: Dict[str, Any]) -> bool:
        """Appends record atomically to persistent JSONL log file, rolling back partial writes on error."""
        if cls._explicitly_cleared:
            return True
        try:
            if cls._log_dir:
                os.makedirs(cls._log_dir, exist_ok=True)
            encoded = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
            with open(cls._log_file, "a+b") as f:
                pre_size = f.seek(0, os.SEEK_END)
                try:
                    f.write(encoded)
                    f.flush()
                    if hasattr(f, "fileno"):
                        try:
                            fd = f.fileno()
                        except (OSError, ValueError):
                            fd = None
                        if isinstance(fd, int):
                            os.fsync(fd)
                except Exception:
                    try:
                        f.truncate(pre_size)
                        f.flush()
                    except OSError:
                        pass
                    raise
            try:
                st = os.stat(cls._log_file)
                cls._known_disk_state = (cls._log_file, st.st_size, st.st_mtime_ns)
            except OSError:
                cls._known_disk_state = None
            return True
        except Exception as exc:
            cls._known_disk_state = None
            cls._audit_degraded = True
            cls._degraded_reason = str(exc)
            if cls._strict_persistence:
                raise AuditPersistenceError(f"CRITICAL: Failed to write audit record to disk: {exc}") from exc
            sys.stderr.write(f"[AUDIT PERSISTENCE WARNING] Failed to persist audit record to disk: {exc}\n")
            return False

    @classmethod
    def verify_audit_chain(cls, log_path: Optional[str] = None, full_verify: bool = True) -> Dict[str, Any]:
        """
        Cryptographically verifies the hash chain of audit records to prove zero tampering.
        When `full_verify=True` (default), verifies every record across all sealed archives
        and active journal from genesis without trusting `.sealedcache.json`.
        When `full_verify=False`, uses digest-cached sealed-segment verification plus full
        per-record verification of the active segment (still hashing archive digests cleanly).
        """
        with cls._lock:
            target = log_path or (cls._log_file if not cls._explicitly_cleared else None)
            lock_path = (target + ".lock") if target else ""
            with _ProcessFileLock(lock_path, fail_closed=False):
                segs = cls._sealed_segments(target) if target else []
                active_exists = bool(target and os.path.exists(target))
                active_has_data = bool(active_exists and os.path.getsize(target) > 0)

                if segs or active_has_data:
                    next_seq = 0
                    head_hash = "0" * 64
                    archived_bytes = 0
                    try:
                        if not full_verify and segs:
                            anchor = cls._sealed_anchor(target, use_cache=True)
                            if anchor:
                                next_seq = int(anchor["sequence"]) + 1
                                head_hash = anchor["record_hash"]
                            for seg_path in segs:
                                archived_bytes += os.path.getsize(seg_path)
                        else:
                            for seg_path in segs:
                                prev_seq = next_seq
                                next_seq, head_hash, _ = cls._verify_segment_file(seg_path, next_seq, head_hash)
                                archived_bytes += os.path.getsize(seg_path)
                                if next_seq == prev_seq:
                                    return {
                                        "is_valid": False,
                                        "error": f"Sealed audit segment '{seg_path}' is empty",
                                        "failed_sequence": next_seq,
                                    }
                                bounds = cls._sealed_filename_bounds(seg_path)
                                if bounds is not None and bounds != (prev_seq, next_seq - 1):
                                    return {
                                        "is_valid": False,
                                        "error": f"Sealed audit segment '{seg_path}' filename bounds {bounds} mismatch records {(prev_seq, next_seq - 1)}",
                                        "failed_sequence": prev_seq,
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
                        "verification_mode": "full_record_chain" if full_verify else "sealed_digest_cache",
                        "bounded_cost": False,
                        "archived_bytes_scanned": archived_bytes,
                    }

                if (
                    target
                    and not cls._explicitly_cleared
                    and cls._log_file
                    and os.path.abspath(target) == os.path.abspath(cls._log_file)
                    and cls._journal
                ):
                    return {
                        "is_valid": False,
                        "error": f"Persistent audit journal '{target}' is missing or truncated to empty while {len(cls._journal)} records exist in memory",
                        "failed_sequence": 0,
                    }

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
            cls._tamper_detected = False
            cls._tamper_reason = None
