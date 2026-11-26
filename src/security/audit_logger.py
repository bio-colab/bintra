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
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ._audit_lock import AuditIntegrityError, AuditPersistenceError, _ProcessFileLock
from ._audit_storage import (
    NON_PAYLOAD_FIELDS,
    append_record_atomic,
    cache_entry_commitment,
    compute_record_hash,
    compute_record_hmac,
    file_sha256,
    get_audit_hmac_key,
    load_sealed_cache,
    parse_sealed_filename_bounds,
    read_disk_tail,
    scan_sealed_segments,
    sealed_cache_path,
    store_sealed_cache,
    verify_record_hmac_if_configured,
    verify_segment_file,
)
from .config import (
    AUDIT_SENSITIVE_PATTERNS,
    default_audit_log_dir,
    default_audit_log_file,
    resolve_audit_segment_max_bytes,
)

_TAMPER_MARKERS = (
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
    "malformed sealed",
)


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
    _known_disk_state: Optional[tuple] = None

    _log_dir = default_audit_log_dir()
    _log_file = default_audit_log_file()
    _segment_max_bytes = resolve_audit_segment_max_bytes()
    _SENSITIVE_PATTERNS = list(AUDIT_SENSITIVE_PATTERNS)

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
        """True when an AuditIntegrityError indicates active hash/sequence tampering rather than legacy format."""
        msg = str(err).lower()
        return any(marker in msg for marker in _TAMPER_MARKERS)

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
        if isinstance(val, dict):
            return {k: cls.sanitize(v) for k, v in val.items()}
        if isinstance(val, list):
            return [cls.sanitize(v) for v in val]
        return val

    @classmethod
    def _compute_hash(cls, record_payload: Dict[str, Any], prev_hash: str) -> str:
        """Computes deterministic SHA-256 hash chaining over record and previous hash."""
        return compute_record_hash(record_payload, prev_hash)

    @classmethod
    def _sealed_filename_bounds(cls, path: str) -> Optional[Tuple[int, int]]:
        """Extracts `(first_seq, last_seq)` from a sealed segment filename, if well-formed."""
        return parse_sealed_filename_bounds(path)

    @classmethod
    def _sealed_segments(cls, target_file: str) -> List[str]:
        """Sealed archive segments of `target_file`, ordered by their first sequence number."""
        valid, malformed = scan_sealed_segments(target_file)
        if malformed:
            raise AuditIntegrityError(
                f"Malformed sealed audit segment filename(s) detected for '{target_file}': {malformed[0]}"
            )
        return valid

    @classmethod
    def _verify_segment_file(
        cls,
        file_path: str,
        start_seq: int,
        start_prev: str,
        collect: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[int, str, Optional[Dict[str, Any]]]:
        """Streams and cryptographically verifies every JSONL record in `file_path`."""
        return verify_segment_file(
            file_path,
            start_seq,
            start_prev,
            collect=collect,
            hash_fn=cls._compute_hash,
        )

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
        return cache_entry_commitment(
            prev_commitment,
            key,
            digest,
            start_seq,
            start_prev,
            next_seq,
            head_hash,
            tail_hash,
        )

    @classmethod
    def _sealed_anchor(cls, target_file: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Cryptographically verifies every sealed archive segment in chronological order
        from genesis (seq 0, prev_hash '0'*64) and returns the tail record of the newest segment.
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
                bounds_ok = bounds is None or bounds == (prev_seq, entry["next_seq"] - 1)
                hmac_key = get_audit_hmac_key()
                hmac_ok = True
                if hmac_key:
                    try:
                        verify_record_hmac_if_configured(tail, seg_path, tail.get("sequence"), hmac_key=hmac_key)
                    except AuditIntegrityError:
                        hmac_ok = False
                if (
                    bounds_ok
                    and hmac_ok
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
        return file_sha256(path)

    @staticmethod
    def _sealed_cache_path(target_file: str) -> str:
        return sealed_cache_path(target_file)

    @classmethod
    def _load_sealed_cache(cls, target_file: str) -> Dict[str, Any]:
        return load_sealed_cache(target_file)

    @classmethod
    def _store_sealed_cache(cls, target_file: str, cache: Dict[str, Any]) -> None:
        store_sealed_cache(target_file, cache)

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
        next_seq, expected_prev, _ = cls._verify_segment_file(target_file, start_seq, start_hash, collect=records)

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
        return read_disk_tail(target_file, hash_fn=cls._compute_hash)

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
    def _handle_legacy_rotation(cls, target_file: str, err: AuditIntegrityError, rotate_on_corrupt: bool) -> Dict[str, Any]:
        is_tamper = cls._is_tamper_integrity_error(err)
        if is_tamper:
            cls.mark_tampered(str(err))
        else:
            cls._audit_degraded = True
            cls._degraded_reason = str(err)

        try:
            sealed_segs = cls._sealed_segments(target_file) if target_file else []
        except AuditIntegrityError:
            sealed_segs = []

        if is_tamper or not rotate_on_corrupt or (not os.path.exists(target_file) and not sealed_segs):
            raise err

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
            if cls._strict_persistence:
                cls._audit_degraded = True
                cls._degraded_reason = str(rot_err)
                raise AuditPersistenceError(
                    f"CRITICAL: Cannot rotate corrupt audit log '{target_file}': {rot_err}"
                ) from rot_err
            rotated_any = False

        if not rotated_any:
            rotated = None
        cls._sequence = 0
        cls._last_hash = "0" * 64
        cls._known_disk_state = None
        cls._journal.clear()
        cls._audit_degraded = True
        cls._degraded_reason = str(err)
        print(f"[Bintra][AuditLogger] Warning: rotated legacy unchained audit log ({err}) -> {rotated}", file=sys.stderr)
        return {
            "recovered": False,
            "records_count": 0,
            "rotated_legacy_log": rotated,
            "audit_degraded": True,
            "head_hash": cls._last_hash,
        }

    @classmethod
    def _probe_writable(cls, target_file: str, res: Dict[str, Any]) -> None:
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
            sys.stderr.write(f"[AUDIT PERSISTENCE WARNING] Audit log location '{target_file}' is not writable: {exc}\n")
            res["audit_degraded"] = True
            res["audit_degraded_reason"] = str(exc)

    @classmethod
    def ensure_chain_continuity(cls, log_path: Optional[str] = None, rotate_on_corrupt: bool = False) -> Dict[str, Any]:
        """Safely synchronizes in-memory chain sequence/head hash with an existing persistent log on disk."""
        with cls._lock:
            target_file = log_path or cls._log_file
            if cls._explicitly_cleared and log_path is None:
                return {"recovered": False, "records_count": 0, "skipped": "cleared_test_state"}

            lock_path = (target_file or "") + ".lock"
            with _ProcessFileLock(lock_path) as plock:
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

                if cls._sequence > 0 and cls._journal and (disk_matches_mem or not target_file):
                    res = {"recovered": True, "records_count": len(cls._journal), "head_hash": cls._last_hash}
                else:
                    try:
                        res = cls._recover_chain_locked(target_file, allow_seal=plock.acquired, use_cache=True)
                    except AuditIntegrityError as err:
                        res = cls._handle_legacy_rotation(target_file, err, rotate_on_corrupt)
                    except OSError as io_err:
                        cls._audit_degraded = True
                        cls._degraded_reason = str(io_err)
                        if cls._strict_persistence:
                            raise AuditPersistenceError(
                                f"CRITICAL: Cannot read audit log '{target_file}': {io_err}"
                            ) from io_err
                        sys.stderr.write(f"[AUDIT PERSISTENCE WARNING] Cannot read audit log '{target_file}': {io_err}\n")
                        return {
                            "recovered": False,
                            "records_count": 0,
                            "audit_degraded": True,
                            "audit_degraded_reason": str(io_err),
                            "head_hash": cls._last_hash,
                        }

                if log_path is None:
                    cls._probe_writable(target_file, res)
                return res

    @staticmethod
    def _build_unpersisted_record(
        ts: str,
        component: Any,
        operation: Any,
        target: Any,
        requested_capability: Optional[str],
        decision: str,
        reason: Any,
        side_effects: List[str],
        result: str,
        metadata: Any,
        tamper_detected: bool = False,
    ) -> Dict[str, Any]:
        rec = {
            "sequence": None,
            "timestamp": ts,
            "component": component,
            "operation": operation,
            "target": target,
            "requested_capability": requested_capability,
            "decision": decision,
            "reason": reason,
            "side_effects": side_effects,
            "result": result,
            "metadata": metadata,
            "persisted": False,
        }
        if tamper_detected:
            rec["tamper_detected"] = True
        return rec

    @classmethod
    def _sync_sequence_from_disk_locked(cls) -> None:
        if not cls._log_file or cls._explicitly_cleared:
            return
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
        metadata: Optional[Dict[str, Any]] = None,
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
        clean_effects = side_effects or []
        norm_decision = decision.upper()
        norm_result = result.upper()

        with cls._lock:
            lock_path = (cls._log_file or "") + ".lock"
            with _ProcessFileLock(lock_path) as plock:
                ts = datetime.now(timezone.utc).isoformat()
                if cls._log_file and cls._tamper_detected and not cls._explicitly_cleared:
                    if cls._strict_persistence:
                        raise AuditIntegrityError(
                            f"CRITICAL: Refusing to append to tampered audit log: {cls._tamper_reason or 'integrity violation'}"
                        )
                    return cls._build_unpersisted_record(
                        ts,
                        clean_component,
                        clean_op,
                        clean_target,
                        requested_capability,
                        norm_decision,
                        clean_reason,
                        clean_effects,
                        norm_result,
                        clean_meta,
                        tamper_detected=True,
                    )

                if cls._log_file and not plock.acquired and not cls._explicitly_cleared:
                    cls._audit_degraded = True
                    cls._degraded_reason = cls._degraded_reason or f"Audit lock '{lock_path}' not acquired; record not persisted."
                    return cls._build_unpersisted_record(
                        ts,
                        clean_component,
                        clean_op,
                        clean_target,
                        requested_capability,
                        norm_decision,
                        clean_reason,
                        clean_effects,
                        norm_result,
                        clean_meta,
                    )

                cls._sync_sequence_from_disk_locked()

                payload = {
                    "sequence": cls._sequence,
                    "timestamp": ts,
                    "component": clean_component,
                    "operation": clean_op,
                    "target": clean_target,
                    "requested_capability": requested_capability,
                    "decision": norm_decision,
                    "reason": clean_reason,
                    "side_effects": clean_effects,
                    "result": norm_result,
                    "metadata": clean_meta,
                }
                rec_hash = cls._compute_hash(payload, cls._last_hash)
                full_record = dict(payload)
                full_record["prev_hash"] = cls._last_hash
                full_record["record_hash"] = rec_hash
                hmac_key = get_audit_hmac_key()
                if hmac_key:
                    full_record["record_hmac"] = compute_record_hmac(rec_hash, hmac_key)

                if cls._log_file and not cls._explicitly_cleared and not cls._persist_record(full_record):
                    return cls._build_unpersisted_record(
                        ts,
                        clean_component,
                        clean_op,
                        clean_target,
                        requested_capability,
                        norm_decision,
                        clean_reason,
                        clean_effects,
                        norm_result,
                        clean_meta,
                    )

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
            cls._known_disk_state = append_record_atomic(cls._log_dir, cls._log_file, record, fsync_fn=os.fsync)
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
    def _verify_disk_chain(cls, target: str, segs: List[str], active_has_data: bool, full_verify: bool) -> Dict[str, Any]:
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
            return {"is_valid": False, "error": msg, "failed_sequence": failed_seq}

        hmac_key = get_audit_hmac_key()
        return {
            "is_valid": True,
            "records_verified": next_seq,
            "segments_verified": len(segs) + (1 if active_has_data else 0),
            "head_hash": head_hash,
            "verification_mode": "full_record_chain" if full_verify else "sealed_digest_cache",
            "bounded_cost": False,
            "archived_bytes_scanned": archived_bytes,
            "external_trust_anchor": "hmac_sha256_verified" if hmac_key else "absent_hash_chain_only",
        }

    @classmethod
    def _verify_memory_journal(cls) -> Dict[str, Any]:
        records = [dict(r) for r in cls._journal]
        expected_prev = "0" * 64
        hmac_key = get_audit_hmac_key()
        for idx, rec in enumerate(records):
            if rec.get("sequence") != idx:
                return {
                    "is_valid": False,
                    "error": f"Sequence discontinuity at index {idx} (got {rec.get('sequence')})",
                    "failed_sequence": idx,
                }
            if rec.get("prev_hash") != expected_prev:
                return {
                    "is_valid": False,
                    "error": f"Hash chain broken at sequence {idx}: expected prev_hash {expected_prev}, got {rec.get('prev_hash')}",
                    "failed_sequence": idx,
                }
            payload = {k: v for k, v in rec.items() if k not in NON_PAYLOAD_FIELDS}
            if cls._compute_hash(payload, expected_prev) != rec.get("record_hash"):
                return {
                    "is_valid": False,
                    "error": f"Tamper detected at sequence {idx}: payload hash mismatch",
                    "failed_sequence": idx,
                }
            if hmac_key:
                try:
                    verify_record_hmac_if_configured(rec, "<in-memory>", idx, hmac_key=hmac_key)
                except AuditIntegrityError as exc:
                    return {
                        "is_valid": False,
                        "error": str(exc),
                        "failed_sequence": idx,
                    }
            expected_prev = rec.get("record_hash")

        return {
            "is_valid": True,
            "records_verified": len(records),
            "head_hash": expected_prev,
            "external_trust_anchor": "hmac_sha256_verified" if hmac_key else "absent_hash_chain_only",
        }

    @classmethod
    def verify_audit_chain(cls, log_path: Optional[str] = None, full_verify: bool = True) -> Dict[str, Any]:
        """Cryptographically verifies the hash chain of audit records to prove zero tampering."""
        with cls._lock:
            target = log_path or (cls._log_file if not cls._explicitly_cleared else None)
            lock_path = (target + ".lock") if target else ""
            with _ProcessFileLock(lock_path, fail_closed=False):
                try:
                    segs = cls._sealed_segments(target) if target else []
                except AuditIntegrityError as err:
                    return {"is_valid": False, "error": str(err), "failed_sequence": 0}
                active_exists = bool(target and os.path.exists(target))
                active_has_data = bool(active_exists and os.path.getsize(target) > 0)

                if segs or active_has_data:
                    return cls._verify_disk_chain(target, segs, active_has_data, full_verify)

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

                return cls._verify_memory_journal()

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
            components = sorted({r["component"] for r in cls._journal})
            last_h = cls._last_hash

        return {
            "total_mediated_operations": total,
            "allowed_count": allows,
            "allowed_scoped_count": allow_scoped,
            "denied_count": denies,
            "participating_components_count": len(components),
            "participating_components": components,
            "audit_chain_head": last_h,
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
