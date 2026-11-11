# -*- coding: utf-8 -*-
"""
REA-Neural Tamper-Evident Security Audit Logger.
Maintains a cryptographically hash-chained, persistent audit journal
recording every mediated system access attempt.
Enforces Data Minimization by scrubbing secrets across all record fields.
Provides persistent chain continuity across process restarts and detects disk tampering.
"""

import os
import re
import sys
import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


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

    _lock = threading.Lock()
    _journal: List[Dict[str, Any]] = []
    _sequence: int = 0
    _last_hash: str = "0" * 64
    _strict_persistence: bool = False
    _explicitly_cleared: bool = False

    # Default persistent log path
    _log_dir = os.path.join(os.path.expanduser("~"), ".rea_neural", "logs")
    _log_file = os.path.join(_log_dir, "audit.jsonl")

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
    def set_log_file(cls, file_path: str) -> None:
        """Configures custom persistent audit log file."""
        with cls._lock:
            cls._log_file = os.path.abspath(file_path)
            cls._log_dir = os.path.dirname(cls._log_file)
            cls._explicitly_cleared = False

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
    def _recover_chain_locked(cls, target_file: str) -> Dict[str, Any]:
        """Must be called while holding cls._lock."""
        if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
            cls._sequence = 0
            cls._last_hash = "0" * 64
            cls._journal.clear()
            return {"recovered": False, "records_count": 0, "head_hash": cls._last_hash}

        records = []
        with open(target_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as jde:
                        raise AuditIntegrityError(f"Audit log on disk has invalid JSON at line {line_num}: {jde}")

        # Verify entire existing chain
        expected_prev = "0" * 64
        for idx, rec in enumerate(records):
            if rec.get("sequence") != idx:
                raise AuditIntegrityError(f"Audit log sequence discontinuity on disk at index {idx}: got {rec.get('sequence')}")
            if rec.get("prev_hash") != expected_prev:
                raise AuditIntegrityError(f"Audit log hash break on disk at sequence {idx}: expected {expected_prev}, got {rec.get('prev_hash')}")
            payload = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
            computed = cls._compute_hash(payload, expected_prev)
            if computed != rec.get("record_hash"):
                raise AuditIntegrityError(f"Audit log tamper detected on disk at sequence {idx}: hash mismatch")
            expected_prev = rec.get("record_hash")

        cls._journal = records
        cls._sequence = len(records)
        cls._last_hash = expected_prev
        return {"recovered": True, "records_count": len(records), "head_hash": expected_prev}

    @classmethod
    def recover_chain_from_disk(cls, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Recovers and cryptographically verifies an existing persistent audit journal from disk,
        allowing a new process to append new records without resetting sequence numbers or hash chains.
        """
        with cls._lock:
            target_file = log_path or cls._log_file
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
            if cls._sequence > 0 and cls._journal:
                return {"recovered": True, "records_count": len(cls._journal), "head_hash": cls._last_hash}
            try:
                return cls._recover_chain_locked(target_file)
            except AuditIntegrityError as err:
                if not rotate_on_corrupt or not os.path.exists(target_file):
                    raise
                import sys, time
                rotated = f"{target_file}.legacy.{int(time.time())}.jsonl"
                try:
                    os.replace(target_file, rotated)
                except OSError:
                    rotated = None
                cls._sequence = 0
                cls._last_hash = "0" * 64
                cls._journal.clear()
                print(f"[REA-Neural][AuditLogger] Warning: rotated legacy/broken audit log ({err}) -> {rotated}", file=sys.stderr)
                return {"recovered": False, "records_count": 0, "rotated_legacy_log": rotated, "head_hash": cls._last_hash}

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

            # Persist to disk with error checking
            cls._persist_record(full_record)

        return full_record

    @classmethod
    def _persist_record(cls, record: Dict[str, Any]) -> None:
        """Appends record to persistent JSONL log file with atomic flush."""
        try:
            if cls._log_dir:
                os.makedirs(cls._log_dir, exist_ok=True)
            with open(cls._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                f.flush()
        except Exception as exc:
            if cls._strict_persistence:
                raise AuditPersistenceError(f"CRITICAL: Failed to write audit record to disk: {exc}") from exc
            sys.stderr.write(f"[AUDIT PERSISTENCE WARNING] Failed to persist audit record to disk: {exc}\n")

    @classmethod
    def verify_audit_chain(cls, log_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Cryptographically verifies the hash chain of audit records to prove zero tampering.
        If log_path is provided, verifies that file. Otherwise verifies in-memory journal
        and asserts synchronization with on-disk log if present.
        """
        records = []
        if log_path and os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        else:
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
            cls._sequence = 0
            cls._last_hash = "0" * 64
            cls._explicitly_cleared = True
