# -*- coding: utf-8 -*-
"""
REA-Neural Tamper-Evident Security Audit Logger.
Maintains a structured, chronological record of every mediated system access attempt.
Enforces Data Minimization by redacting tokens, credentials, and sensitive metadata.
"""

import re
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class AuditLogger:
    """
    Thread-safe audit journal recording all access authorizations,
    boundary checks, and security rejections.
    """

    _lock = threading.Lock()
    _journal: List[Dict[str, Any]] = []

    # Patterns for sensitive credentials to scrub
    _SENSITIVE_PATTERNS = [
        re.compile(r"(password|passwd|pwd|secret|token|bearer|key)=([^&\s]+)", re.IGNORECASE),
        re.compile(r"(--password|--token|--key)\s+([^\s]+)", re.IGNORECASE),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Scrubs sensitive tokens, passwords, and secrets from logged strings."""
        if not text or not isinstance(text, str):
            return ""
        clean = text
        for pat in cls._SENSITIVE_PATTERNS:
            clean = pat.sub(r"\1=***REDACTED***", clean)
        return clean

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
        Records an authoritative security decision into the audit journal.
        """
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": cls.sanitize(component),
            "operation": cls.sanitize(operation),
            "target": cls.sanitize(target),
            "requested_capability": requested_capability,
            "decision": decision.upper(),
            "reason": reason,
            "side_effects": side_effects or [],
            "result": result.upper(),
            "metadata": metadata or {}
        }

        with cls._lock:
            cls._journal.append(record)

        return record

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

        return {
            "total_mediated_operations": total,
            "allowed_count": allows,
            "allowed_scoped_count": allow_scoped,
            "denied_count": denies,
            "participating_components_count": len(components),
            "participating_components": sorted(components)
        }

    @classmethod
    def clear(cls) -> None:
        """Clears the audit journal (used for clean test fixture isolation)."""
        with cls._lock:
            cls._journal.clear()
