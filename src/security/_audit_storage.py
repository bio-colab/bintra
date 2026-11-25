# -*- coding: utf-8 -*-
"""
Persistent storage, segment rotation, digest caching, and cryptographic
verification primitives for the Bintra Audit Logger.
"""

import glob
import hashlib
import json
import os
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from ._audit_lock import AuditIntegrityError
from ._win32 import streaming_file_sha256


def compute_record_hash(record_payload: Dict[str, Any], prev_hash: str) -> str:
    """Computes deterministic SHA-256 hash chaining over record payload and previous hash."""
    canonical_str = json.dumps(record_payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical_str).encode("utf-8")).hexdigest()


def parse_sealed_filename_bounds(path: str) -> Optional[Tuple[int, int]]:
    """Extracts `(first_seq, last_seq)` from a sealed segment filename, if well-formed."""
    try:
        base = os.path.basename(path)
        if ".legacy." in base:
            return None
        bounds_str = base.rsplit(".sealed.", 1)[1].rsplit(".jsonl", 1)[0]
        first_s, last_s = bounds_str.split("-", 1)
        first_seq = int(first_s)
        last_seq = int(last_s)
        if first_seq < 0 or last_seq < first_seq:
            return None
        return first_seq, last_seq
    except (IndexError, ValueError):
        return None


def scan_sealed_segments(target_file: str) -> Tuple[List[str], List[str]]:
    """
    Scans for sealed archive segments of `target_file`.
    Returns `(sorted_valid_segments, malformed_non_legacy_segments)`.
    """
    candidates = glob.glob(glob.escape(target_file) + ".sealed.*.jsonl")
    valid: List[Tuple[int, str]] = []
    malformed: List[str] = []
    for path in candidates:
        if ".legacy." in os.path.basename(path):
            continue
        bounds = parse_sealed_filename_bounds(path)
        if bounds is None:
            malformed.append(path)
        else:
            valid.append((bounds[0], path))
    valid.sort(key=lambda item: item[0])
    return [path for _, path in valid], sorted(malformed)


def sealed_cache_path(target_file: str) -> str:
    return f"{target_file}.sealedcache.json"


def load_sealed_cache(target_file: str) -> Dict[str, Any]:
    try:
        with open(sealed_cache_path(target_file), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def store_sealed_cache(target_file: str, cache: Dict[str, Any]) -> None:
    cache_dest = sealed_cache_path(target_file)
    cache_dir = os.path.dirname(cache_dest) or "."
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cache_dir,
            prefix=os.path.basename(cache_dest) + ".",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp_path = fh.name
            json.dump(cache, fh, ensure_ascii=False)
        os.replace(tmp_path, cache_dest)
    except OSError:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def cache_entry_commitment(
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


def verify_segment_file(
    file_path: str,
    start_seq: int,
    start_prev: str,
    collect: Optional[List[Dict[str, Any]]] = None,
    hash_fn: Callable[[Dict[str, Any], str], str] = compute_record_hash,
) -> Tuple[int, str, Optional[Dict[str, Any]]]:
    """
    Streams and cryptographically verifies every JSONL record in `file_path`
    starting at `start_seq` and `start_prev`.
    Returns `(next_seq, head_hash, last_record)`.
    """
    expected_seq = start_seq
    expected_prev = start_prev
    last_rec: Optional[Dict[str, Any]] = None
    with open(file_path, "r", encoding="utf-8") as fh:
        for line_num, raw_line in enumerate(fh, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as jde:
                raise AuditIntegrityError(
                    f"Audit log '{file_path}' has invalid JSON at line {line_num}: {jde}"
                ) from jde
            if not isinstance(rec, dict):
                raise AuditIntegrityError(
                    f"Audit log '{file_path}' line {line_num} is not a JSON object"
                )
            if rec.get("sequence") != expected_seq:
                raise AuditIntegrityError(
                    f"Audit log sequence discontinuity on disk in '{file_path}' at index {expected_seq}: got {rec.get('sequence')}"
                )
            if rec.get("prev_hash") != expected_prev:
                raise AuditIntegrityError(
                    f"Audit log hash break on disk in '{file_path}' at sequence {expected_seq}: expected {expected_prev}, got {rec.get('prev_hash')}"
                )
            payload = {k: v for k, v in rec.items() if k not in ("prev_hash", "record_hash")}
            if hash_fn(payload, expected_prev) != rec.get("record_hash"):
                raise AuditIntegrityError(
                    f"Audit log tamper detected on disk in '{file_path}' at sequence {expected_seq}: hash mismatch"
                )
            expected_prev = rec.get("record_hash")
            expected_seq += 1
            last_rec = rec
            if collect is not None:
                collect.append(rec)
    return expected_seq, expected_prev, last_rec


def read_disk_tail(
    target_file: str,
    hash_fn: Callable[[Dict[str, Any], str], str] = compute_record_hash,
) -> Optional[Dict[str, Any]]:
    """Reads and hash-verifies the last JSONL record from the persistent log file on disk."""
    if not target_file or not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
        return None
    with open(target_file, "rb") as fh:
        size = os.path.getsize(target_file)
        buf_size = 8192
        while True:
            read_len = min(size, buf_size)
            offset = size - read_len
            fh.seek(offset)
            chunk = fh.read(read_len)
            lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
            if not lines:
                if offset == 0:
                    return None
                buf_size *= 2
                continue
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
    if hash_fn(payload, str(rec["prev_hash"])) != rec.get("record_hash"):
        raise AuditIntegrityError(f"Audit log tail tamper detected in '{target_file}': hash mismatch.")
    return rec


def append_record_atomic(
    log_dir: Optional[str],
    log_file: str,
    record: Dict[str, Any],
    fsync_fn: Callable[[int], None] = os.fsync,
) -> Optional[Tuple[str, int, int]]:
    """
    Appends `record` atomically to `log_file` with flush + fsync and rolls back
    partial writes via truncation if an I/O failure occurs.
    Returns updated disk-state fingerprint `(log_file, st_size, st_mtime_ns)` or `None`.
    """
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    encoded = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    with open(log_file, "a+b") as fh:
        pre_size = fh.seek(0, os.SEEK_END)
        try:
            fh.write(encoded)
            fh.flush()
            if hasattr(fh, "fileno"):
                try:
                    fd = fh.fileno()
                except (OSError, ValueError):
                    fd = None
                if isinstance(fd, int):
                    fsync_fn(fd)
        except Exception:
            try:
                fh.truncate(pre_size)
                fh.flush()
            except OSError:
                pass
            raise
    try:
        st = os.stat(log_file)
        return (log_file, st.st_size, st.st_mtime_ns)
    except OSError:
        return None


def file_sha256(path: str) -> str:
    """Computes streaming SHA-256 hex digest using 1 MiB read chunks."""
    return streaming_file_sha256(path, chunk_size=1 << 20)
