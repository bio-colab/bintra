# -*- coding: utf-8 -*-
"""
Helper utility for locating the legacy benchmark target executable.
Reads target path from environment variable BINTRA_TARGET_PE or .env file.
Enforces strict sanitization to guarantee host environment privacy.
"""

import os
from typing import Optional, Any

_CACHED_TARGET: Optional[str] = None


def get_target_binary_path() -> Optional[str]:
    """Resolves target binary path safely without hardcoding private directories in source."""
    global _CACHED_TARGET
    if _CACHED_TARGET and os.path.isfile(_CACHED_TARGET):
        return _CACHED_TARGET

    # 1. Environment variable
    env_path = os.environ.get("BINTRA_TARGET_PE")
    if env_path and os.path.isfile(env_path):
        _CACHED_TARGET = os.path.abspath(env_path)
        return _CACHED_TARGET

    # 2. Local git-ignored .env file
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env_file = os.path.join(repo_root, ".env")
    if os.path.isfile(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("BINTRA_TARGET_PE="):
                    cand = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if os.path.isfile(cand):
                        _CACHED_TARGET = os.path.abspath(cand)
                        return _CACHED_TARGET

    return None


def sanitize_all(obj: Any) -> Any:
    """Recursively replaces any occurrence of the target's host directory with <target_dir>."""
    target_path = get_target_binary_path()
    raw_path = os.path.abspath(target_path) if target_path else ""
    raw_dir = os.path.dirname(raw_path) if raw_path else ""

    if isinstance(obj, str):
        res = obj
        if raw_path:
            res = res.replace(raw_path, "<target_dir>/generals.exe")
            res = res.replace(raw_path.replace("\\", "/"), "<target_dir>/generals.exe")
        if raw_dir:
            res = res.replace(raw_dir, "<target_dir>")
            res = res.replace(raw_dir.replace("\\", "/"), "<target_dir>")
        return res
    elif isinstance(obj, dict):
        return {k: sanitize_all(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_all(v) for v in obj]
    return obj
