# -*- coding: utf-8 -*-
"""Shared helper utilities for OBS Studio benchmark PoC scripts."""

import json
from pathlib import Path
from typing import Any, Dict, List


def resolve_obs_binary(obs_dir: Path, rel_candidates: List[str]) -> Path:
    for rel in rel_candidates:
        candidate = obs_dir / rel
        if candidate.exists():
            return candidate
    return obs_dir / rel_candidates[0]


def sanitize_text(text: str, obs_root: Path, repo_root: Path) -> str:
    if not isinstance(text, str):
        return text
    out = text
    for src, dst in [
        (str(obs_root), "<OBS_ROOT>"),
        (str(repo_root), "<BINTRA_ROOT>"),
    ]:
        out = out.replace(src, dst).replace(src.replace("\\", "/"), dst)
    return out


def sanitize_obj(obj: Any, obs_root: Path, repo_root: Path) -> Any:
    if isinstance(obj, str):
        return sanitize_text(obj, obs_root, repo_root)
    if isinstance(obj, list):
        return [sanitize_obj(x, obs_root, repo_root) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize_obj(v, obs_root, repo_root) for k, v in obj.items()}
    return obj


def write_evidence(evidence_dir: Path, filename: str, payload: Dict[str, Any], obs_root: Path, repo_root: Path) -> Path:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / filename
    clean = sanitize_obj(payload, obs_root, repo_root)
    out_path.write_text(json.dumps(clean, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path
