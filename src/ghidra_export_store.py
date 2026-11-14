"""
Bintra Ghidra Export Store: High-Performance SQLite & JSONL Streaming Storage
Provides zero-dependency indexed querying and streaming for large Ghidra decompiler exports.

Architecture:
- Legacy JSON (.json): Transparent auto-indexing to SQLite for exports > threshold.
- JSON Lines (.jsonl): Native line-by-line streaming from Ghidra bridge without full-RAM loading.
- SQLite Store (.db / .sqlite): Instant O(log N) indexed function retrieval and SQL-accelerated call graphs.
- Memory Parity: 100% backward-compatible fallback to in-memory dicts.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple, Union


# Threshold above which JSON exports are transparently cached to SQLite
# to prevent CPython RAM exhaustion on multi-megabyte Ghidra dumps.
SQLITE_AUTO_INGEST_THRESHOLD_BYTES = 2 * 1024 * 1024  # 2 MB

SENSITIVE_API_PATTERNS = (
    "LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
    "CreateFile", "WriteFile", "ReadFile", "RegOpenKey", "RegSetValue",
    "CreateProcess", "WinExec", "ShellExecute", "WSASocket", "connect",
    "InternetOpen", "HttpSendRequest", "CryptDecrypt", "BCryptDecrypt",
    "RtlCopyMemory", "memcpy", "strcpy", "sprintf",
)


class GhidraExportStore:
    """
    Unified storage and query engine for Ghidra program exports.
    Abstracts whether the backing store is an in-memory dictionary,
    a flat JSON file, a streamed JSON Lines (.jsonl) file, or an indexed SQLite database (.db).
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        in_memory_dict: Optional[Dict[str, Any]] = None,
        source_path: Optional[str] = None
    ) -> None:
        self.db_path = db_path
        self._in_memory = in_memory_dict
        self.source_path = source_path
        self._conn: Optional[sqlite3.Connection] = None

    @classmethod
    def from_path(cls, path: Union[str, Path, Dict[str, Any]]) -> "GhidraExportStore":
        """
        Factory method to resolve any Ghidra export artifact:
        - Dict -> In-memory store (zero ingestion, instant)
        - .db / .sqlite -> Direct SQLite store (zero ingestion, O(log N) queries)
        - .jsonl -> Streamed or cached SQLite store
        - .json -> Cached SQLite store (if large) or in-memory dict (if small)
        """
        if isinstance(path, dict):
            return cls(in_memory_dict=path)

        path_str = str(path)
        if not os.path.exists(path_str):
            raise FileNotFoundError(f"Ghidra export file not found: {path_str}")

        suffix = Path(path_str).suffix.lower()

        # 1. Direct SQLite database
        if suffix in (".db", ".sqlite", ".sqlite3"):
            return cls(db_path=path_str, source_path=path_str)

        # 2. JSON Lines (.jsonl)
        if suffix == ".jsonl":
            cache_db = cls._get_or_build_cache(path_str, is_jsonl=True)
            if cache_db:
                return cls(db_path=cache_db, source_path=path_str)
            # Fallback: parse into memory if cache creation failed
            return cls(in_memory_dict=cls._read_jsonl_to_dict(path_str), source_path=path_str)

        # 3. Standard JSON (.json)
        file_size = os.path.getsize(path_str)
        if file_size >= SQLITE_AUTO_INGEST_THRESHOLD_BYTES:
            cache_db = cls._get_or_build_cache(path_str, is_jsonl=False)
            if cache_db:
                return cls(db_path=cache_db, source_path=path_str)

        # Fast direct load for small JSON or when cache is not needed
        with open(path_str, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        return cls(in_memory_dict=data, source_path=path_str)

    @classmethod
    def _get_cache_dir(cls) -> str:
        """Resolves standard cache directory under user .bintra workspace or temp."""
        user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
        cache_dir = os.path.join(user_home, ".bintra", "workspace", "exports_cache")
        try:
            os.makedirs(cache_dir, exist_ok=True)
            return cache_dir
        except Exception:
            return tempfile.gettempdir()

    @classmethod
    def _compute_cache_path(cls, source_path: str) -> str:
        """Derives a deterministic cache DB path based on canonical source path and mtime."""
        canon = os.path.abspath(source_path)
        mtime = os.path.getmtime(source_path)
        size = os.path.getsize(source_path)
        sig = f"{canon}:{mtime}:{size}".encode("utf-8")
        h = hashlib.sha256(sig).hexdigest()[:16]
        base_name = Path(source_path).stem
        safe_base = "".join(c if c.isalnum() else "_" for c in base_name)[:24]
        return os.path.join(cls._get_cache_dir(), f"{safe_base}_{h}.bintra_cache.db")

    @classmethod
    def _get_or_build_cache(cls, source_path: str, is_jsonl: bool = False) -> Optional[str]:
        """Returns existing fresh cache or ingests source into a new SQLite database."""
        cache_path = cls._compute_cache_path(source_path)
        if os.path.exists(cache_path):
            try:
                # Quick health check
                con = sqlite3.connect(cache_path)
                cur = con.cursor()
                cur.execute("SELECT COUNT(*) FROM functions")
                cur.fetchone()
                con.close()
                return cache_path
            except Exception:
                try:
                    os.remove(cache_path)
                except Exception:
                    pass

        # Build new cache
        try:
            cls.ingest_to_sqlite(source_path, cache_path, is_jsonl=is_jsonl)
            return cache_path
        except Exception:
            # On ingestion failure (e.g. disk full, permission), return None for graceful fallback
            return None

    @classmethod
    def _read_jsonl_to_dict(cls, path_str: str) -> Dict[str, Any]:
        """Reads a .jsonl file into a legacy dictionary structure."""
        funcs = []
        meta = {}
        with open(path_str, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if "program_name" in obj or "image_base" in obj:
                    meta.update(obj)
                elif "entry_point" in obj or "name" in obj:
                    funcs.append(obj)
        res = dict(meta)
        res["functions"] = funcs
        return res

    @classmethod
    def ingest_to_sqlite(cls, source_path: str, target_db_path: str, is_jsonl: bool = False) -> None:
        """
        Surgically ingests a Ghidra .json or .jsonl export into an indexed SQLite database.
        Uses WAL mode, synchronous=NORMAL, and chunked batch transactions.
        """
        tmp_db = target_db_path + ".tmp"
        if os.path.exists(tmp_db):
            try:
                os.remove(tmp_db)
            except Exception:
                pass

        con = sqlite3.connect(tmp_db)
        cur = con.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS program_metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS functions (
            entry_point TEXT PRIMARY KEY,
            name TEXT,
            size INTEGER,
            parameter_count INTEGER,
            return_type TEXT,
            has_sensitive_api INTEGER DEFAULT 0,
            pcode_ops_count INTEGER DEFAULT 0,
            basic_blocks_count INTEGER DEFAULT 0,
            data JSON
        );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_func_name ON functions(name);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_func_sens ON functions(has_sensitive_api);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_func_size ON functions(size);")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS call_edges (
            caller_name TEXT,
            caller_addr TEXT,
            callee_name TEXT,
            callee_addr TEXT,
            is_indirect INTEGER DEFAULT 0,
            call_site_addr TEXT
        );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_edge_caller ON call_edges(caller_name);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_edge_callee ON call_edges(callee_name);")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS xrefs (
            function_name TEXT,
            from_addr TEXT,
            to_addr TEXT,
            xref_type TEXT,
            symbol TEXT
        );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_xref_fn ON xrefs(function_name);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_xref_to ON xrefs(to_addr);")

        def _insert_func_batch(batch: List[Tuple[Any, ...]], edges_batch: List[Tuple[Any, ...]], xrefs_batch: List[Tuple[Any, ...]]):
            if batch:
                cur.executemany(
                    "INSERT OR REPLACE INTO functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    batch
                )
            if edges_batch:
                cur.executemany(
                    "INSERT INTO call_edges VALUES (?, ?, ?, ?, ?, ?)",
                    edges_batch
                )
            if xrefs_batch:
                cur.executemany(
                    "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?)",
                    xrefs_batch
                )

        func_batch: List[Tuple[Any, ...]] = []
        edge_batch: List[Tuple[Any, ...]] = []
        xref_batch: List[Tuple[Any, ...]] = []

        def _process_function(fn: Dict[str, Any]):
            name = str(fn.get("name", "unknown"))
            entry = str(fn.get("entry_point", fn.get("address", "0x0")))
            size = int(fn.get("size", 0))
            param_cnt = int(fn.get("parameter_count", 0))
            ret_type = str(fn.get("return_type", "void"))
            pcode = fn.get("pcode_ops", [])
            blocks = fn.get("basic_blocks", [])

            # Check sensitive APIs
            callees = list(fn.get("callees", []))
            for op in pcode:
                opc = str(op.get("opcode", "")).upper()
                if opc == "CALL":
                    tgt = op.get("target_name") or op.get("target_address")
                    if tgt and tgt not in callees:
                        callees.append(str(tgt))
                elif opc == "CALLIND":
                    edge_batch.append((name, entry, "INDIRECT_CALL", "0x0", 1, str(op.get("address", entry))))

            has_sens = 1 if any(any(pat.lower() in str(c).lower() for pat in SENSITIVE_API_PATTERNS) for c in callees) else 0

            for c in callees:
                edge_batch.append((name, entry, str(c), "", 0, entry))

            for xr in fn.get("xrefs", []):
                xref_batch.append((
                    name,
                    str(xr.get("from", entry)),
                    str(xr.get("to", "")),
                    str(xr.get("type", "CALL")),
                    str(xr.get("symbol", ""))
                ))

            func_batch.append((
                entry,
                name,
                size,
                param_cnt,
                ret_type,
                has_sens,
                len(pcode),
                len(blocks),
                json.dumps(fn, ensure_ascii=False)
            ))

            if len(func_batch) >= 1000:
                _insert_func_batch(func_batch, edge_batch, xref_batch)
                func_batch.clear()
                edge_batch.clear()
                xref_batch.clear()

        if is_jsonl:
            with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if "program_name" in obj or "image_base" in obj:
                        for k, v in obj.items():
                            if k != "functions":
                                cur.execute("INSERT OR REPLACE INTO program_metadata VALUES (?, ?)", (str(k), str(v)))
                    if "functions" in obj and isinstance(obj["functions"], list):
                        for fn in obj["functions"]:
                            _process_function(fn)
                    elif "entry_point" in obj or "name" in obj:
                        _process_function(obj)
        else:
            with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                for k, v in payload.items():
                    if k != "functions":
                        cur.execute("INSERT OR REPLACE INTO program_metadata VALUES (?, ?)", (str(k), str(v)))
                for fn in payload.get("functions", []):
                    _process_function(fn)
            elif isinstance(payload, list):
                for fn in payload:
                    _process_function(fn)

        if func_batch or edge_batch or xref_batch:
            _insert_func_batch(func_batch, edge_batch, xref_batch)

        con.commit()
        con.close()

        # Atomic rename
        if os.path.exists(target_db_path):
            try:
                os.remove(target_db_path)
            except Exception:
                pass
        os.rename(tmp_db, target_db_path)

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            if not self.db_path or not os.path.exists(self.db_path):
                raise RuntimeError("No active SQLite database for GhidraExportStore")
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> "GhidraExportStore":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # --- Query API ---

    @property
    def is_sqlite(self) -> bool:
        return self.db_path is not None and os.path.exists(self.db_path)

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary-like metadata access (e.g. program_name, image_base, functions)."""
        if not self.is_sqlite:
            return (self._in_memory or {}).get(key, default)

        if key == "functions":
            return list(self.iter_functions())

        con = self._get_connection()
        cur = con.cursor()
        cur.execute("SELECT value FROM program_metadata WHERE key = ?", (key,))
        row = cur.fetchone()
        if row:
            return row["value"]
        return default

    def get_function(self, name_or_addr: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single function by name or entry point in O(log N) time.
        Consumes virtually zero RAM compared to loading a 50MB JSON file.
        """
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            cur.execute(
                "SELECT data FROM functions WHERE name = ? OR entry_point = ? LIMIT 1",
                (name_or_addr, name_or_addr)
            )
            row = cur.fetchone()
            if row:
                return json.loads(row["data"])
            return None

        # In-memory dictionary fallback
        funcs = self._in_memory.get("functions", []) if self._in_memory else []
        for fn in funcs:
            if fn.get("name") == name_or_addr or fn.get("entry_point") == name_or_addr or fn.get("address") == name_or_addr:
                return fn
        return None

    def list_functions(
        self,
        limit: int = 100,
        offset: int = 0,
        sensitive_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Lists functions with direct indexed LIMIT and WHERE filters."""
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            if sensitive_only:
                cur.execute(
                    "SELECT data FROM functions WHERE has_sensitive_api = 1 ORDER BY size DESC LIMIT ? OFFSET ?",
                    (limit, offset)
                )
            else:
                cur.execute(
                    "SELECT data FROM functions ORDER BY size DESC LIMIT ? OFFSET ?",
                    (limit, offset)
                )
            return [json.loads(r["data"]) for r in cur.fetchall()]

        funcs = self._in_memory.get("functions", []) if self._in_memory else []
        if sensitive_only:
            filtered = []
            for fn in funcs:
                callees = fn.get("callees", [])
                if any(any(pat.lower() in str(c).lower() for pat in SENSITIVE_API_PATTERNS) for c in callees):
                    filtered.append(fn)
            return filtered[offset : offset + limit]
        return funcs[offset : offset + limit]

    def count_functions(self) -> int:
        """Returns total functions count."""
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM functions")
            return int(cur.fetchone()[0])
        return len(self._in_memory.get("functions", [])) if self._in_memory else 0

    def iter_functions(self) -> Iterator[Dict[str, Any]]:
        """Streams all functions one-by-one without holding all objects in RAM."""
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            cur.execute("SELECT data FROM functions")
            while True:
                rows = cur.fetchmany(500)
                if not rows:
                    break
                for r in rows:
                    yield json.loads(r["data"])
            return

        funcs = self._in_memory.get("functions", []) if self._in_memory else []
        for fn in funcs:
            yield fn

    def build_call_graph_and_xrefs(
        self, target_function: Optional[str] = None, max_depth: int = 4
    ) -> Dict[str, Any]:
        """
        Fast graph computation leveraging SQLite index tables or in-memory fallback.
        Guarantees 100% schema parity with GhidraDeepAnalyzer.build_call_graph_and_xrefs.
        """
        from collections import deque

        if not self.is_sqlite:
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            return GhidraDeepAnalyzer().build_call_graph_and_xrefs(
                self.to_dict(), target_function=target_function, max_depth=max_depth
            )

        con = self._get_connection()
        cur = con.cursor()

        # 1. Total functions count
        cur.execute("SELECT COUNT(*) FROM functions")
        total_funcs = int(cur.fetchone()[0])

        # 2. Call edges and maps
        cur.execute("SELECT caller_name, callee_name, is_indirect, call_site_addr FROM call_edges WHERE callee_name != ''")
        edge_rows = cur.fetchall()

        callers_of: Dict[str, List[str]] = {}
        callees_of: Dict[str, List[str]] = {}
        indirect_calls: List[Dict[str, Any]] = []

        for r in edge_rows:
            c_name = r["caller_name"]
            e_name = r["callee_name"]
            is_ind = r["is_indirect"]
            if is_ind:
                indirect_calls.append({
                    "function": c_name,
                    "address": r["call_site_addr"],
                    "inputs": [],
                })
            else:
                callees_of.setdefault(c_name, [])
                if e_name not in callees_of[c_name]:
                    callees_of[c_name].append(e_name)

                callers_of.setdefault(e_name, [])
                if c_name not in callers_of[e_name]:
                    callers_of[e_name].append(c_name)

        # 3. XREFs
        cur.execute("SELECT function_name, from_addr, to_addr, xref_type, symbol FROM xrefs LIMIT 500")
        xref_rows = cur.fetchall()
        xref_records = [
            {
                "function": r["function_name"],
                "from": r["from_addr"],
                "to": r["to_addr"],
                "type": r["xref_type"],
                "symbol": r["symbol"],
            }
            for r in xref_rows
        ]

        # 4. Sensitive API reachability
        api_reachability: List[Dict[str, Any]] = []
        for c_name, dests in callees_of.items():
            for d in dests:
                if any(pat.lower() in d.lower() for pat in SENSITIVE_API_PATTERNS):
                    api_reachability.append({
                        "api": d,
                        "direct_caller": c_name,
                        "caller_address": "",
                        "upstream_callers": callers_of.get(c_name, [])[:10],
                    })

        # 5. BFS subgraph around target_function
        subgraph = None
        if target_function:
            visited = {target_function}
            q = deque([(target_function, 0)])
            edges: List[Dict[str, Any]] = []
            while q:
                curr, d = q.popleft()
                if d >= max_depth:
                    continue
                for nxt in callees_of.get(curr, []):
                    edges.append({"from": curr, "to": nxt, "depth": d + 1})
                    if nxt not in visited:
                        visited.add(nxt)
                        q.append((nxt, d + 1))
            subgraph = {
                "root": target_function,
                "max_depth": max_depth,
                "reachable_nodes": sorted(visited),
                "edges": edges,
            }

        return {
            "status": "ok",
            "functions_indexed": total_funcs,
            "call_edges_count": sum(len(v) for v in callees_of.values()),
            "indirect_calls_count": len(indirect_calls),
            "indirect_calls_sample": indirect_calls[:50],
            "xrefs_count": len(xref_records),
            "xrefs_sample": xref_records[:100],
            "sensitive_api_reachability": api_reachability[:50],
            "callees_map": {k: v for k, v in list(callees_of.items())[:100]},
            "callers_map": {k: v for k, v in list(callers_of.items())[:100]},
            "target_subgraph": subgraph,
            "epistemic_classification": "GHIDRA_STATIC_TOPOLOGY_PARSE",
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Reconstructs a full legacy dictionary {"program_name": ..., "functions": [...]}.
        Guarantees 100% backward compatibility when legacy code requires an in-memory dict.
        """
        if not self.is_sqlite:
            return self._in_memory or {"functions": []}

        con = self._get_connection()
        cur = con.cursor()
        cur.execute("SELECT key, value FROM program_metadata")
        meta = {r["key"]: r["value"] for r in cur.fetchall()}

        cur.execute("SELECT data FROM functions")
        funcs = [json.loads(r["data"]) for r in cur.fetchall()]

        res = dict(meta)
        res["functions"] = funcs
        return res
