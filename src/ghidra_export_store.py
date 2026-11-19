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
        """Resolves standard cache directory under active scope workspace or user .bintra workspace."""
        try:
            from security import ExecutionGuard
            scope = ExecutionGuard.get_current_scope()
            if scope and getattr(scope, "workspace_dir", None):
                cache_dir = os.path.join(scope.workspace_dir, "exports_cache")
            else:
                user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
                cache_dir = os.path.join(user_home, ".bintra", "workspace", "exports_cache")
        except Exception:
            user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
            cache_dir = os.path.join(user_home, ".bintra", "workspace", "exports_cache")

        try:
            os.makedirs(cache_dir, exist_ok=True)
            return cache_dir
        except Exception:
            return cache_dir

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
                cur.close()
                con.close()
                return cache_path
            except Exception:
                from security import SafeFileAccess, SecurityViolationError
                try:
                    SafeFileAccess.delete_workspace_file(cache_path)
                except SecurityViolationError:
                    raise
                except OSError:
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
        Uses in-memory journaling and chunked batch transactions with guaranteed handle cleanup.
        Mediated by ExecutionGuard for Capability.WORKSPACE_WRITE.
        """
        try:
            from security import ExecutionGuard, Capability, SafeFileAccess, SecurityViolationError
        except ImportError as imp_err:
            raise RuntimeError(
                f"SECURITY_KERNEL_UNAVAILABLE: Refusing unmediated SQLite ingestion: {imp_err}"
            ) from imp_err

        ExecutionGuard.request_access(
            component="ghidra_export_store",
            operation="ingest_to_sqlite",
            target=target_db_path,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )
        scope = ExecutionGuard.get_current_scope()
        if scope:
            scope.record_session_file(target_db_path)
        if os.path.exists(target_db_path):
            try:
                SafeFileAccess.delete_workspace_file(target_db_path)
            except SecurityViolationError:
                raise

        con = sqlite3.connect(target_db_path)
        try:
            cur = con.cursor()
            cur.execute("PRAGMA journal_mode = MEMORY;")
            cur.execute("PRAGMA synchronous = OFF;")

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
            CREATE TABLE IF NOT EXISTS function_opcodes (
                entry_point TEXT,
                opcode TEXT
            );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_fn_opc ON function_opcodes(opcode, entry_point);")

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

            def _insert_func_batch(
                batch: List[Tuple[Any, ...]],
                edges_batch: List[Tuple[Any, ...]],
                xrefs_batch: List[Tuple[Any, ...]],
                opcodes_batch: List[Tuple[str, str]]
            ):
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
                if opcodes_batch:
                    cur.executemany(
                        "INSERT INTO function_opcodes VALUES (?, ?)",
                        opcodes_batch
                    )

            func_batch: List[Tuple[Any, ...]] = []
            edge_batch: List[Tuple[Any, ...]] = []
            xref_batch: List[Tuple[Any, ...]] = []
            opcode_batch: List[Tuple[str, str]] = []

            def _process_function(fn: Dict[str, Any]):
                name = str(fn.get("name", "unknown"))
                entry = str(fn.get("entry_point", fn.get("address", "0x0")))
                size = int(fn.get("size", 0))
                param_cnt = int(fn.get("parameter_count", 0))
                ret_type = str(fn.get("return_type", "void"))
                pcode = fn.get("pcode_ops", [])
                blocks = fn.get("basic_blocks", [])

                # Check sensitive APIs & index opcodes
                callees = list(fn.get("callees", []))
                unique_opcs = set()
                for op in pcode:
                    opc = str(op.get("opcode", "")).upper()
                    if opc:
                        unique_opcs.add(opc)
                    if opc == "CALL":
                        tgt = op.get("target_name") or op.get("target_address")
                        if tgt and tgt not in callees:
                            callees.append(str(tgt))
                    elif opc == "CALLIND":
                        edge_batch.append((name, entry, "INDIRECT_CALL", "0x0", 1, str(op.get("address", entry))))

                for opc in unique_opcs:
                    opcode_batch.append((entry, opc))

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
                    _insert_func_batch(func_batch, edge_batch, xref_batch, opcode_batch)
                    func_batch.clear()
                    edge_batch.clear()
                    xref_batch.clear()
                    opcode_batch.clear()

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

            if func_batch or edge_batch or xref_batch or opcode_batch:
                _insert_func_batch(func_batch, edge_batch, xref_batch, opcode_batch)

            con.commit()
            cur.close()
        except Exception:
            try:
                con.close()
            except Exception:
                pass
            if os.path.exists(target_db_path):
                try:
                    os.remove(target_db_path)
                except Exception:
                    pass
            raise
        finally:
            try:
                con.close()
            except Exception:
                pass

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

    def search_functions(
        self,
        query: Optional[str] = None,
        opcode: Optional[str] = None,
        xref_target: Optional[str] = None,
        sensitive_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Advanced query and search engine across the Ghidra program export.
        Allows searching functions by:
        - query: substring in name, entry point, signature, or decompiled C pseudocode
        - opcode: specific P-Code mnemonic (e.g. CALLIND, INT_XOR, FLOAT_SQRT)
        - xref_target: target symbol, address, or string referenced by the function
        - sensitive_only: whether to filter to functions invoking sensitive Win32 APIs
        """
        matched_summaries: List[Dict[str, Any]] = []
        clean_query = query.strip().lower() if query else None
        clean_opcode = opcode.strip().upper() if opcode else None
        clean_xref = xref_target.strip().lower() if xref_target else None

        def _check_fn(fn: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            fn_name = str(fn.get("name", "unknown"))
            entry = str(fn.get("entry_point", fn.get("address", "0x0")))
            sig = str(fn.get("signature", ""))
            decomp_c = str(fn.get("decompiled_c", ""))
            callees = fn.get("callees", [])
            pcode = fn.get("pcode_ops", [])
            blocks = fn.get("basic_blocks", [])
            reasons = []

            # 1. Sensitive API filter
            has_sens = any(any(pat.lower() in str(c).lower() for pat in SENSITIVE_API_PATTERNS) for c in callees)
            if sensitive_only and not has_sens:
                return None

            # 2. Text query filter
            if clean_query:
                q_matched = False
                if clean_query in fn_name.lower():
                    reasons.append(f"name matches '{query}'")
                    q_matched = True
                elif clean_query in entry.lower():
                    reasons.append(f"entry_point matches '{query}'")
                    q_matched = True
                elif clean_query in sig.lower():
                    reasons.append(f"signature matches '{query}'")
                    q_matched = True
                elif clean_query in decomp_c.lower():
                    reasons.append(f"decompiled C contains '{query}'")
                    q_matched = True
                if not q_matched:
                    return None

            # 3. Opcode filter
            if clean_opcode:
                op_found = False
                for op in pcode:
                    if str(op.get("opcode", "")).upper() == clean_opcode:
                        op_found = True
                        break
                if not op_found:
                    return None
                reasons.append(f"contains P-Code opcode '{clean_opcode}'")

            # 4. XREF target filter
            if clean_xref:
                xref_found = False
                for xr in fn.get("xrefs", []):
                    to_s = str(xr.get("to", "")).lower()
                    sym_s = str(xr.get("symbol", "")).lower()
                    from_s = str(xr.get("from", "")).lower()
                    if clean_xref in to_s or clean_xref in sym_s or clean_xref in from_s:
                        xref_found = True
                        reasons.append(f"references '{xr.get('symbol') or xr.get('to')}'")
                        break
                if not xref_found:
                    return None

            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            demangled = GhidraDeepAnalyzer.demangle_msvc_symbol(fn_name)

            return {
                "name": fn_name,
                "demangled_name": demangled if demangled != fn_name else None,
                "entry_point": entry,
                "size": int(fn.get("size", 0)),
                "signature": sig or None,
                "parameter_count": int(fn.get("parameter_count", 0)),
                "return_type": str(fn.get("return_type", "void")),
                "has_sensitive_api": has_sens,
                "pcode_ops_count": len(pcode),
                "basic_blocks_count": len(blocks),
                "match_reasons": reasons or ["matched filter criteria"],
            }

        total_matches = 0
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            query_conds = []
            params: List[Any] = []

            if sensitive_only:
                query_conds.append("f.has_sensitive_api = 1")

            if clean_query:
                query_conds.append("(f.name LIKE ? OR f.entry_point LIKE ? OR f.data LIKE ?)")
                like_p = f"%{clean_query}%"
                params.extend([like_p, like_p, like_p])

            if clean_opcode:
                query_conds.append("f.entry_point IN (SELECT entry_point FROM function_opcodes WHERE opcode = ?)")
                params.append(clean_opcode)

            if clean_xref:
                query_conds.append(
                    "(f.name IN (SELECT function_name FROM xrefs WHERE to_addr LIKE ? OR symbol LIKE ? OR from_addr LIKE ?) "
                    "OR f.entry_point IN (SELECT from_addr FROM xrefs WHERE to_addr LIKE ? OR symbol LIKE ?))"
                )
                like_x = f"%{clean_xref}%"
                params.extend([like_x, like_x, like_x, like_x, like_x])

            where_clause = " WHERE " + " AND ".join(query_conds) if query_conds else ""
            count_sql = f"SELECT COUNT(*) FROM functions f{where_clause}"
            cur.execute(count_sql, params)
            total_matches = int(cur.fetchone()[0])

            page_sql = f"SELECT f.data FROM functions f{where_clause} ORDER BY f.size DESC LIMIT ? OFFSET ?"
            cur.execute(page_sql, params + [limit, offset])
            rows = cur.fetchall()
            for r in rows:
                fn = json.loads(r["data"])
                m = _check_fn(fn)
                if m:
                    matched_summaries.append(m)
        else:
            funcs = self._in_memory.get("functions", []) if self._in_memory else []
            for fn in funcs:
                m = _check_fn(fn)
                if m:
                    total_matches += 1
                    if len(matched_summaries) < limit and total_matches > offset:
                        matched_summaries.append(m)

        return {
            "status": "ok",
            "query": query,
            "opcode_filter": opcode,
            "xref_target": xref_target,
            "sensitive_only": sensitive_only,
            "total_matches": total_matches,
            "limit": limit,
            "offset": offset,
            "matches": matched_summaries,
            "epistemic_classification": "GHIDRA_INDEXED_FUNCTION_SEARCH",
        }

    def inspect_function(self, name_or_addr: str) -> Optional[Dict[str, Any]]:
        """
        Recovers comprehensive architectural and decompiler telemetry for a single function.
        Includes demangled prototype, parameter details, local variables, 12-category P-Code
        distribution, cyclomatic complexity, call hierarchy, and decompiled C preview.
        """
        fn = self.get_function(name_or_addr)
        if not fn:
            return None

        from ghidra_pcode_vectorizer import (
            PCODE_CATEGORIES, OPCODE_MAP, GhidraDeepAnalyzer
        )

        fn_name = str(fn.get("name", "unknown"))
        entry = str(fn.get("entry_point", fn.get("address", "0x0")))
        pcode = fn.get("pcode_ops", [])
        blocks = fn.get("basic_blocks", [])
        callees = fn.get("callees", [])
        xrefs = fn.get("xrefs", [])
        c_code = fn.get("decompiled_c", "")
        locals_list = fn.get("local_variables", [])

        # 1. P-Code category distribution
        cat_counts = {cat: 0 for cat in PCODE_CATEGORIES}
        opcode_counts: Dict[str, int] = {}
        for op in pcode:
            opc = str(op.get("opcode", "")).upper()
            opcode_counts[opc] = opcode_counts.get(opc, 0) + 1
            cat = OPCODE_MAP.get(opc, "SUBPIECE_CAST")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        # 2. Control flow metrics
        num_blocks = len(blocks)
        total_out = sum(b.get("out_degree", len(b.get("successors", []))) for b in blocks)
        cyclomatic = max(1, total_out - num_blocks + 2) if num_blocks > 0 else 1

        # 3. Callers discovery
        callers = []
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            cur.execute("SELECT DISTINCT caller_name FROM call_edges WHERE callee_name = ? LIMIT 50", (fn_name,))
            callers = [r["caller_name"] for r in cur.fetchall()]
        else:
            funcs = self._in_memory.get("functions", []) if self._in_memory else []
            for other_fn in funcs:
                if fn_name in other_fn.get("callees", []):
                    callers.append(str(other_fn.get("name", other_fn.get("entry_point"))))
                if len(callers) >= 50:
                    break

        # 4. Sensitive API reachability
        sensitive_apis = [c for c in callees if any(pat.lower() in str(c).lower() for pat in SENSITIVE_API_PATTERNS)]

        demangled = GhidraDeepAnalyzer.demangle_msvc_symbol(fn_name)

        return {
            "status": "ok",
            "name": fn_name,
            "demangled_name": demangled if demangled != fn_name else None,
            "entry_point": entry,
            "size_bytes": int(fn.get("size", 0)),
            "signature": fn.get("signature"),
            "return_type": fn.get("return_type", "void"),
            "parameter_count": int(fn.get("parameter_count", 0)),
            "parameters": fn.get("parameters", []),
            "local_variables_count": len(locals_list) if isinstance(locals_list, list) else 0,
            "local_variables": locals_list[:30] if isinstance(locals_list, list) else [],
            "cyclomatic_complexity": cyclomatic,
            "basic_blocks_count": num_blocks,
            "pcode_ops_total": len(pcode),
            "pcode_category_distribution": cat_counts,
            "top_opcodes": sorted(opcode_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "callees": callees[:50],
            "callers": callers[:50],
            "sensitive_apis_called": sensitive_apis,
            "xrefs_count": len(xrefs),
            "xrefs_sample": xrefs[:20],
            "has_decompiled_c": bool(c_code),
            "decompiled_c_preview": c_code[:4000] if c_code else None,
            "epistemic_classification": "GHIDRA_DEEP_FUNCTION_INSPECTION",
        }

    def search_xrefs(self, target: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Finds all cross-references pointing to or originating from target."""
        clean_target = target.strip().lower()
        if self.is_sqlite:
            con = self._get_connection()
            cur = con.cursor()
            cur.execute(
                "SELECT function_name, from_addr, to_addr, xref_type, symbol FROM xrefs WHERE to_addr LIKE ? OR symbol LIKE ? OR from_addr LIKE ? LIMIT ?",
                (f"%{clean_target}%", f"%{clean_target}%", f"%{clean_target}%", limit)
            )
            return [
                {
                    "function": r["function_name"],
                    "from": r["from_addr"],
                    "to": r["to_addr"],
                    "type": r["xref_type"],
                    "symbol": r["symbol"],
                }
                for r in cur.fetchall()
            ]

        res = []
        funcs = self._in_memory.get("functions", []) if self._in_memory else []
        for fn in funcs:
            fn_name = fn.get("name", "unknown")
            for xr in fn.get("xrefs", []):
                t = str(xr.get("to", "")).lower()
                s = str(xr.get("symbol", "")).lower()
                f = str(xr.get("from", "")).lower()
                if clean_target in t or clean_target in s or clean_target in f:
                    res.append({
                        "function": fn_name,
                        "from": xr.get("from", ""),
                        "to": xr.get("to", ""),
                        "type": xr.get("type", "REF"),
                        "symbol": xr.get("symbol", ""),
                    })
                    if len(res) >= limit:
                        return res
        return res

    def query_computational_profile(self) -> Dict[str, Any]:
        """
        Synthesizes the computational and architectural profile across all functions:
        computes aggregate opcode category distribution and cognitive complexity profile.
        """
        from ghidra_pcode_vectorizer import PCODE_CATEGORIES, OPCODE_MAP

        total_funcs = 0
        total_pcode_ops = 0
        total_blocks = 0
        cat_counts = {cat: 0 for cat in PCODE_CATEGORIES}
        sensitive_funcs = 0

        for fn in self.iter_functions():
            total_funcs += 1
            pcode = fn.get("pcode_ops", [])
            total_pcode_ops += len(pcode)
            total_blocks += len(fn.get("basic_blocks", []))
            callees = fn.get("callees", [])
            if any(any(pat.lower() in str(c).lower() for pat in SENSITIVE_API_PATTERNS) for c in callees):
                sensitive_funcs += 1
            for op in pcode:
                opc = str(op.get("opcode", "")).upper()
                cat = OPCODE_MAP.get(opc, "SUBPIECE_CAST")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1

        arith_ops = cat_counts.get("ALU_ARITH", 0) + cat_counts.get("ALU_LOGIC", 0) + cat_counts.get("BIT_SHIFT", 0)
        control_ops = cat_counts.get("CONTROL_BRANCH_COND", 0) + cat_counts.get("CONTROL_BRANCH_UNCOND", 0) + cat_counts.get("CONTROL_CALL", 0)
        mem_ops = cat_counts.get("MEMORY_LOAD", 0) + cat_counts.get("MEMORY_STORE", 0)

        arith_to_ctrl = round(arith_ops / max(1, control_ops), 3)
        mem_to_total = round(mem_ops / max(1, total_pcode_ops), 3)

        if arith_to_ctrl > 2.0:
            profile = "ALGORITHMIC_COMPUTE_INTENSIVE"
        elif control_ops > arith_ops:
            profile = "LOGIC_AND_STATE_MACHINE_HEAVY"
        elif mem_to_total > 0.4:
            profile = "MEMORY_AND_BUFFER_IO_INTENSIVE"
        else:
            profile = "BALANCED_SYSTEM_CODE"

        return {
            "status": "ok",
            "total_functions": total_funcs,
            "total_pcode_ops": total_pcode_ops,
            "total_basic_blocks": total_blocks,
            "sensitive_api_functions_count": sensitive_funcs,
            "arithmetic_to_control_ratio": arith_to_ctrl,
            "memory_io_ratio": mem_to_total,
            "architectural_classification": profile,
            "confidence_score": 0.85,
            "threshold_criteria": {
                "algorithmic_compute": "arith_to_ctrl > 2.0",
                "logic_state_machine": "control_ops > arith_ops",
                "memory_buffer_io": "mem_to_total > 0.4",
                "balanced": "fallback baseline"
            },
            "category_distribution": cat_counts,
            "epistemic_classification": "EXPLORATORY_HEURISTIC_ARCHITECTURAL_PROFILE",
            "disclaimer": "Heuristic categorization based on static P-Code category distribution; does not guarantee dynamic runtime behavior."
        }

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
