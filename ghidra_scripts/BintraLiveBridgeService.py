# -*- coding: utf-8 -*-
# Bintra Ghidra Live Bi-Directional Bridge Service (Python / PyGhidra)
# Connects to Bintra local JSON-RPC bridge daemon at 127.0.0.1:41718.
# Continuously receives Crash RCA bookmarks, VAD memory layout notes,
# and P-Code deobfuscation plans and commits them directly into the Ghidra Database.
#
# @category Bintra
# @menupath Tools.Bintra.Start Live Bridge Service
# @keybinding
# @toolbar

import os
import sys
import json
import time
import tempfile

try:
    import urllib.request as urllib_req
    from urllib.error import URLError, HTTPError
except ImportError:
    # Jython 2.7 fallback inside Ghidra GUI
    import urllib2 as urllib_req
    from urllib2 import URLError, HTTPError

DEFAULT_BRIDGE_PORT = 41718


def log_msg(msg):
    if "println" in globals():
        println("[Bintra-Bridge] " + str(msg))
    else:
        print("[Bintra-Bridge] " + str(msg))


def log_err(msg):
    if "printerr" in globals():
        printerr("[Bintra-Bridge ERROR] " + str(msg))
    else:
        sys.stderr.write("[Bintra-Bridge ERROR] " + str(msg) + "\n")


def resolve_bridge_config():
    """Locates .bintra_bridge.json marker in working tree, temp, or user home, or env override."""
    env_url = os.environ.get("BINTRA_BRIDGE_URL")
    if env_url:
        return env_url, os.environ.get("BINTRA_BRIDGE_TOKEN", "")

    candidates = [
        os.path.join(tempfile.gettempdir(), ".bintra_bridge.json"),
        os.path.join(os.getcwd(), ".bintra_bridge.json"),
        os.path.expanduser("~/.bintra_bridge.json"),
    ]
    bintra_root = os.environ.get("BINTRA_ROOT")
    if bintra_root:
        candidates.insert(0, os.path.join(bintra_root, ".bintra_bridge.json"))

    # Also search script parent directory
    script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
    parent_cand = os.path.dirname(script_dir)
    candidates.append(os.path.join(parent_cand, ".bintra_bridge.json"))

    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, "r") as f:
                    cfg = json.load(f)
                    return cfg.get("url", f"http://127.0.0.1:{DEFAULT_BRIDGE_PORT}"), cfg.get("auth_token", "")
            except Exception:
                pass

    return f"http://127.0.0.1:{DEFAULT_BRIDGE_PORT}", ""


def rpc_call(url, token, method, params=None):
    """Executes a JSON-RPC 2.0 call against Bintra bridge."""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": int(time.time() * 1000)
    }
    if token and "auth_token" not in payload["params"]:
        payload["params"]["auth_token"] = token

    data = json.dumps(payload).encode("utf-8")
    req = urllib_req.Request(url, data=data)
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if token:
        req.add_header("X-Bintra-Auth-Token", token)

    resp = urllib_req.urlopen(req, timeout=5.0)
    content = resp.read().decode("utf-8")
    res = json.loads(content)
    if "error" in res:
        raise RuntimeError(f"RPC Error [{res['error'].get('code')}]: {res['error'].get('message')}")
    return res.get("result")


def apply_command(prog, cmd):
    """Applies a single Bintra diagnostic command into the Ghidra Program Database."""
    action = cmd.get("action")
    details = cmd.get("details", {})
    listing = prog.getListing()
    addr_factory = prog.getAddressFactory()
    image_base = prog.getImageBase()

    def _resolve_addr(addr_val, address_space="auto"):
        if not addr_val:
            return None
        addr_str = str(addr_val).strip()
        mode = str(address_space or "auto").lower()
        # Numerical parsing first when explicit address space is declared
        try:
            val = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
            if mode == "rva":
                return image_base.add(val)
            if mode == "va":
                return addr_factory.getDefaultAddressSpace().getAddress(val)
            # Legacy auto fallback: avoid misclassifying full 64-bit VAs below high ASLR image bases as RVAs
            if val < 0x10000000 and val < image_base.getOffset():
                return image_base.add(val)
            return addr_factory.getDefaultAddressSpace().getAddress(val)
        except Exception:
            a = addr_factory.getAddress(addr_str)
            return a

    if action == "SET_PLATE_COMMENT":
        addr = _resolve_addr(details.get("address"), details.get("address_space", "auto"))
        comment = details.get("comment", "")
        if addr:
            cu = listing.getCodeUnitAt(addr)
            if cu:
                from ghidra.program.model.listing import CodeUnit
                cu.setComment(CodeUnit.PLATE_COMMENT, comment)
                log_msg(f"Applied PLATE_COMMENT at {addr.toString()}")
            else:
                log_msg(f"Target code unit not found at {addr.toString()} for plate comment.")

    elif action == "CREATE_BOOKMARK":
        addr = _resolve_addr(details.get("address"), details.get("address_space", "auto"))
        cat = details.get("category", "BINTRA_CRASH_FAULT")
        desc = details.get("description", "")
        if addr:
            bm = prog.getBookmarkManager()
            bm.setBookmark(addr, "BookmarkCategory", cat, desc)
            log_msg(f"Created Bookmark at {addr.toString()} [{cat}]: {desc}")

    elif action == "SET_PROGRAM_NOTE":
        title = details.get("title", "BINTRA_DIAGNOSTIC_NOTE")
        content = details.get("content", "")
        base_cu = listing.getCodeUnitAt(image_base)
        if base_cu:
            from ghidra.program.model.listing import CodeUnit
            cur = base_cu.getComment(CodeUnit.REPEATABLE_COMMENT) or ""
            note = f"\n\n=== {title} ===\n{content}".strip()
            new_c = f"{cur}\n{note}".strip() if cur else note
            base_cu.setComment(CodeUnit.REPEATABLE_COMMENT, new_c)
            log_msg(f"Applied Program Note '{title}' at image base {image_base.toString()}")

    elif action == "RENAME_FUNCTION":
        addr = _resolve_addr(details.get("address"), details.get("address_space", "auto"))
        new_name = details.get("new_name")
        if addr and new_name:
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if func:
                from ghidra.program.model.symbol import SourceType
                func.setName(new_name, SourceType.USER_DEFINED)
                log_msg(f"Renamed function at {addr.toString()} (entry: {func.getEntryPoint().toString()}) -> '{new_name}'")
            else:
                log_msg(f"No function found containing {addr.toString()} to rename.")

    elif action == "APPLY_DATA_STRUCTURE":
        addr = _resolve_addr(details.get("address"), details.get("address_space", "va"))
        struct_name = details.get("name", "BintraReconstructedStruct")
        c_decl = details.get("c_declaration", "")
        fields = details.get("fields", [])
        size = details.get("size", 0)

        # 1. Apply Plate Comment at structure base address
        if addr:
            cu = listing.getCodeUnitAt(addr)
            if cu:
                from ghidra.program.model.listing import CodeUnit
                comment = f"[Bintra Reconstructed Structure: {struct_name}] ({len(fields)} fields, {size} bytes)\n{c_decl}"
                cu.setComment(CodeUnit.PLATE_COMMENT, comment)
                log_msg(f"Applied Structure Plate Comment at {addr.toString()}")

        # 2. Add Composite Structure in Ghidra DataTypeManager if available
        try:
            from ghidra.program.model.data import (
                StructureDataType, ByteDataType, DWordDataType,
                QWordDataType, PointerDataType
            )
            dtm = prog.getDataTypeManager()
            struct_dt = StructureDataType(struct_name, 0)
            for f_info in fields:
                offset = f_info.get("offset_bytes", 0)
                if isinstance(offset, str):
                    offset = int(offset, 16) if offset.startswith("0x") else int(offset)
                f_type_str = f_info.get("inferred_type", "uint8")
                f_comment = f_info.get("description", "")
                f_name = f"field_0x{offset:X}"

                if "void*" in f_type_str or "ptr" in f_type_str.lower():
                    dt = PointerDataType()
                elif "64" in f_type_str:
                    dt = QWordDataType()
                elif "32" in f_type_str or "float" in f_type_str:
                    dt = DWordDataType()
                else:
                    dt = ByteDataType()

                struct_dt.insertAtOffset(offset, dt, dt.getLength(), f_name, f_comment)

            added_dt = dtm.addDataType(struct_dt, None)
            log_msg(f"Created DataTypeManager structure: {added_dt.getName()} ({added_dt.getLength()} bytes)")
        except Exception as dt_err:
            log_msg(f"DataTypeManager notice (running headless/fallback): {dt_err}")

    elif action == "SET_POINTER_CHAIN":
        addr = _resolve_addr(details.get("address"), details.get("address_space", "auto"))
        comment = details.get("comment", "")
        if addr:
            cu = listing.getCodeUnitAt(addr)
            if cu:
                from ghidra.program.model.listing import CodeUnit
                cu.setComment(CodeUnit.EOL_COMMENT, comment)
                log_msg(f"Applied Pointer Chain EOL comment at {addr.toString()}")


def run():
    log_msg("=================================================================")
    log_msg(" [Bintra] Ghidra Live Bridge Service v1.0.0 (Python)")
    log_msg("=================================================================")

    if "currentProgram" not in globals() or currentProgram is None:
        log_err("No program loaded. Please open a binary in Ghidra before running this service.")
        return

    bridge_url, auth_token = resolve_bridge_config()
    log_msg(f"Connecting to Bintra Bridge at: {bridge_url}")

    try:
        ping = rpc_call(bridge_url, auth_token, "ping")
        log_msg(f"Connected! Bridge status: {ping.get('status')} (version: {ping.get('bridge_version')})")
    except Exception as e:
        log_err(f"Connection to Bintra Bridge failed: {e}")
        log_err("Ensure Bintra bridge daemon is running ('python src/cli.py ghidra-bridge --start')")
        return

    # Register client metadata
    reg_params = {
        "program_name": currentProgram.getName(),
        "image_base": "0x%x" % currentProgram.getImageBase().getOffset(),
        "architecture": currentProgram.getLanguage().getProcessor().toString(),
        "ghidra_version": "Ghidra"
    }
    try:
        rpc_call(bridge_url, auth_token, "ghidra.register_client", reg_params)
        log_msg(f"Client registered for '{currentProgram.getName()}' (Base: {reg_params['image_base']})")
    except Exception as e:
        log_err(f"Failed to register client: {e}")
        return

    log_msg("Listening for live annotations and mutations...")
    log_msg("(To stop the service, click 'Cancel' in Ghidra's task monitor)")

    loop_count = 0
    while True:
        if "monitor" in globals() and monitor.isCancelled():
            log_msg("Live bridge listener cancelled by user.")
            break

        try:
            res = rpc_call(bridge_url, auth_token, "ghidra.poll_commands")
            cmds = res.get("commands", [])
            if cmds:
                log_msg(f"Processing {len(cmds)} diagnostic command(s)...")
                tx = currentProgram.startTransaction("Bintra Live Mutations")
                try:
                    for cmd in cmds:
                        apply_command(currentProgram, cmd)
                    currentProgram.endTransaction(tx, True)
                    log_msg("Transaction committed successfully.")
                except Exception as ex:
                    currentProgram.endTransaction(tx, False)
                    log_err(f"Transaction aborted due to error: {ex}")
        except Exception as e:
            if loop_count % 30 == 0:
                log_err(f"Polling error: {e}")

        loop_count += 1
        time.sleep(1.0)


if __name__ == "__main__":
    if "currentProgram" in globals():
        run()
    else:
        print("[Bintra] Ghidra Live Bridge Service Script loaded.")
        u, t = resolve_bridge_config()
        print(f"Target Bridge URL: {u}")
