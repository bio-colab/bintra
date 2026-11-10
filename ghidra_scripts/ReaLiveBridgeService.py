# -*- coding: utf-8 -*-
# REA-Neural Ghidra Live Bi-Directional Bridge Service (Python / PyGhidra)
# Connects to REA-Neural local JSON-RPC bridge daemon at 127.0.0.1:41718.
# Continuously receives Crash RCA bookmarks, VAD memory layout notes,
# and P-Code deobfuscation plans and commits them directly into the Ghidra Database.
#
# @category REA-Neural
# @menupath Tools.REA-Neural.Start Live Bridge Service
# @keybinding
# @toolbar

import os
import sys
import json
import time

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
        println("[REA-Bridge] " + str(msg))
    else:
        print("[REA-Bridge] " + str(msg))


def log_err(msg):
    if "printerr" in globals():
        printerr("[REA-Bridge ERROR] " + str(msg))
    else:
        sys.stderr.write("[REA-Bridge ERROR] " + str(msg) + "\n")


def resolve_bridge_config():
    """Locates .rea_bridge.json marker in working tree or user home."""
    candidates = [
        os.path.join(os.getcwd(), ".rea_bridge.json"),
        os.path.expanduser("~/.rea_bridge.json"),
    ]
    rea_root = os.environ.get("REA_NEURAL_ROOT")
    if rea_root:
        candidates.insert(0, os.path.join(rea_root, ".rea_bridge.json"))

    # Also search script parent directory
    script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
    parent_cand = os.path.dirname(script_dir)
    candidates.append(os.path.join(parent_cand, ".rea_bridge.json"))

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
    """Executes a JSON-RPC 2.0 call against REA-Neural bridge."""
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
        req.add_header("X-REA-Auth-Token", token)

    resp = urllib_req.urlopen(req, timeout=5.0)
    content = resp.read().decode("utf-8")
    res = json.loads(content)
    if "error" in res:
        raise RuntimeError(f"RPC Error [{res['error'].get('code')}]: {res['error'].get('message')}")
    return res.get("result")


def apply_command(prog, cmd):
    """Applies a single REA-Neural diagnostic command into the Ghidra Program Database."""
    action = cmd.get("action")
    details = cmd.get("details", {})
    listing = prog.getListing()
    addr_factory = prog.getAddressFactory()
    image_base = prog.getImageBase()

    def _resolve_addr(addr_val):
        if not addr_val:
            return None
        addr_str = str(addr_val).strip()
        # Direct lookup
        a = addr_factory.getAddress(addr_str)
        if a is not None:
            return a
        # Numerical conversion
        try:
            val = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
            # If val is an RVA relative to image base
            if val < image_base.getOffset():
                return image_base.add(val)
            return addr_factory.getDefaultAddressSpace().getAddress(val)
        except Exception:
            return None

    if action == "SET_PLATE_COMMENT":
        addr = _resolve_addr(details.get("address"))
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
        addr = _resolve_addr(details.get("address"))
        cat = details.get("category", "REA_CRASH_FAULT")
        desc = details.get("description", "")
        if addr:
            bm = prog.getBookmarkManager()
            bm.setBookmark(addr, "BookmarkCategory", cat, desc)
            log_msg(f"Created Bookmark at {addr.toString()} [{cat}]: {desc}")

    elif action == "SET_PROGRAM_NOTE":
        title = details.get("title", "REA_DIAGNOSTIC_NOTE")
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
        addr = _resolve_addr(details.get("address"))
        new_name = details.get("new_name")
        if addr and new_name:
            func = prog.getFunctionManager().getFunctionAt(addr)
            if func:
                from ghidra.program.model.symbol import SourceType
                func.setName(new_name, SourceType.USER_DEFINED)
                log_msg(f"Renamed function at {addr.toString()} -> '{new_name}'")


def run():
    log_msg("=================================================================")
    log_msg(" [REA-Neural] Ghidra Live Bridge Service v7.4.0 (Python)")
    log_msg("=================================================================")

    if "currentProgram" not in globals() or currentProgram is None:
        log_err("No program loaded. Please open a binary in Ghidra before running this service.")
        return

    bridge_url, auth_token = resolve_bridge_config()
    log_msg(f"Connecting to REA-Neural Bridge at: {bridge_url}")

    try:
        ping = rpc_call(bridge_url, auth_token, "ping")
        log_msg(f"Connected! Bridge status: {ping.get('status')} (version: {ping.get('bridge_version')})")
    except Exception as e:
        log_err(f"Connection to REA-Neural Bridge failed: {e}")
        log_err("Ensure REA-Neural bridge daemon is running ('python src/cli.py ghidra-bridge --start')")
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
                tx = currentProgram.startTransaction("REA-Neural Live Mutations")
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
        print("[REA-Neural] Ghidra Live Bridge Service Script loaded.")
        u, t = resolve_bridge_config()
        print(f"Target Bridge URL: {u}")
