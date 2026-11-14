# Bintra Ghidra Bridge (Python / PyGhidra variant)
# @category Bintra
# @menupath Tools.Bintra.Run Python Semantic Deobfuscation Bridge

import os
import sys
import json
import subprocess
import tempfile

def serialize_varnode(vn, current_prog):
    if vn is None:
        return None
    try:
        size = vn.getSize()
        offset = "0x%x" % vn.getOffset()
        v_map = {"size": size, "offset": offset}

        if vn.isConstant():
            v_map["kind"] = "constant"
            v_map["const_val"] = vn.getOffset()
        elif vn.isRegister():
            v_map["kind"] = "register"
            reg = current_prog.getRegister(vn.getAddress(), vn.getSize())
            v_map["name"] = reg.getName() if reg else "reg"
        elif vn.isUnique():
            v_map["kind"] = "unique"
            v_map["unique_id"] = vn.getUniqueId()
        elif vn.isAddress():
            v_map["kind"] = "address"
        else:
            v_map["kind"] = "ram"

        def_op = vn.getDef()
        if def_op is not None:
            def_addr = "0x" + def_op.getSeqnum().getTarget().toString()
            def_time = def_op.getSeqnum().getTime()
            v_map["def_addr"] = def_addr
            v_map["def_seq"] = def_time
            v_map["def_id"] = "%s:%s" % (def_addr, def_time)
            v_map["def_opcode"] = def_op.getMnemonic()
        else:
            v_map["def_addr"] = None
            v_map["def_seq"] = None
            v_map["def_id"] = None
            v_map["is_input"] = vn.isInput()

        return v_map
    except Exception:
        return str(vn)


def run():
    print("=================================================================")
    print(" [Bintra] Initiating Python Ghidra Bridge (v1.0.0)")
    print("=================================================================")

    if currentProgram is None:
        print("[Bintra] Error: No program loaded in Ghidra.")
        return

    bintra_root = os.environ.get("BINTRA_ROOT")
    if not bintra_root:
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
        candidate = os.path.dirname(script_dir)
        if os.path.exists(os.path.join(candidate, "src", "cli.py")):
            bintra_root = candidate
        else:
            bintra_root = "."
    cli_py = os.path.join(bintra_root, "src", "cli.py")
    if not os.path.exists(cli_py):
        print("[Bintra] Error: Could not locate Bintra CLI at: " + cli_py)
        return

    # Decompile and extract High P-Code
    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    funcs_data = []
    fm = currentProgram.getFunctionManager()
    total_funcs = fm.getFunctionCount()
    print("[Bintra] Scanning %d functions for High P-Code..." % total_funcs)

    for func in fm.getFunctions(True):
        if monitor.isCancelled():
            break
        res = decomp.decompileFunction(func, 30, monitor)
        if not res.decompileCompleted():
            continue
        high_func = res.getHighFunction()
        if not high_func:
            continue

        pcode_ops = []
        op_iter = high_func.getPcodeOps()
        while op_iter.hasNext():
            op = op_iter.next()
            op_addr = "0x" + op.getSeqnum().getTarget().toString()
            op_seq = op.getSeqnum().getTime()
            inputs = []
            for i in range(op.getNumInputs()):
                vn = op.getInput(i)
                inputs.append(serialize_varnode(vn, currentProgram))
            out_vn = op.getOutput()
            pcode_ops.append({
                "opcode": op.getMnemonic(),
                "address": op_addr,
                "seq": op_seq,
                "op_id": "%s:%s" % (op_addr, op_seq),
                "inputs": inputs,
                "output": serialize_varnode(out_vn, currentProgram)
            })

        callees = []
        try:
            for c_fn in func.getCalledFunctions(monitor):
                callees.append(c_fn.getName())
        except Exception:
            pass

        xrefs = []
        try:
            ref_mgr = currentProgram.getReferenceManager()
            ref_iter = ref_mgr.getReferencesTo(func.getEntryPoint())
            while ref_iter.hasNext() and len(xrefs) < 64:
                r = ref_iter.next()
                xrefs.append({
                    "from": "0x" + r.getFromAddress().toString(),
                    "to": "0x" + r.getToAddress().toString(),
                    "type": str(r.getReferenceType()),
                })
        except Exception:
            pass

        decompiled_c = ""
        try:
            dc_fn = res.getDecompiledFunction()
            if dc_fn is not None:
                decompiled_c = dc_fn.getC() or ""
        except Exception:
            pass

        local_vars = []
        try:
            for lv in func.getLocalVariables()[:40]:
                local_vars.append({
                    "name": lv.getName(),
                    "type": lv.getDataType().getName(),
                    "storage": str(lv.getVariableStorage()),
                })
        except Exception:
            pass

        funcs_data.append({
            "name": func.getName(),
            "entry_point": "0x" + func.getEntryPoint().toString(),
            "size": int(func.getBody().getNumAddresses()),
            "parameter_count": func.getParameterCount(),
            "return_type": func.getReturnType().getName(),
            "signature": func.getPrototypeString(False, False),
            "callees": callees,
            "xrefs": xrefs,
            "local_variables": local_vars,
            "decompiled_c": decompiled_c,
            "pcode_ops": pcode_ops
        })

    payload = {
        "program_name": currentProgram.getName(),
        "image_base": "0x" + currentProgram.getImageBase().toString(),
        "functions_count": len(funcs_data),
        "functions": funcs_data
    }

    # Write export JSON inside authorized Bintra workspace
    ws_dir = os.path.join(os.path.expanduser("~"), ".bintra", "workspace")
    exports_dir = os.path.join(ws_dir, "exports")
    plans_dir = os.path.join(ws_dir, "plans")
    if not os.path.isdir(exports_dir):
        os.makedirs(exports_dir)
    if not os.path.isdir(plans_dir):
        os.makedirs(plans_dir)
    fd_exp, export_path = tempfile.mkstemp(prefix="bintra_exp_", suffix=".json", dir=exports_dir)
    os.close(fd_exp)
    fd_plan, plan_path = tempfile.mkstemp(prefix="bintra_plan_", suffix=".json", dir=plans_dir)
    os.close(fd_plan)

    with open(export_path, "w") as f:
        json.dump(payload, f, indent=2)

    # Invoke Bintra
    python_exe = os.environ.get("PYTHON_EXE", "python")
    cmd = [python_exe, cli_py, "ghidra-analyze", "--input", export_path, "--output", plan_path, "--workspace", plans_dir]
    print("[Bintra] Running: " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print(stdout)

    if proc.returncode != 0 or not os.path.exists(plan_path):
        print("[Bintra] Analysis failed: " + stderr)
        return

    with open(plan_path, "r") as f:
        plan = json.load(f)

    renames = plan.get("rename_actions", [])
    comments = plan.get("comment_actions", [])
    print("[Bintra] Analysis found %d renames and %d comments." % (len(renames), len(comments)))

    # Security confirmation: In Ghidra Jython, askYesNo is injected into script globals(), not __builtins__.
    # Default to False (fail-closed) unless the user explicitly confirms or BINTRA_GHIDRA_AUTO_APPLY is set.
    should_apply = False
    msg = "Apply %d renames and %d comments to Ghidra Database?" % (len(renames), len(comments))
    try:
        ask_func = globals().get("askYesNo")
        if ask_func is not None and callable(ask_func):
            should_apply = ask_func("Bintra Mutations", msg)
        elif "askYesNo" in dir(__builtins__):
            should_apply = askYesNo("Bintra Mutations", msg)
        elif os.environ.get("BINTRA_GHIDRA_AUTO_APPLY", "").lower() in ("1", "true", "yes"):
            # Authorized automated headless workflow
            should_apply = True
        else:
            print("[Bintra] Interactive prompt 'askYesNo' unavailable in headless context; mutations not applied (set BINTRA_GHIDRA_AUTO_APPLY=1 to permit).")
    except Exception as e:
        print("[Bintra] Confirmation check error: %s; fail-closed." % e)
        should_apply = False

    if should_apply:
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.listing import CodeUnit
        tx = currentProgram.startTransaction("Bintra Semantic Mutations")
        try:
            for r in renames:
                addr = currentProgram.getAddressFactory().getAddress(r["address"])
                fn = currentProgram.getFunctionManager().getFunctionAt(addr)
                if fn:
                    fn.setName(r["name"], SourceType.USER_DEFINED)
            for c in comments:
                addr = currentProgram.getAddressFactory().getAddress(c["address"])
                currentProgram.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, c["comment"])
            print("[Bintra] Successfully applied mutations to Ghidra Program Database.")
        finally:
            currentProgram.endTransaction(tx, True)

if __name__ == "__main__":
    run()
