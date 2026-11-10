# REA-Neural Ghidra Bridge (Python / PyGhidra variant)
# @category REA-Neural
# @menupath Tools.REA-Neural.Run Python Semantic Deobfuscation Bridge

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
    print(" [REA-Neural] Initiating Python Ghidra Bridge (v7.4.0)")
    print("=================================================================")

    if currentProgram is None:
        print("[REA-Neural] Error: No program loaded in Ghidra.")
        return

    rea_root = os.environ.get("REA_NEURAL_ROOT")
    if not rea_root:
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
        candidate = os.path.dirname(script_dir)
        if os.path.exists(os.path.join(candidate, "src", "cli.py")):
            rea_root = candidate
        else:
            rea_root = "."
    cli_py = os.path.join(rea_root, "src", "cli.py")
    if not os.path.exists(cli_py):
        print("[REA-Neural] Error: Could not locate REA CLI at: " + cli_py)
        return

    # Decompile and extract High P-Code
    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    funcs_data = []
    fm = currentProgram.getFunctionManager()
    total_funcs = fm.getFunctionCount()
    print("[REA-Neural] Scanning %d functions for High P-Code..." % total_funcs)

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

        funcs_data.append({
            "name": func.getName(),
            "entry_point": "0x" + func.getEntryPoint().toString(),
            "size": int(func.getBody().getNumAddresses()),
            "parameter_count": func.getParameterCount(),
            "return_type": func.getReturnType().getName(),
            "pcode_ops": pcode_ops
        })

    payload = {
        "program_name": currentProgram.getName(),
        "image_base": "0x" + currentProgram.getImageBase().toString(),
        "functions_count": len(funcs_data),
        "functions": funcs_data
    }

    # Write export JSON
    fd_exp, export_path = tempfile.mkstemp(prefix="rea_exp_", suffix=".json")
    os.close(fd_exp)
    fd_plan, plan_path = tempfile.mkstemp(prefix="rea_plan_", suffix=".json")
    os.close(fd_plan)

    with open(export_path, "w") as f:
        json.dump(payload, f, indent=2)

    # Invoke REA
    python_exe = os.environ.get("PYTHON_EXE", "python")
    cmd = [python_exe, cli_py, "ghidra-analyze", "--input", export_path, "--output", plan_path]
    print("[REA-Neural] Running: " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print(stdout)

    if proc.returncode != 0 or not os.path.exists(plan_path):
        print("[REA-Neural] Analysis failed: " + stderr)
        return

    with open(plan_path, "r") as f:
        plan = json.load(f)

    renames = plan.get("rename_actions", [])
    comments = plan.get("comment_actions", [])
    print("[REA-Neural] Analysis found %d renames and %d comments." % (len(renames), len(comments)))

    # Security confirmation: In Ghidra Jython, askYesNo is injected into script globals(), not __builtins__.
    # Default to False (fail-closed) unless the user explicitly confirms or REA_GHIDRA_AUTO_APPLY is set.
    should_apply = False
    msg = "Apply %d renames and %d comments to Ghidra Database?" % (len(renames), len(comments))
    try:
        ask_func = globals().get("askYesNo")
        if ask_func is not None and callable(ask_func):
            should_apply = ask_func("REA-Neural Mutations", msg)
        elif "askYesNo" in dir(__builtins__):
            should_apply = askYesNo("REA-Neural Mutations", msg)
        elif os.environ.get("REA_GHIDRA_AUTO_APPLY", "").lower() in ("1", "true", "yes"):
            # Authorized automated headless workflow
            should_apply = True
        else:
            print("[REA-Neural] Interactive prompt 'askYesNo' unavailable in headless context; mutations not applied (set REA_GHIDRA_AUTO_APPLY=1 to permit).")
    except Exception as e:
        print("[REA-Neural] Confirmation check error: %s; fail-closed." % e)
        should_apply = False

    if should_apply:
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.listing import CodeUnit
        tx = currentProgram.startTransaction("REA-Neural Semantic Mutations")
        try:
            for r in renames:
                addr = currentProgram.getAddressFactory().getAddress(r["address"])
                fn = currentProgram.getFunctionManager().getFunctionAt(addr)
                if fn:
                    fn.setName(r["name"], SourceType.USER_DEFINED)
            for c in comments:
                addr = currentProgram.getAddressFactory().getAddress(c["address"])
                currentProgram.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, c["comment"])
            print("[REA-Neural] Successfully applied mutations to Ghidra Program Database.")
        finally:
            currentProgram.endTransaction(tx, True)

if __name__ == "__main__":
    run()
