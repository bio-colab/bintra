# REA-Neural Ghidra Bridge (Python / PyGhidra variant)
# @category REA-Neural
# @menupath Tools.REA-Neural.Run Python Semantic Deobfuscation Bridge

import os
import sys
import json
import subprocess
import tempfile

def run():
    print("=================================================================")
    print(" [REA-Neural] Initiating Python Ghidra Bridge (v7.3.0)")
    print("=================================================================")

    if currentProgram is None:
        print("[REA-Neural] Error: No program loaded in Ghidra.")
        return

    rea_root = os.environ.get("REA_NEURAL_ROOT", r"D:\rea-neural")
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
            inputs = []
            for i in range(op.getNumInputs()):
                vn = op.getInput(i)
                inputs.append(str(vn) if vn else "null")
            out_vn = op.getOutput()
            pcode_ops.append({
                "opcode": op.getMnemonic(),
                "inputs": inputs,
                "output": str(out_vn) if out_vn else None
            })

        funcs_data.append({
            "name": func.getName(),
            "entry_point": "0x" + func.getEntryPoint().toString(),
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

    # Ask user or check headless
    should_apply = True
    if hasattr(globals().get("__builtins__", {}), "askYesNo"):
        msg = "Apply %d renames and %d comments to Ghidra Database?" % (len(renames), len(comments))
        should_apply = askYesNo("REA-Neural Mutations", msg)

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
