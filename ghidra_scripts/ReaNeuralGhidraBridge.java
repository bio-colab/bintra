// REA-Neural Ghidra Bridge: Extracts High P-Code, runs semantic deobfuscation, and mutates Ghidra DB.
//@category REA-Neural
//@keybinding 
//@menupath Tools.REA-Neural.Run Semantic Deobfuscation Bridge
//@toolbar 

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

public class ReaNeuralGhidraBridge extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=================================================================");
        println(" [REA-Neural] Initiating Symbiotic Ghidra Bridge (v7.3.0)");
        println("=================================================================");

        if (currentProgram == null) {
            printerr("[REA-Neural] No program loaded. Please open a binary in Ghidra.");
            return;
        }

        File reaRoot = resolveReaRoot();
        if (reaRoot == null || !new File(reaRoot, "src/cli.py").exists()) {
            printerr("[REA-Neural] Could not locate REA-Neural repository root (containing src/cli.py).");
            return;
        }
        println("[REA-Neural] Located REA-Neural root at: " + reaRoot.getAbsolutePath());

        // 1. Setup Decompiler
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // 2. Extract Functions and High P-Code
        println("[REA-Neural] Extracting High P-Code from program functions...");
        List<Map<String, Object>> functionsList = new ArrayList<>();
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int totalFuncs = 0;
        int decompiledCount = 0;

        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("[REA-Neural] Extraction cancelled by user.");
                return;
            }
            Function func = funcIter.next();
            totalFuncs++;

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (!results.decompileCompleted()) {
                continue;
            }

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) {
                continue;
            }

            decompiledCount++;
            Map<String, Object> funcData = new HashMap<>();
            funcData.put("name", func.getName());
            funcData.put("entry_point", "0x" + func.getEntryPoint().toString());
            funcData.put("parameter_count", func.getParameterCount());
            funcData.put("return_type", func.getReturnType().getName());

            List<Map<String, Object>> pcodeOpsList = new ArrayList<>();
            Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps();
            while (opIter.hasNext()) {
                PcodeOpAST op = opIter.next();
                Map<String, Object> opData = new HashMap<>();
                opData.put("opcode", op.getMnemonic());

                List<String> inputs = new ArrayList<>();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    VarnodeAST inVn = (VarnodeAST) op.getInput(i);
                    inputs.add(inVn != null ? formatVarnode(inVn) : "null");
                }
                opData.put("inputs", inputs);

                VarnodeAST outVn = (VarnodeAST) op.getOutput();
                opData.put("output", outVn != null ? formatVarnode(outVn) : null);
                pcodeOpsList.add(opData);
            }
            funcData.put("pcode_ops", pcodeOpsList);
            functionsList.add(funcData);
        }

        println("[REA-Neural] Extracted High P-Code for " + decompiledCount + " / " + totalFuncs + " functions.");

        // 3. Serialize to JSON
        Map<String, Object> payload = new HashMap<>();
        payload.put("program_name", currentProgram.getName());
        payload.put("image_base", "0x" + currentProgram.getImageBase().toString());
        payload.put("functions_count", functionsList.size());
        payload.put("functions", functionsList);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        File tempExport = File.createTempFile("rea_ghidra_export_", ".json");
        File tempPlan = File.createTempFile("rea_ghidra_plan_", ".json");
        tempExport.deleteOnExit();
        tempPlan.deleteOnExit();

        try (FileWriter writer = new FileWriter(tempExport)) {
            gson.toJson(payload, writer);
        }
        println("[REA-Neural] Exported P-Code JSON to: " + tempExport.getAbsolutePath());

        // 4. Invoke REA Engine
        println("[REA-Neural] Invoking REA Continuous Semantic Engine (ghidra-analyze)...");
        String pythonExe = resolvePythonExe();
        File cliPy = new File(reaRoot, "src/cli.py");

        ProcessBuilder pb = new ProcessBuilder(
            pythonExe,
            cliPy.getAbsolutePath(),
            "ghidra-analyze",
            "--input", tempExport.getAbsolutePath(),
            "--output", tempPlan.getAbsolutePath()
        );
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                println(" [REA CLI] " + line);
            }
        }

        int exitCode = proc.waitFor();
        if (exitCode != 0 || !tempPlan.exists()) {
            printerr("[REA-Neural] REA Analysis failed with exit code: " + exitCode);
            return;
        }

        // 5. Read Mutation Plan
        JsonObject planJson;
        try (FileReader reader = new FileReader(tempPlan)) {
            planJson = gson.fromJson(reader, JsonObject.class);
        }

        int opaqueDetected = planJson.has("opaque_predicates_total") ? planJson.get("opaque_predicates_total").getAsInt() : 0;
        JsonArray renames = planJson.has("rename_actions") ? planJson.getAsJsonArray("rename_actions") : new JsonArray();
        JsonArray comments = planJson.has("comment_actions") ? planJson.getAsJsonArray("comment_actions") : new JsonArray();

        println("[REA-Neural] Analysis Complete:");
        println("  * Total Opaque Predicates Detected: " + opaqueDetected);
        println("  * Proposed Function Renames: " + renames.size());
        println("  * Proposed Plate Comments: " + comments.size());

        // 6. User Confirmation
        boolean shouldApply = false;
        if (isRunningHeadless()) {
            // In headless mode, check for script argument "apply" or default to true
            String[] args = getScriptArgs();
            shouldApply = (args != null && args.length > 0 && "apply".equalsIgnoreCase(args[0]));
            if (!shouldApply) {
                println("[REA-Neural] Headless mode: mutations generated but not applied (pass 'apply' argument to commit).");
            }
        } else {
            String confirmMsg = String.format(
                "REA-Neural Semantic Analysis Complete:\n\n" +
                " - Analyzed Functions: %d\n" +
                " - Opaque Predicates Detected: %d\n" +
                " - Proposed Function Renames: %d\n" +
                " - Proposed Plate Comments: %d\n\n" +
                "Do you want to apply these mutations directly to the Ghidra Program Database?",
                decompiledCount, opaqueDetected, renames.size(), comments.size()
            );
            shouldApply = askYesNo("REA-Neural Mutation Plan", confirmMsg);
        }

        // 7. Apply Mutations in Transaction
        if (shouldApply) {
            println("[REA-Neural] Committing mutations to Ghidra Program Database...");
            int txId = currentProgram.startTransaction("REA-Neural Semantic Deobfuscation");
            boolean commitSuccess = false;
            try {
                // Apply Renames
                for (JsonElement elem : renames) {
                    JsonObject act = elem.getAsJsonObject();
                    String addrStr = act.get("address").getAsString();
                    String newName = act.get("name").getAsString();
                    Address addr = toAddress(addrStr);
                    if (addr != null) {
                        Function targetFunc = currentProgram.getFunctionManager().getFunctionAt(addr);
                        if (targetFunc != null) {
                            targetFunc.setName(newName, SourceType.USER_DEFINED);
                            println("   [RENAME] " + addrStr + " -> " + newName);
                        }
                    }
                }

                // Apply Comments
                for (JsonElement elem : comments) {
                    JsonObject act = elem.getAsJsonObject();
                    String addrStr = act.get("address").getAsString();
                    String commentText = act.get("comment").getAsString();
                    Address addr = toAddress(addrStr);
                    if (addr != null) {
                        setPlateComment(addr, commentText);
                        currentProgram.getBookmarkManager().setBookmark(
                            addr, "REA-Neural", "Semantic Deobfuscation", "Deobfuscated by REA-Neural continuous semantics"
                        );
                        println("   [COMMENT] Added plate comment at " + addrStr);
                    }
                }
                commitSuccess = true;
            } catch (Exception ex) {
                printerr("[REA-Neural] Error while mutating database: " + ex.getMessage());
            } finally {
                currentProgram.endTransaction(txId, commitSuccess);
            }

            if (commitSuccess) {
                println("[REA-Neural] Successfully applied all mutations to Program Database!");
            }
        } else {
            println("[REA-Neural] Database mutation skipped per user request.");
        }
        println("=================================================================");
    }

    private String formatVarnode(VarnodeAST vn) {
        if (vn == null) return "null";
        if (vn.isConstant()) {
            return "const:0x" + Long.toHexString(vn.getOffset());
        }
        if (vn.isRegister()) {
            String regName = currentProgram.getRegister(vn.getAddress(), vn.getSize()) != null ?
                currentProgram.getRegister(vn.getAddress(), vn.getSize()).getName() : "reg";
            return "reg:" + regName;
        }
        if (vn.isUnique()) {
            return "u_0x" + Long.toHexString(vn.getOffset());
        }
        return "ram:0x" + Long.toHexString(vn.getOffset());
    }

    private Address toAddress(String addrStr) {
        try {
            if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
                addrStr = addrStr.substring(2);
            }
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr);
        } catch (Exception e) {
            return null;
        }
    }

    private File resolveReaRoot() {
        String envRoot = System.getenv("REA_NEURAL_ROOT");
        if (envRoot != null && !envRoot.isEmpty()) {
            File f = new File(envRoot);
            if (f.exists()) return f;
        }
        File standardD = new File("D:\\rea-neural");
        if (standardD.exists()) return standardD;

        // Check relative to script location
        File scriptFile = getSourceFile().getFile(true);
        if (scriptFile != null && scriptFile.getParentFile() != null) {
            File parentDir = scriptFile.getParentFile().getParentFile();
            if (parentDir != null && new File(parentDir, "src/cli.py").exists()) {
                return parentDir;
            }
        }
        return null;
    }

    private String resolvePythonExe() {
        String envPy = System.getenv("PYTHON_EXE");
        if (envPy != null && !envPy.isEmpty() && new File(envPy).exists()) {
            return envPy;
        }
        return "python";
    }
}
