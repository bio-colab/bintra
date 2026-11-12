// Bintra Ghidra Bridge: Extracts High P-Code, SSA Def-Use chains, and Full CFG, runs evidence-based semantic deobfuscation, and commits verified mutations.
//@category Bintra
//@keybinding 
//@menupath Tools.Bintra.Run Semantic Deobfuscation Bridge
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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

public class BintraGhidraBridge extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=================================================================");
        println(" [Bintra] Initiating Symbiotic Ghidra Bridge (v1.0.0)");
        println("=================================================================");

        if (currentProgram == null) {
            printerr("[Bintra] No program loaded. Please open a binary in Ghidra.");
            return;
        }

        File bintraRoot = resolveBintraRoot();
        if (bintraRoot == null || !new File(bintraRoot, "src/cli.py").exists()) {
            printerr("[Bintra] Could not locate Bintra repository root (containing src/cli.py).");
            return;
        }
        println("[Bintra] Located Bintra root at: " + bintraRoot.getAbsolutePath());

        // 1. Setup Decompiler
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // 2. Extract Functions, Full CFG, and High P-Code with SSA Def-Use
        println("[Bintra] Extracting High P-Code, SSA Def-Use, and CFG from program functions...");
        List<Map<String, Object>> functionsList = new ArrayList<>();
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int totalFuncs = 0;
        int decompiledCount = 0;

        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("[Bintra] Extraction cancelled by user.");
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
            funcData.put("size", (int) func.getBody().getNumAddresses());
            funcData.put("parameter_count", func.getParameterCount());
            funcData.put("return_type", func.getReturnType().getName());

            // 2a. Extract Full CFG (Basic Blocks, In/Out Edges, Branch Topology)
            List<Map<String, Object>> blocksList = new ArrayList<>();
            ArrayList<PcodeBlockBasic> bBlocks = highFunc.getBasicBlocks();
            if (bBlocks != null) {
                for (PcodeBlockBasic block : bBlocks) {
                    Map<String, Object> blockData = new HashMap<>();
                    blockData.put("id", block.getIndex());
                    blockData.put("start", "0x" + block.getStart().toString());
                    blockData.put("stop", "0x" + block.getStop().toString());
                    blockData.put("end", "0x" + block.getStop().toString());
                    blockData.put("size", (int) (block.getStop().getOffset() - block.getStart().getOffset() + 1));
                    blockData.put("in_degree", block.getInSize());
                    blockData.put("out_degree", block.getOutSize());

                    List<Integer> inBlocks = new ArrayList<>();
                    for (int i = 0; i < block.getInSize(); i++) {
                        inBlocks.add(block.getIn(i).getIndex());
                    }
                    blockData.put("predecessors", inBlocks);

                    List<Integer> outBlocks = new ArrayList<>();
                    for (int i = 0; i < block.getOutSize(); i++) {
                        outBlocks.add(block.getOut(i).getIndex());
                    }
                    blockData.put("successors", outBlocks);

                    if (block.getOutSize() >= 2) {
                        try {
                            if (block.getTrueOut() != null) {
                                blockData.put("true_out", block.getTrueOut().getIndex());
                            }
                        } catch (Exception ignored) {}
                        try {
                            if (block.getFalseOut() != null) {
                                blockData.put("false_out", block.getFalseOut().getIndex());
                            }
                        } catch (Exception ignored) {}
                    }
                    blocksList.add(blockData);
                }
            }
            funcData.put("basic_blocks", blocksList);

            // 2b. Extract High P-Code with SSA Def-Use and Varnode Metadata
            List<Map<String, Object>> pcodeOpsList = new ArrayList<>();
            Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps();
            while (opIter.hasNext()) {
                PcodeOpAST op = opIter.next();
                Map<String, Object> opData = new HashMap<>();
                String targetAddr = "0x" + op.getSeqnum().getTarget().toString();
                int opTime = op.getSeqnum().getTime();
                opData.put("seq", opTime);
                opData.put("address", targetAddr);
                opData.put("op_id", targetAddr + ":" + opTime);
                opData.put("opcode", op.getMnemonic());
                opData.put("block_id", op.getParent() != null ? op.getParent().getIndex() : -1);

                List<Map<String, Object>> inputs = new ArrayList<>();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    VarnodeAST inVn = (VarnodeAST) op.getInput(i);
                    inputs.add(serializeVarnode(inVn));
                }
                opData.put("inputs", inputs);

                VarnodeAST outVn = (VarnodeAST) op.getOutput();
                opData.put("output", serializeVarnode(outVn));
                pcodeOpsList.add(opData);
            }
            funcData.put("pcode_ops", pcodeOpsList);
            functionsList.add(funcData);
        }

        println("[Bintra] Extracted High P-Code & Full CFG for " + decompiledCount + " / " + totalFuncs + " functions.");

        // 3. Serialize to JSON
        Map<String, Object> payload = new HashMap<>();
        payload.put("program_name", currentProgram.getName());
        payload.put("image_base", "0x" + currentProgram.getImageBase().toString());
        payload.put("functions_count", functionsList.size());
        payload.put("functions", functionsList);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        File wsDir = new File(System.getProperty("user.home"), ".bintra" + File.separator + "workspace");
        File exportsDir = new File(wsDir, "exports");
        File plansDir = new File(wsDir, "plans");
        if (!exportsDir.exists()) {
            exportsDir.mkdirs();
        }
        if (!plansDir.exists()) {
            plansDir.mkdirs();
        }
        File tempExport = File.createTempFile("bintra_ghidra_export_", ".json", exportsDir);
        File tempPlan = File.createTempFile("bintra_ghidra_plan_", ".json", plansDir);
        tempExport.deleteOnExit();
        tempPlan.deleteOnExit();

        try (FileWriter writer = new FileWriter(tempExport)) {
            gson.toJson(payload, writer);
        }
        println("[Bintra] Exported P-Code & CFG JSON to: " + tempExport.getAbsolutePath());

        // 4. Invoke Bintra Engine
        println("[Bintra] Invoking Bintra Continuous Semantic Engine (ghidra-analyze)...");
        String pythonExe = resolvePythonExe();
        File cliPy = new File(bintraRoot, "src/cli.py");

        ProcessBuilder pb = new ProcessBuilder(
            pythonExe,
            cliPy.getAbsolutePath(),
            "ghidra-analyze",
            "--input", tempExport.getAbsolutePath(),
            "--output", tempPlan.getAbsolutePath(),
            "--workspace", plansDir.getAbsolutePath()
        );
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                println(" [Bintra CLI] " + line);
            }
        }

        int exitCode = proc.waitFor();
        if (exitCode != 0 || !tempPlan.exists()) {
            printerr("[Bintra] Bintra Analysis failed with exit code: " + exitCode);
            throw new RuntimeException("[Bintra] Bintra Analysis failed with exit code: " + exitCode);
        }

        // 5. Read Mutation Plan
        JsonObject planJson;
        try (FileReader reader = new FileReader(tempPlan)) {
            planJson = gson.fromJson(reader, JsonObject.class);
        }

        int opaqueDetected = planJson.has("opaque_predicates_total") ? planJson.get("opaque_predicates_total").getAsInt() : 0;
        int cffDetected = planJson.has("cff_backbones_total") ? planJson.get("cff_backbones_total").getAsInt() : 0;
        JsonArray renames = planJson.has("rename_actions") ? planJson.getAsJsonArray("rename_actions") : new JsonArray();
        JsonArray comments = planJson.has("comment_actions") ? planJson.getAsJsonArray("comment_actions") : new JsonArray();
        JsonArray evidenceList = planJson.has("evidence_dossiers") ? planJson.getAsJsonArray("evidence_dossiers") : new JsonArray();

        println("[Bintra] Analysis Complete:");
        println("  * Proven Invariant Tautologies (Opaque Predicates): " + opaqueDetected);
        println("  * Control Flow Flattening (CFF) Backbones: " + cffDetected);
        println("  * Evidence Dossiers Generated: " + evidenceList.size());
        println("  * Verified Rename Recommendations: " + renames.size());
        println("  * Verified Plate Comment / Evidence Actions: " + comments.size());

        // 6. User Confirmation
        boolean shouldApply = false;
        if (isRunningHeadless()) {
            String[] args = getScriptArgs();
            shouldApply = (args != null && args.length > 0 && "apply".equalsIgnoreCase(args[0]));
            if (!shouldApply) {
                println("[Bintra] Headless mode: evidence dossiers generated but mutations not applied (pass 'apply' argument to commit).");
            }
        } else {
            String confirmMsg = String.format(
                "Bintra Semantic Analysis Complete:\n\n" +
                " - Analyzed Functions: %d\n" +
                " - Proven Opaque Predicates: %d\n" +
                " - CFF Dispatcher Backbones: %d\n" +
                " - Evidence Dossiers: %d\n" +
                " - Verified Rename Actions: %d\n" +
                " - Plate Comments: %d\n\n" +
                "Do you want to apply these verified mutations directly to the Ghidra Program Database?",
                decompiledCount, opaqueDetected, cffDetected, evidenceList.size(), renames.size(), comments.size()
            );
            shouldApply = askYesNo("Bintra Mutation Plan", confirmMsg);
        }

        // 7. Apply Verified Mutations in Safe Transaction
        if (shouldApply) {
            println("[Bintra] Committing verified mutations to Ghidra Program Database...");
            int txId = currentProgram.startTransaction("Bintra Semantic Deobfuscation");
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
                            String orig = targetFunc.getName();
                            targetFunc.setName(newName, SourceType.USER_DEFINED);
                            println("   [RENAME] " + addrStr + " (" + orig + ") -> " + newName);
                        }
                    }
                }

                // Apply Comments & Bookmarks
                for (JsonElement elem : comments) {
                    JsonObject act = elem.getAsJsonObject();
                    String addrStr = act.get("address").getAsString();
                    String commentText = act.get("comment").getAsString();
                    Address addr = toAddress(addrStr);
                    if (addr != null) {
                        setPlateComment(addr, commentText);
                        currentProgram.getBookmarkManager().setBookmark(
                            addr, "Bintra", "Evidence-Based Deobfuscation", "Analyzed with High P-Code SSA & CFG"
                        );
                        println("   [COMMENT] Added verified plate comment at " + addrStr);
                    }
                }
                commitSuccess = true;
            } catch (Exception ex) {
                printerr("[Bintra] Error while mutating database: " + ex.getMessage());
            } finally {
                currentProgram.endTransaction(txId, commitSuccess);
            }

            if (commitSuccess) {
                println("[Bintra] Successfully applied all verified mutations to Program Database!");
            }
        } else {
            println("[Bintra] Database mutation skipped per user request.");
        }
        println("=================================================================");
    }

    private Map<String, Object> serializeVarnode(VarnodeAST vn) {
        if (vn == null) return null;
        Map<String, Object> vMap = new HashMap<>();
        vMap.put("size", vn.getSize());
        vMap.put("offset", "0x" + Long.toHexString(vn.getOffset()));

        String kind = "ram";
        if (vn.isConstant()) {
            kind = "constant";
            vMap.put("const_val", vn.getOffset());
        } else if (vn.isRegister()) {
            kind = "register";
            String regName = currentProgram.getRegister(vn.getAddress(), vn.getSize()) != null ?
                currentProgram.getRegister(vn.getAddress(), vn.getSize()).getName() : "reg";
            vMap.put("name", regName);
        } else if (vn.isUnique()) {
            kind = "unique";
            vMap.put("unique_id", vn.getUniqueId());
        } else if (vn.isAddress()) {
            kind = "address";
        }
        vMap.put("kind", kind);

        // SSA Def: Export address + time to guarantee globally unique definition identity
        PcodeOp defOp = vn.getDef();
        if (defOp != null) {
            String defAddr = "0x" + defOp.getSeqnum().getTarget().toString();
            int defTime = defOp.getSeqnum().getTime();
            vMap.put("def_addr", defAddr);
            vMap.put("def_seq", defTime);
            vMap.put("def_id", defAddr + ":" + defTime);
            vMap.put("def_opcode", defOp.getMnemonic());
        } else {
            vMap.put("def_addr", null);
            vMap.put("def_seq", null);
            vMap.put("def_id", null);
            vMap.put("is_input", vn.isInput());
        }

        // SSA Use count
        int uses = 0;
        Iterator<PcodeOp> descIter = vn.getDescendants();
        while (descIter.hasNext()) {
            descIter.next();
            uses++;
        }
        vMap.put("use_count", uses);

        // Debug string representation for backwards compatibility
        vMap.put("repr", formatVarnode(vn));

        return vMap;
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

    private File resolveBintraRoot() {
        String envRoot = System.getenv("BINTRA_ROOT");
        if (envRoot != null && !envRoot.isEmpty()) {
            File f = new File(envRoot);
            if (f.exists()) return f;
        }
        try {
            File scriptFile = getSourceFile().getFile(true);
            if (scriptFile != null && scriptFile.getParentFile() != null) {
                File parentDir = scriptFile.getParentFile().getParentFile();
                if (parentDir != null && new File(parentDir, "src/cli.py").exists()) {
                    return parentDir;
                }
            }
        } catch (Exception ignored) {}

        File cwd = new File(".");
        if (new File(cwd, "src/cli.py").exists()) return cwd;
        File parentCwd = new File("..");
        if (new File(parentCwd, "src/cli.py").exists()) return parentCwd;

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
