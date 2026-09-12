import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import generic.concurrent.GThreadPool;
import generic.concurrent.QResult;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class DisrobeMetrics extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "metrics.json";

        Listing listing = currentProgram.getListing();

        long functionCount = 0;
        FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : fns) {
            if (f.isExternal()) {
                continue;
            }
            functionCount++;
        }

        long thunkCount = 0;
        FunctionIterator fns2 = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : fns2) {
            if (f.isThunk()) {
                thunkCount++;
            }
        }

        long instructionCount = 0;
        InstructionIterator insns = listing.getInstructions(true);
        while (insns.hasNext()) {
            insns.next();
            instructionCount++;
        }

        long definedStrings = 0;
        DataIterator data = listing.getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            if (d.hasStringValue()) {
                definedStrings++;
            }
        }

        long resolvedImports = 0;
        SymbolTable symtab = currentProgram.getSymbolTable();
        SymbolIterator extSyms = symtab.getExternalSymbols();
        while (extSyms.hasNext()) {
            Symbol s = extSyms.next();
            if (s.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION
                    || s.getSymbolType() == ghidra.program.model.symbol.SymbolType.LABEL) {
                resolvedImports++;
            }
        }

        long execBytes = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.isExecute()) {
                execBytes += b.getSize();
            }
        }

        long decompiledOk = 0;
        long decompileAttempts = 0;
        GThreadPool pool = GThreadPool.getPrivateThreadPool("Disrobe metrics");
        pool.setMaxThreadCount(4);
        DecompilerCallback<Boolean> callback = new DecompilerCallback<>(
                currentProgram, decompiler -> decompiler.toggleCCode(true)) {
            @Override
            public Boolean process(DecompileResults result, TaskMonitor taskMonitor) throws Exception {
                taskMonitor.checkCancelled();
                if (result == null || !result.decompileCompleted()
                        || result.getDecompiledFunction() == null) {
                    return false;
                }
                String source = result.getDecompiledFunction().getC();
                return source != null && !source.trim().isEmpty();
            }
        };
        callback.setTimeout(45);
        DecompilerConcurrentQ<Function, Boolean> queue =
            new DecompilerConcurrentQ<>(callback, pool, true, monitor);
        try {
            FunctionIterator dfns = currentProgram.getFunctionManager().getFunctions(true);
            for (Function f : dfns) {
                monitor.checkCancelled();
                if (f.isThunk() || f.isExternal()) {
                    continue;
                }
                decompileAttempts++;
                queue.add(f);
            }
            Collection<QResult<Function, Boolean>> results = queue.waitForResults();
            for (QResult<Function, Boolean> result : results) {
                if (result.hasError()) {
                    result.getResult();
                }
            }
            monitor.checkCancelled();
            if (results.size() != decompileAttempts) {
                throw new IOException("Ghidra returned " + results.size() + " of "
                    + decompileAttempts + " function results");
            }
            for (QResult<Function, Boolean> result : results) {
                Boolean successful = result.getResult();
                if (result.isCancelled() || successful == null) {
                    throw new IOException("Decompilation was cancelled for " + result.getItem());
                }
                if (successful) {
                    decompiledOk++;
                }
            }
        } finally {
            queue.dispose();
            callback.dispose();
        }

        File out = new File(outPath);
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        try {
            pw.println("{");
            pw.println("  \"runtime\": {");
            pw.println("    \"ghidra_version\": \"" + jsonEscape(Application.getApplicationVersion()) + "\",");
            pw.println("    \"java_home\": \"" + jsonEscape(System.getProperty("java.home")) + "\",");
            pw.println("    \"java_version\": \"" + jsonEscape(System.getProperty("java.version")) + "\",");
            pw.println("    \"java_vendor\": \"" + jsonEscape(System.getProperty("java.vendor")) + "\",");
            pw.println("    \"java_vm_name\": \"" + jsonEscape(System.getProperty("java.vm.name")) + "\"");
            pw.println("  },");
            pw.println("  \"program\": \"" + jsonEscape(currentProgram.getName()) + "\",");
            pw.println("  \"language\": \"" + jsonEscape(currentProgram.getLanguageID().getIdAsString()) + "\",");
            pw.println("  \"image_base\": \"" + currentProgram.getImageBase().toString() + "\",");
            pw.println("  \"functions\": " + functionCount + ",");
            pw.println("  \"thunks\": " + thunkCount + ",");
            pw.println("  \"instructions\": " + instructionCount + ",");
            pw.println("  \"defined_strings\": " + definedStrings + ",");
            pw.println("  \"resolved_imports\": " + resolvedImports + ",");
            pw.println("  \"executable_bytes\": " + execBytes + ",");
            pw.println("  \"decompile_workers\": 4,");
            pw.println("  \"decompile_timeout_seconds\": 45,");
            pw.println("  \"decompile_attempts\": " + decompileAttempts + ",");
            pw.println("  \"decompiled_ok\": " + decompiledOk);
            pw.println("}");
        } finally {
            pw.close();
        }
        println("DisrobeMetrics wrote " + outPath);
    }

    private static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\b", "\\b")
            .replace("\f", "\\f")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
