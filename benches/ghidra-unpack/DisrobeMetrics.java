import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

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

        ExternalManager extMgr = currentProgram.getExternalManager();
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
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try {
            FunctionIterator dfns = currentProgram.getFunctionManager().getFunctions(true);
            for (Function f : dfns) {
                if (f.isThunk() || f.isExternal()) {
                    continue;
                }
                decompileAttempts++;
                DecompileResults r = ifc.decompileFunction(f, 45, new ConsoleTaskMonitor());
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    String c = r.getDecompiledFunction().getC();
                    if (c != null && c.trim().length() > 0) {
                        decompiledOk++;
                    }
                }
            }
        } finally {
            ifc.dispose();
        }

        File out = new File(outPath);
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        try {
            pw.println("{");
            pw.println("  \"program\": \"" + jsonEscape(currentProgram.getName()) + "\",");
            pw.println("  \"language\": \"" + jsonEscape(currentProgram.getLanguageID().getIdAsString()) + "\",");
            pw.println("  \"image_base\": \"" + currentProgram.getImageBase().toString() + "\",");
            pw.println("  \"functions\": " + functionCount + ",");
            pw.println("  \"thunks\": " + thunkCount + ",");
            pw.println("  \"instructions\": " + instructionCount + ",");
            pw.println("  \"defined_strings\": " + definedStrings + ",");
            pw.println("  \"resolved_imports\": " + resolvedImports + ",");
            pw.println("  \"executable_bytes\": " + execBytes + ",");
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
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
