import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.Data;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DecompileToJsonScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("DR-PYARM-BCC-LIFT: missing output path argument");
            return;
        }
        File outFile = new File(args[0]);

        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            println("DR-PYARM-BCC-LIFT: decompiler open failed: " + ifc.getLastMessage());
            return;
        }

        StringBuilder json = new StringBuilder(64 * 1024);
        json.append("{\"functions\":[");

        FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFn = true;
        while (fns.hasNext()) {
            if (monitor.isCancelled()) break;
            Function fn = fns.next();
            if (fn.isThunk()) continue;
            Address entry = fn.getEntryPoint();

            DecompileResults results = ifc.decompileFunction(fn, 60, monitor);
            String c = "";
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                c = results.getDecompiledFunction().getC();
                if (c == null) c = "";
            }

            List<long[]> callees = collectCallees(fn);

            if (!firstFn) json.append(',');
            firstFn = false;
            json.append('{');
            appendField(json, "entry", String.format("0x%x", entry.getOffset()));
            json.append(',');
            appendField(json, "name", fn.getName());
            json.append(',');
            appendField(json, "signature", fn.getSignature().toString());
            json.append(',');
            appendField(json, "pseudoC", c);
            json.append(",\"size\":").append(fn.getBody().getNumAddresses());
            json.append(",\"paramCount\":").append(fn.getParameterCount());
            json.append(",\"calls\":[");
            boolean firstCall = true;
            for (long[] callee : callees) {
                if (!firstCall) json.append(',');
                firstCall = false;
                json.append('{');
                appendField(json, "entry", String.format("0x%x", callee[0]));
                json.append(',');
                Function tgt = currentProgram.getFunctionManager().getFunctionAt(
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(callee[0]));
                String tgtName = (tgt != null) ? tgt.getName() : "FUN_" + Long.toHexString(callee[0]);
                appendField(json, "name", tgtName);
                json.append('}');
            }
            json.append("]}");
        }

        json.append("],\"strings\":[");
        boolean firstStr = true;
        List<String> strs = collectStrings(2048);
        for (String s : strs) {
            if (!firstStr) json.append(',');
            firstStr = false;
            json.append('"').append(escape(s)).append('"');
        }
        json.append("],\"imports\":[");
        boolean firstImp = true;
        List<String> imports = collectImports();
        for (String imp : imports) {
            if (!firstImp) json.append(',');
            firstImp = false;
            json.append('"').append(escape(imp)).append('"');
        }
        json.append("]}");

        try (PrintWriter pw = new PrintWriter(outFile, "UTF-8")) {
            pw.write(json.toString());
        }
        println("DR-PYARM-BCC-LIFT: wrote " + outFile.getAbsolutePath() + " (" + json.length() + " bytes)");
    }

    private List<long[]> collectCallees(Function fn) {
        List<long[]> out = new ArrayList<>();
        Set<Long> seen = new HashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction ins = it.next();
            Reference[] refs = ins.getReferencesFrom();
            for (Reference r : refs) {
                RefType t = r.getReferenceType();
                if (t.isCall()) {
                    long va = r.getToAddress().getOffset();
                    if (seen.add(va)) {
                        out.add(new long[] { va });
                    }
                }
            }
        }
        return out;
    }

    private List<String> collectStrings(int cap) {
        List<String> out = new ArrayList<>(cap);
        Iterator<Data> dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext() && out.size() < cap) {
            if (monitor.isCancelled()) break;
            Data d = dit.next();
            if (d == null) continue;
            String s = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (s != null && !s.isEmpty() && s.length() >= 4) {
                out.add(s);
            }
        }
        return out;
    }

    private List<String> collectImports() {
        List<String> out = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator sit = st.getExternalSymbols();
        while (sit.hasNext()) {
            if (monitor.isCancelled()) break;
            ghidra.program.model.symbol.Symbol sym = sit.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION || sym.getSymbolType() == SymbolType.LABEL) {
                out.add(sym.getName());
            }
        }
        return out;
    }

    private static void appendField(StringBuilder sb, String k, String v) {
        sb.append('"').append(escape(k)).append("\":\"").append(escape(v)).append('"');
    }

    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
