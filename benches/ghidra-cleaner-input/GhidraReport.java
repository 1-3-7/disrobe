import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

public class GhidraReport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "ghidra-report.json";

        Listing listing = currentProgram.getListing();

        long functionCount = 0;
        long thunkCount = 0;
        FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f : fns) {
            if (f.isExternal()) {
                continue;
            }
            if (f.isThunk()) {
                thunkCount++;
                continue;
            }
            functionCount++;
        }

        long instructionCount = 0;
        long instructionBytes = 0;
        InstructionIterator insns = listing.getInstructions(true);
        while (insns.hasNext()) {
            Instruction ins = insns.next();
            instructionCount++;
            instructionBytes += ins.getLength();
        }

        long definedStrings = 0;
        long definedDataBytes = 0;
        DataIterator data = listing.getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            definedDataBytes += d.getLength();
            if (d.hasStringValue()) {
                definedStrings++;
            }
        }

        long execBlockBytes = 0;
        long totalBlockBytes = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            totalBlockBytes += b.getSize();
            if (b.isExecute()) {
                execBlockBytes += b.getSize();
            }
        }

        long undefinedInExec = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute() || !b.isInitialized()) {
                continue;
            }
            Address addr = b.getStart();
            Address end = b.getEnd();
            while (addr != null && addr.compareTo(end) <= 0) {
                CodeUnit cu = listing.getCodeUnitContaining(addr);
                if (cu == null) {
                    undefinedInExec++;
                    Address next = addr.next();
                    if (next == null) {
                        break;
                    }
                    addr = next;
                    continue;
                }
                if (cu instanceof Data && !((Data) cu).isDefined()) {
                    undefinedInExec++;
                }
                Address cuEnd = cu.getMaxAddress();
                Address next = cuEnd.next();
                if (next == null) {
                    break;
                }
                addr = next;
            }
        }

        long definedBytes = instructionBytes + definedDataBytes;

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
            pw.println("  \"instruction_bytes\": " + instructionBytes + ",");
            pw.println("  \"defined_data_bytes\": " + definedDataBytes + ",");
            pw.println("  \"defined_bytes\": " + definedBytes + ",");
            pw.println("  \"defined_strings\": " + definedStrings + ",");
            pw.println("  \"undefined_in_exec\": " + undefinedInExec + ",");
            pw.println("  \"executable_block_bytes\": " + execBlockBytes + ",");
            pw.println("  \"total_block_bytes\": " + totalBlockBytes);
            pw.println("}");
        } finally {
            pw.close();
        }
        println("GhidraReport wrote " + outPath);
    }

    private static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
