import ghidra.app.script.GhidraScript;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DisrobeAnalyzer extends GhidraScript {

    private static final String BINARY = "disrobe";

    @Override
    public void run() throws Exception {
        String path = currentProgram.getExecutablePath();
        if (path == null || path.isEmpty()) {
            printerr("disrobe: no executable path available from currentProgram");
            return;
        }

        String[] choices = {
            "Auto: run full deobfuscation pipeline",
            "Detect: identify obfuscator / packer",
            "Strings: extract and deobfuscate strings",
            "IOC: extract indicators of compromise",
            "Behavior: summarize binary capabilities (MITRE)",
            "Identify: compiler / packer / protector fingerprint",
            "Scan: leak credentials scanner"
        };

        String chosen = askChoice("disrobe", "Select action:", choices, choices[0]);
        if (chosen == null) {
            return;
        }

        if (chosen.equals(choices[0])) { runAutoRunFullDeobfuscationPipeline(); return; }
        if (chosen.equals(choices[1])) { runDetectIdentifyObfuscatorPacker(); return; }
        if (chosen.equals(choices[2])) { runStringsExtractAndDeobfuscateStrings(); return; }
        if (chosen.equals(choices[3])) { runIOCExtractIndicatorsOfCompromise(); return; }
        if (chosen.equals(choices[4])) { runBehaviorSummarizeBinaryCapabilitiesMITRE(); return; }
        if (chosen.equals(choices[5])) { runIdentifyCompilerPackerProtectorFingerprint(); return; }
        if (chosen.equals(choices[6])) { runScanLeakCredentialsScanner(); return; }
    }

    private void runDisrobe(String subcommand) throws Exception {
        String path = currentProgram.getExecutablePath();
        List<String> cmd = new ArrayList<>();
        cmd.add(BINARY);
        cmd.add(subcommand);
        cmd.add(path);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }

        int exit = proc.waitFor();
        println("[disrobe] $ " + String.join(" ", cmd));
        println(sb.toString());
        if (exit != 0) {
            printerr("disrobe " + subcommand + " exited " + exit);
        }
    }

    private void runAutoRunFullDeobfuscationPipeline() throws Exception {
        runDisrobe("auto");
    }

    private void runDetectIdentifyObfuscatorPacker() throws Exception {
        runDisrobe("detect");
    }

    private void runStringsExtractAndDeobfuscateStrings() throws Exception {
        runDisrobe("strings");
    }

    private void runIOCExtractIndicatorsOfCompromise() throws Exception {
        runDisrobe("ioc");
    }

    private void runBehaviorSummarizeBinaryCapabilitiesMITRE() throws Exception {
        runDisrobe("behavior");
    }

    private void runIdentifyCompilerPackerProtectorFingerprint() throws Exception {
        runDisrobe("identify");
    }

    private void runScanLeakCredentialsScanner() throws Exception {
        runDisrobe("scan");
    }

    // Supported ecosystems (derived from disrobe catalog):
    // Python pyc
    // PyArmor
    // PyInstaller
    // Nuitka
    // Python pickle
    // JavaScript
    // WebAssembly
    // .NET / CIL
    // JVM classfile
    // Android DEX
    // Go
    // Lua
    // PHP
    // Ruby YARV
    // BEAM
    // Swift / Obj-C
    // ActionScript 3
    // Hermes
    // Flutter
    // Shell / PowerShell
    // Native PE/ELF/Mach-O
    // Nim / Zig / Crystal
    // Containers
}
