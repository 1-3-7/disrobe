import ghidra.app.script.GhidraScript;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class DisrobeAnalyzer extends GhidraScript {

    private static final String BINARY = "disrobe";
    private static final int OUTPUT_LIMIT_BYTES = 1024 * 1024;
    private static final long TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(120);
    private static final long POLL_MILLIS = 100;
    private static final long TERMINATION_GRACE_NANOS = TimeUnit.SECONDS.toNanos(2);
    private static final List<String> CHOICES = List.of(
            "Auto: run full deobfuscation pipeline",
            "Detect: identify obfuscator / packer",
            "Strings: extract and deobfuscate strings",
            "IOC: extract indicators of compromise",
            "Behavior: summarize binary capabilities (MITRE)",
            "Identify: compiler / packer / protector fingerprint",
            "Scan: leak credentials scanner"
    );
    private static final List<String> SUBCOMMANDS = List.of(
            "auto",
            "detect",
            "strings",
            "ioc",
            "behavior",
            "identify",
            "scan"
    );

    @Override
    public void run() throws Exception {
        String path = currentProgram.getExecutablePath();
        if (path == null || path.isEmpty()) {
            printerr("disrobe: no executable path available from currentProgram");
            return;
        }
        if (File.separatorChar == '\\' && path.length() >= 3 && path.charAt(0) == '/'
            && Character.isLetter(path.charAt(1)) && path.charAt(2) == ':') {
            path = path.substring(1);
        }

        String subcommand;
        if (isRunningHeadless()) {
            String[] args = getScriptArgs();
            if (args.length != 1 || !SUBCOMMANDS.contains(args[0])) {
                throw new IllegalArgumentException(
                    "headless usage: DisrobeAnalyzer.java <" + String.join("|", SUBCOMMANDS) + ">"
                );
            }
            subcommand = args[0];
        }
        else {
            String chosen = askChoice("disrobe", "Select action:", CHOICES, CHOICES.get(0));
            if (chosen == null) {
                return;
            }
            int selected = CHOICES.indexOf(chosen);
            if (selected < 0) {
                throw new IllegalStateException("Ghidra returned an unknown disrobe action");
            }
            subcommand = SUBCOMMANDS.get(selected);
        }
        runDisrobe(subcommand, path);
    }

    private void runDisrobe(String subcommand, String path) throws Exception {
        List<String> cmd = List.of(BINARY, subcommand, path);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        OutputCapture output = new OutputCapture();
        Thread reader = new Thread(
            () -> drainOutput(proc.getInputStream(), output),
            "disrobe-output"
        );
        reader.setDaemon(true);
        reader.start();
        Set<ProcessHandle> descendants = new LinkedHashSet<>();
        long deadline = System.nanoTime() + TIMEOUT_NANOS;
        boolean timedOut = false;
        boolean completed = false;
        try {
            while (true) {
                proc.descendants().forEach(descendants::add);
                completed = proc.waitFor(POLL_MILLIS, TimeUnit.MILLISECONDS);
                proc.descendants().forEach(descendants::add);
                if (completed) {
                    break;
                }
                monitor.checkCancelled();
                if (System.nanoTime() - deadline >= 0) {
                    timedOut = true;
                    break;
                }
            }
        }
        finally {
            proc.descendants().forEach(descendants::add);
            Exception cleanupFailure = null;
            boolean restoreInterrupt = false;
            try {
                terminateProcessTree(proc, descendants);
            }
            catch (IOException | InterruptedException error) {
                cleanupFailure = error;
                restoreInterrupt = Thread.interrupted() || error instanceof InterruptedException;
            }
            try {
                reader.join(TimeUnit.NANOSECONDS.toMillis(TERMINATION_GRACE_NANOS));
            }
            catch (InterruptedException error) {
                restoreInterrupt = true;
                if (cleanupFailure == null) {
                    cleanupFailure = error;
                }
                else {
                    cleanupFailure.addSuppressed(error);
                }
            }
            if (reader.isAlive()) {
                try {
                    proc.getInputStream().close();
                }
                catch (IOException error) {
                    if (cleanupFailure == null) {
                        cleanupFailure = error;
                    }
                    else {
                        cleanupFailure.addSuppressed(error);
                    }
                }
                try {
                    reader.join(TimeUnit.NANOSECONDS.toMillis(TERMINATION_GRACE_NANOS));
                }
                catch (InterruptedException error) {
                    restoreInterrupt = true;
                    if (cleanupFailure == null) {
                        cleanupFailure = error;
                    }
                    else {
                        cleanupFailure.addSuppressed(error);
                    }
                }
            }
            if (reader.isAlive()) {
                IOException error = new IOException("disrobe output reader did not stop");
                if (cleanupFailure == null) {
                    cleanupFailure = error;
                }
                else {
                    cleanupFailure.addSuppressed(error);
                }
            }
            if (restoreInterrupt) {
                Thread.currentThread().interrupt();
            }
            if (cleanupFailure != null) {
                throw cleanupFailure;
            }
        }
        String captured = output.text();
        println("[disrobe] $ " + String.join(" ", cmd));
        if (!captured.isEmpty()) {
            println(captured);
        }
        if (output.truncated) {
            printerr("disrobe output truncated at " + OUTPUT_LIMIT_BYTES + " bytes");
        }
        if (timedOut) {
            throw new IOException("disrobe " + subcommand + " exceeded 120 seconds");
        }
        if (output.failure != null) {
            throw output.failure;
        }
        if (!completed) {
            throw new IOException("disrobe process ended without an exit status");
        }
        int exit = proc.exitValue();
        if (exit != 0) {
            throw new IOException("disrobe " + subcommand + " exited " + exit);
        }
    }

    private static void drainOutput(InputStream input, OutputCapture output) {
        byte[] buffer = new byte[8192];
        try (input) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                int remaining = OUTPUT_LIMIT_BYTES - output.bytes.size();
                int retained = Math.min(read, Math.max(remaining, 0));
                output.bytes.write(buffer, 0, retained);
                output.truncated |= retained < read;
            }
        }
        catch (IOException error) {
            output.failure = error;
        }
    }

    private static void terminateProcessTree(Process proc, Set<ProcessHandle> descendants)
        throws IOException, InterruptedException {
        Set<ProcessHandle> processes = new LinkedHashSet<>(descendants);
        processes.add(proc.toHandle());
        IOException completionFailure = null;
        InterruptedException interruption = null;
        for (int phase = 0; phase < 2; phase++) {
            boolean force = phase == 1;
            processes.stream().filter(ProcessHandle::isAlive).forEach(handle -> {
                if (force) {
                    handle.destroyForcibly();
                }
                else {
                    handle.destroy();
                }
            });
            CompletableFuture<?>[] exits = processes.stream()
                .filter(ProcessHandle::isAlive)
                .map(ProcessHandle::onExit)
                .toArray(CompletableFuture<?>[]::new);
            if (exits.length == 0) {
                break;
            }
            try {
                CompletableFuture.allOf(exits).get(
                    TERMINATION_GRACE_NANOS,
                    TimeUnit.NANOSECONDS
                );
                break;
            }
            catch (InterruptedException error) {
                if (interruption == null) {
                    interruption = error;
                }
                else {
                    interruption.addSuppressed(error);
                }
            }
            catch (ExecutionException error) {
                IOException failure = new IOException(
                    "waiting for the disrobe process tree failed",
                    error.getCause()
                );
                if (completionFailure == null) {
                    completionFailure = failure;
                }
                else {
                    completionFailure.addSuppressed(failure);
                }
            }
            catch (TimeoutException error) {
                if (force) {
                    IOException failure = new IOException(
                        "timed out waiting for the forcibly terminated disrobe process tree",
                        error
                    );
                    if (completionFailure == null) {
                        completionFailure = failure;
                    }
                    else {
                        completionFailure.addSuppressed(failure);
                    }
                }
            }
        }
        if (processes.stream().anyMatch(ProcessHandle::isAlive)) {
            IOException failure = new IOException("disrobe process tree did not stop");
            if (completionFailure != null) {
                failure.addSuppressed(completionFailure);
            }
            if (interruption != null) {
                failure.addSuppressed(interruption);
                Thread.currentThread().interrupt();
            }
            throw failure;
        }
        if (completionFailure != null) {
            if (interruption != null) {
                completionFailure.addSuppressed(interruption);
                Thread.currentThread().interrupt();
            }
            throw completionFailure;
        }
        if (interruption != null) {
            Thread.currentThread().interrupt();
            throw interruption;
        }
    }

    private static final class OutputCapture {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private IOException failure;
        private boolean truncated;

        private String text() {
            return bytes.toString(StandardCharsets.UTF_8);
        }
    }
}
