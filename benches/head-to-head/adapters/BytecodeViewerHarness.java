import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.util.Enumeration;
import java.util.HashMap;
import org.benf.cfr.reader.util.getopt.Options;
import org.benf.cfr.reader.util.getopt.OptionsImpl;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import the.bytecode.club.bytecodeviewer.BytecodeViewer;
import the.bytecode.club.bytecodeviewer.decompilers.impl.CFRDecompiler;
import the.bytecode.club.bytecodeviewer.resources.ResourceContainer;

public final class BytecodeViewerHarness {
    static final class HeadlessCfr extends CFRDecompiler {
        @Override public Options generateOptions() {
            return new OptionsImpl(new HashMap<String, String>());
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("jar output");
        Path jar = Path.of(args[0]);
        Path output = Path.of(args[1]);
        if (Files.size(jar) > 64L * 1024 * 1024) throw new IllegalArgumentException("JAR byte limit");
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            if (zip.size() > 4096) throw new IllegalArgumentException("JAR entry limit");
            ResourceContainer container = new ResourceContainer(jar.toFile());
            Enumeration<? extends ZipEntry> entries = zip.entries();
            long total = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                long size = entry.getSize();
                if (size < 0 || size > 32L * 1024 * 1024) throw new IllegalArgumentException("class byte limit");
                total = Math.addExact(total, size);
                if (total > 64L * 1024 * 1024) throw new IllegalArgumentException("aggregate class byte limit");
                byte[] bytes;
                try (InputStream input = zip.getInputStream(entry)) {
                    bytes = input.readNBytes(Math.toIntExact(size) + 1);
                }
                if (bytes.length != size) throw new IllegalArgumentException("class length mismatch");
                ClassNode node = new ClassNode();
                new ClassReader(bytes).accept(node, 0);
                if (container.resourceClassBytes.putIfAbsent(entry.getName(), bytes) != null
                    || container.resourceClasses.putIfAbsent(node.name, node) != null)
                    throw new IllegalArgumentException("duplicate class");
            }
            BytecodeViewer.resourceContainers.put(container.name, container);
            byte[] bytes = container.resourceClassBytes.get("EdgeCases.class");
            ClassNode node = container.resourceClasses.get("EdgeCases");
            if (bytes == null || node == null) throw new IllegalStateException("EdgeCases missing");
            String source = new HeadlessCfr().decompileClassNode(node, bytes);
            if (source.length() > 16 * 1024 * 1024) throw new IllegalArgumentException("source byte limit");
            Files.writeString(output, source, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE);
        }
    }
}
