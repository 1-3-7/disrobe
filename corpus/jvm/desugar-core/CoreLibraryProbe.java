package fixtures.desugar;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collection;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class CoreLibraryProbe {
    private CoreLibraryProbe() {
    }

    public static Duration duration(long minutes) {
        return Duration.ofMinutes(minutes);
    }

    public static long seconds(long minutes) {
        return TimeUnit.SECONDS.convert(duration(minutes));
    }

    public static IntStream range(int start, int end) {
        return IntStream.range(start, end);
    }

    public static Function<String, String> identity() {
        return Function.identity();
    }

    public static Optional<String> optional(String value) {
        return Optional.of(value);
    }

    public static Stream<String> collection(Collection<String> values) {
        return values.stream();
    }

    public static boolean exists(Path path, LinkOption[] options) {
        return Files.exists(path, options);
    }

    public static void main(String[] args) {
        System.out.print(args.length);
    }
}
