package fixtures.desugar;

import java.time.Instant;
import java.util.Date;

public final class DateRetargetProbe {
    private DateRetargetProbe() {
    }

    public static Date fromInstant(Instant instant) {
        return Date.from(instant);
    }

    public static Instant toInstant(Date date) {
        return date.toInstant();
    }
}
