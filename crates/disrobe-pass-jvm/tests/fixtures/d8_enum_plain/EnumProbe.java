public final class EnumProbe {
    public enum Level {
        LOW(1, "low"),
        MEDIUM(5, "medium"),
        HIGH(9, "high");

        private final int weight;
        private final String label;

        Level(int weight, String label) {
            this.weight = weight;
            this.label = label;
        }

        public int weight() {
            return weight;
        }

        public String label() {
            return label;
        }

        public Level next() {
            Level[] all = values();
            return all[(ordinal() + 1) % all.length];
        }
    }

    public enum Flag {
        OFF,
        ON
    }

    static String describe(Level level) {
        switch (level) {
            case LOW:
                return "l:" + level.weight();
            case MEDIUM:
                return "m:" + level.weight();
            default:
                return "h:" + level.weight();
        }
    }

    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (Level level : Level.values()) {
            out.append(level.name()).append('=').append(level.label()).append('/')
                .append(describe(level)).append('/').append(level.next().name()).append(';');
        }
        out.append(Level.valueOf("MEDIUM").ordinal()).append(';');
        out.append(Flag.ON.compareTo(Flag.OFF)).append(';');
        out.append(Flag.valueOf("OFF").name());
        System.out.println(out);
    }
}
