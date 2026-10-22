public final class EnumBodies {
    public enum Op {
        ADD("+") {
            @Override
            public int apply(int a, int b) {
                return a + b;
            }
        },
        SUB("-") {
            @Override
            public int apply(int a, int b) {
                return a - b;
            }
        },
        MUL("*") {
            @Override
            public int apply(int a, int b) {
                return a * b;
            }

            @Override
            public String symbol() {
                return "x";
            }
        };

        private final String sign;

        Op(String sign) {
            this.sign = sign;
        }

        public abstract int apply(int a, int b);

        public String symbol() {
            return sign;
        }
    }

    public enum Mode {
        FAST {
            @Override
            public String tag() {
                return "f";
            }
        },
        SLOW;

        public String tag() {
            return "s" + ordinal();
        }
    }

    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (Op op : Op.values()) {
            out.append(op.name()).append(op.symbol()).append(op.apply(7, 3)).append(';');
        }
        for (Mode mode : Mode.values()) {
            out.append(mode.tag()).append(';');
        }
        out.append(Op.valueOf("SUB").ordinal());
        System.out.println(out);
    }
}
