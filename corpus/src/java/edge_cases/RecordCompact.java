public final class RecordCompact {
    public record Point(double x, double y) {
        public Point {
            if (Double.isNaN(x) || Double.isNaN(y)) {
                throw new IllegalArgumentException("NaN coordinate");
            }
        }
        public static Point origin() {
            return new Point(0.0, 0.0);
        }
        public double distanceTo(Point other) {
            double dx = x - other.x;
            double dy = y - other.y;
            return Math.sqrt(dx * dx + dy * dy);
        }
    }

    public static void main(String[] args) {
        Point a = new Point(3, 4);
        Point b = Point.origin();
        System.out.println(a.distanceTo(b));
    }
}
