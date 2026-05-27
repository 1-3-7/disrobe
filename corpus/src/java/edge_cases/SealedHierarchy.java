public final class SealedHierarchy {
    public sealed interface Shape permits Circle, Square, Triangle {}
    public record Circle(double radius) implements Shape {}
    public record Square(double side) implements Shape {}
    public record Triangle(double base, double height) implements Shape {}

    public static double area(Shape s) {
        return switch (s) {
            case Circle c -> Math.PI * c.radius() * c.radius();
            case Square sq -> sq.side() * sq.side();
            case Triangle t -> 0.5 * t.base() * t.height();
        };
    }

    public static void main(String[] args) {
        System.out.println(area(new Circle(2.0)));
        System.out.println(area(new Square(3.0)));
        System.out.println(area(new Triangle(4.0, 5.0)));
    }
}
