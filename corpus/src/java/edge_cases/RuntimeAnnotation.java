import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

public final class RuntimeAnnotation {
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.METHOD, ElementType.TYPE })
    public @interface Marked {
        String value() default "default-mark";
        int priority() default 0;
    }

    @Marked(value = "primary", priority = 5)
    public void doWork() {}

    @Marked
    public void doOther() {}

    public static void main(String[] args) throws Exception {
        for (Method m : RuntimeAnnotation.class.getDeclaredMethods()) {
            Marked marked = m.getAnnotation(Marked.class);
            if (marked != null) {
                System.out.println(m.getName() + " -> " + marked.value() + "/" + marked.priority());
            }
        }
    }
}
