# Java edge-case playground

Java 21 sources exercising sealed hierarchies, records, switch-pattern matching, text blocks, generics variance, nested classes, runtime annotations, and module descriptors. They feed any future Java/JVM-bytecode pass.

## Coverage

| file | category | preview/standard | what it exercises |
|------|----------|------------------|-------------------|
| `LambdaCapture.java` | lambda | standard | lambda capturing effectively-final outer local + method reference. |
| `SealedHierarchy.java` | sealed | standard | `sealed interface ... permits` + exhaustive pattern `switch`. |
| `RecordCompact.java` | record | standard | record with compact constructor validation + static factory + instance method. |
| `SwitchPattern.java` | pattern | standard | record deconstruction patterns in `switch` + guarded `when` arms. |
| `TextBlock.java` | literal | standard | multi-line text blocks with stripped incidental whitespace. |
| `VarInference.java` | inference | standard | `var` local-type inference across complex generic types. |
| `WildcardVariance.java` | generics | standard | `? extends T` producer + `? super T` consumer (PECS). |
| `NestedClasses.java` | class | standard | inner class + local class inside method + anonymous class. |
| `RuntimeAnnotation.java` | annotation | standard | `RetentionPolicy.RUNTIME` annotation with default + reflective read. |
| `module-info.java` | module | standard | JPMS module descriptor with `requires`, `exports ... to`, `opens`, `uses`. |
| `GenericBound.java` | generics | standard | bounded type parameter `<T extends Comparable<T>>` + comparator wildcard. |

## Validation

In this workspace `javac` is NOT on PATH. To validate locally (Java 21+):

```powershell
javac -d out --enable-preview --release 21 LambdaCapture.java SealedHierarchy.java RecordCompact.java SwitchPattern.java TextBlock.java VarInference.java WildcardVariance.java NestedClasses.java RuntimeAnnotation.java GenericBound.java
```

The `module-info.java` file must be compiled with appropriate module path settings; it stands as a syntactic specimen.
