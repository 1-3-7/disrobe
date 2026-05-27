# TypeScript edge-case playground

TypeScript 5.x sources exercising the type-system edges and modern decorator syntax. They feed `disrobe-pass-js-deob` once minified/bundled and serve as a baseline for any future TS-aware passes.

## Coverage

| file | category | pass crate(s) | what it exercises |
|------|----------|---------------|-------------------|
| `conditional_distributive.ts` | type-system | js-deob | conditional types, distributive over unions, `infer`, `NonNullable` re-implementation. |
| `mapped_as_rename.ts` | type-system | js-deob | `as`-rename mapped types, template-literal key transforms. |
| `recursive_type.ts` | type-system | js-deob | self-referential `LinkedList`, `Tree`, `JsonValue` with array index. |
| `variadic_tuple.ts` | type-system | js-deob | variadic tuple `Push`/`Concat`/`Drop1` + rest element. |
| `template_literal_types.ts` | type-system | js-deob | template-literal types, `Route` union, recursive `Snake` casing. |
| `infer_conditional.ts` | type-system | js-deob | `infer` in conditional, deep `Promise` unwrapping. |
| `abstract_members.ts` | class | js-deob | abstract class, abstract members, abstract constructor type. |
| `enums_computed.ts` | enum | js-deob | const enum + numeric flag enum + string enum + computed initializers. |
| `module_augmentation.ts` | module | js-deob | `declare global` augmentation of `Array`/`String` prototypes. |
| `triple_slash.ts` | directive | js-deob | `/// <reference />` directives for lib + no-default-lib. |
| `import_type.ts` | import | js-deob | `import type` + inline `type` modifier on named imports. |
| `satisfies_operator.ts` | type-system | js-deob | `satisfies` operator preserving narrow literal types. |
| `branded_type.ts` | type-system | js-deob | nominal `Brand<T, B>` via intersection with `unique symbol` phantom. |
| `hkt_simulation.ts` | type-system | js-deob | higher-kinded simulation via class-mixin factories. |
| `discriminated_unions.ts` | type-system | js-deob | discriminated union with exhaustive `switch` + `never` exhaustiveness check. |
| `unique_symbol.ts` | type-system | js-deob | `unique symbol` declaration + symbol-key indexing. |
| `decorator_metadata.ts` | decorator | js-deob | stage-3 decorators on class, accessor, method via `addInitializer`. |
| `using_declarations.ts` | resource | js-deob | `using` + `await using` explicit resource management. |
| `erasable_syntax.ts` | type-system | js-deob | erasable-syntax-mode friendly module (no runtime type emit). |
| `const_type_params.ts` | type-system | js-deob | `<const T>` type parameters preserving literal narrowness. |
| `overload_signatures.ts` | overload | js-deob | function overload signatures + builder interface overload. |

## Validation

```powershell
tsc --noEmit --target ES2022 --module ES2022 --moduleResolution Bundler --skipLibCheck --strict false *.ts
```

Files are intentionally tolerant of `strict: false` flag for portability across `tsconfig.json` variants. Three files (`decorator_metadata.ts`, `using_declarations.ts`, `import_type.ts`) require TypeScript 5.2+; `const_type_params.ts` requires 5.0+.
