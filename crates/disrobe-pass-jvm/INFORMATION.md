| section | line | summary |
|---------|-----:|---------|
| references | 12 | clean-room study sources + licenses |
| decompiler-algorithms | 22 | what each ported structuring/lifting step does |
| metrics | 40 | how recovery is measured (non-circular oracles) |
| gotchas | 50 | non-obvious behaviors and the info-theoretic ceiling |

## references

Clean-room studied (algorithm/approach only; no source copied or paraphrased):

- Vineflower (github.com/Vineflower/vineflower) — Apache-2.0. Control-flow structuring, string-concat indy folding.
- CFR (github.com/leibnitz27/cfr) — MIT. `BadCompareRewriter` cmp-fusion approach (`Op02WithProcessedDataAndRefs`), comparison lowering.
- Procyon (github.com/mstrobel/procyon) — Apache-2.0. General region-based structuring reference.
- enjarify / dex2jar (Apache-2.0) — register->stack lowering with empty-stack-at-boundaries invariant; `new-instance`/`<init>` fusion to keep the uninitialized ref on the stack (never in a local); const-0-as-null disambiguation.

## decompiler-algorithms

- cmp-fusion (decompile.rs `Expr::Cmp`, `unary_or_cmp_cond`): `lcmp`/`fcmpl`/`fcmpg`/`dcmpl`/`dcmpg` push a 3-way result; a following unary conditional (`iflt`/`ifge`/...) against implicit 0 collapses to the binary relational `a < b`. CFR approach, reimplemented original.
- string-concat indy (decompile.rs `invoke_dynamic`, `fold_string_concat`): resolves `StringConcatFactory.makeConcatWithConstants`/`makeConcat` invokedynamic; walks the bootstrap recipe (`` = dynamic arg, `` = constant) substituting stack args, yields `"x=" + a`. Vineflower approach.
- lambda metafactory (decompile.rs `invoke_dynamic`): `LambdaMetafactory.metafactory` bootstrap arg[1] is the impl `MethodHandle`; renders a readable target reference.
- local declarations (decompile.rs `local_declarations`): hoists `Type varN;` per written non-parameter slot, type inferred from the store-opcode family. Required because javac discards names; only the verifier slot type survives.
- string escaping (bytecode.rs `escape_java_string`): renders CP UTF-8 as a valid Java literal (`\\`, `\"`, `\n`/`\r`/`\t`/`\b`/`\f`, `\uXXXX` for control/non-printable).
- nested-class rendering (descriptor.rs `nested_separator_to_dot`): `$`→`.` for named inner classes, keeps `$` for anonymous (all-digit) segments; array descriptors (`[I`) render via `parse_field`.
- dex2jar constructor fusion (dalvik_to_jvm.rs `new_instance`/`emit_constructor`): defers `new-instance vDest` (records `pending_new`), then at the matching `invoke-direct {vDest,...} <init>` emits `new; dup; <args>; invokespecial; astore vDest`. The uninitialized ref stays on the stack so the strict verifier accepts it with no stack-map frame. `emit_load` of a still-pending register bails; leftover pending allocations bail.
- const-0-as-null (dalvik_to_jvm.rs `const_zero`/`emit_ref_arg`): a register written by `const v,0` and later consumed as a reference argument emits `aconst_null` instead of `aload` of an int slot.

## metrics

- `tests/decompile_recompile_rate.rs`: per-method clean-recovery fraction = methods whose decompiled fragment carries zero invalidity marker (`goto L`, `?;`, `(stack reset)`, `/*cmp*/`, `/*invokedynamic*/`, ...). Non-circular: markers come only from the renderer's own honest fallbacks.
- `tests/dex2jar_real_bodies.rs`: dex2jar bodies_recovered / method_total + JVM `-Xverify:all` verifier pass-rate (independent `javac` baseline).

## gotchas

- EdgeCases.java is a Java 25 LTS torture fixture (records, sealed, pattern-match switch, virtual threads, FFM, anonymous classes, lambda capture). Full bulk recompilation is NOT the bar; per-method recovery is.
- `?;` residuals remain on pattern-match `switch` (MatchException desugaring) and multidimensional-array (`multianewarray`) initializers — these need ternary/  array-literal reconstruction and lambda body lifting (separate synthetic methods), the genuine info-theoretic edge.
