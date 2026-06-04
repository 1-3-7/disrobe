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
- dex2jar / jadx (both Apache-2.0) — forward register type-state propagation over the Dalvik CFG (the same analysis that derives verifier frames); studied for approach, reimplemented original in `dalvik_typestate.rs`.

## decompiler-algorithms

- cmp-fusion (decompile.rs `Expr::Cmp`, `unary_or_cmp_cond`): `lcmp`/`fcmpl`/`fcmpg`/`dcmpl`/`dcmpg` push a 3-way result; a following unary conditional (`iflt`/`ifge`/...) against implicit 0 collapses to the binary relational `a < b`. CFR approach, reimplemented original.
- string-concat indy (decompile.rs `invoke_dynamic`, `fold_string_concat`): resolves `StringConcatFactory.makeConcatWithConstants`/`makeConcat` invokedynamic; walks the bootstrap recipe (`` = dynamic arg, `` = constant) substituting stack args, yields `"x=" + a`. Vineflower approach.
- lambda metafactory (decompile.rs `invoke_dynamic`): `LambdaMetafactory.metafactory` bootstrap arg[1] is the impl `MethodHandle`; renders a readable target reference.
- local declarations (decompile.rs `local_declarations`): hoists `Type varN;` per written non-parameter slot, type inferred from the store-opcode family. Required because javac discards names; only the verifier slot type survives.
- string escaping (bytecode.rs `escape_java_string`): renders CP UTF-8 as a valid Java literal (`\\`, `\"`, `\n`/`\r`/`\t`/`\b`/`\f`, `\uXXXX` for control/non-printable).
- nested-class rendering (descriptor.rs `nested_separator_to_dot`): `$`→`.` for named inner classes, keeps `$` for anonymous (all-digit) segments; array descriptors (`[I`) render via `parse_field`.
- dex2jar constructor fusion (dalvik_to_jvm.rs `new_instance`/`emit_constructor`): defers `new-instance vDest` (records `pending_new`), then at the matching `invoke-direct {vDest,...} <init>` emits `new; dup; <args>; invokespecial; astore vDest`. The uninitialized ref stays on the stack so the strict verifier accepts it with no stack-map frame. `emit_load` of a still-pending register bails; leftover pending allocations bail.
- const-0-as-null (dalvik_to_jvm.rs `const_zero`/`emit_ref_arg`): a register written by `const v,0` and later consumed as a reference argument emits `aconst_null` instead of `aload` of an int slot.
- dex2jar type-state CFG lowering (dalvik_typestate.rs + dalvik_to_jvm.rs `emit_branch_method_code`): forward fixpoint computes, at every basic-block leader, each Dalvik register's verification type (`RegType` lattice: Top/Int/Float/Long/Double/ZeroOrNull/Ref). The SAME per-block-entry state seeds both the register->local lowering (via `block_entry_slots`, reset at each leader) and the synthesized `StackMapTable` frames (`frame_types`), so emission and frames can never drift — the failure mode of an emit-only model. Frames are `full_frame` (locals-only, since the stack is empty at every boundary), emitted only at real JVM branch targets (from `fixups`). Key correctness rules learned empirically against the JVM verifier: (a) a register defined on only SOME predecessor paths merges to `Top` (JVM definite-assignment, `merge_state`); (b) `move-result` types are precomputed linearly, not in the worklist (Dalvik adjacency); (c) `const-wide` is long-vs-double-ambiguous and must be typed by its consumer (`wide_const_doubles`, mirroring the straight-line float/double const inference); (d) methods that branch back to PC 0 bail (offset-0 frame edge case).

## metrics

- `tests/decompile_recompile_rate.rs`: per-method clean-recovery fraction = methods whose decompiled fragment carries zero invalidity marker (`goto L`, `?;`, `(stack reset)`, `/*cmp*/`, `/*invokedynamic*/`, ...). Non-circular: markers come only from the renderer's own honest fallbacks.
- `tests/dex2jar_real_bodies.rs`: dex2jar bodies_recovered / method_total + JVM `-Xverify:all` verifier pass-rate (independent `javac` baseline).
- `tests/dex2jar_body_census.rs` (`report_whole_corpus_body_fidelity`): the non-circular per-method oracle — for every method present in BOTH the dex2jar translation and the independent `EdgeCases-baseline.jar` (real javac output), compares normalized semantic skeletons. Never re-emits through the dex2jar builder. Reports recovered-real-body % and skeleton-match %.

## gotchas

- EdgeCases.java is a Java 25 LTS torture fixture (records, sealed, pattern-match switch, virtual threads, FFM, anonymous classes, lambda capture). Full bulk recompilation is NOT the bar; per-method recovery is.
- `?;` residuals remain on pattern-match `switch` (MatchException desugaring) and multidimensional-array (`multianewarray`) initializers — these need cross-block operand-stack tracking (values that span block boundaries are lost by the per-block stack reset), ternary/array-literal reconstruction, and lambda body lifting (separate synthetic methods), the genuine info-theoretic edge.
- dex2jar BRANCH lowering (SHIPPED via the type-state pass): `if`/`goto` bodies now recover with verifier-clean synthesized `StackMapTable`s. Measured: bodies_recovered 118->142 (31.9->38.4% of all 370 methods), verifier 0 failures / 260 methods verified; the non-circular corpus oracle reads recovered-real-body 103->125 (47.7->57.9% of the 216 comparable methods). The earlier drift ("Inconsistent stackmap frames") was fixed by making the type-state analysis the single source of truth for both emission and frames (not two separate models).
- dex2jar remaining stubbed families (the honest ceiling): `switch` (packed/sparse), `try`/`catch` (needs exception-handler frames with the throwable on the operand stack), `filled-new-array`, registers with genuinely type-conflicting paths (merge to `Top`), and lambda/method-ref synthetic classes (d8 desugaring — `new X; invokespecial` vs javac's `invokedynamic`, a different-but-valid compilation strategy that the skeleton oracle counts as a "mismatch" though both are correct). Switch + try are the next tractable lever (switch needs `tableswitch`/`lookupswitch` emit + frames at each case; try needs handler-frame typing).
- skeleton-match % is a NOISY secondary metric (~45% of recovered): the dominant "mismatch" is d8 lambda desugaring (`new$Lambda; invokespecial`) vs javac `invokedynamic` — semantically equivalent, structurally different. recovered-real-body % + verifier pass-rate are the honest primary metrics.
