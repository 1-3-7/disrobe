# .NET CIL decompilation, whole-type recompile over the EdgeCases corpus

- id: `dotnet-whole-type-recompile`
- ecosystem: dotnet
- claim: disrobe decompiles .NET CIL method bodies to C# that recompile error-free under the real csc inside type declarations the test harness derives from metadata, across the EdgeCases corpus.
- measured: 82.86%
- oracle strength: recompile-only
- CI-attested: yes [CI]
- evidence basis: real csc (dotnet SDK 9.0.318): recovered method bodies, wrapped in type and field declarations the harness builds from metadata, must recompile as one single-file compilation unit per type
- reproduce: `cargo test -p disrobe-pass-dotnet --test it whole_type_il_equivalence_oracle::edgecases_whole_type_recompile_fraction_is_published_as_measured -- --nocapture`
- floor: 82.86 (holds)
- gate source: crates/disrobe-pass-dotnet/tests/whole_type_il_equivalence_oracle.rs (EDGECASES_RECOMPILE_MEMBERS pins the 29 names against EDGECASES_TYPES's 35 members; edgecases_whole_type_recompile_fraction_is_published_as_measured fails if any named member stops recompiling without a stated refusal; standalone_dependency_host_uses_recovered_assembly_declarations requires the metadata-derived dependency host to compile and its changed-reference mutation to fail); measured locally with dotnet SDK 9.0.318 (Roslyn csc bundled with that SDK, MSBuild 17.14.51.32402) via `cargo test -p disrobe-pass-dotnet --test it whole_type_il_equivalence_oracle::edgecases_whole_type_recompile_fraction_is_published_as_measured -- --nocapture`; CI asserts only the named-member floor, not the percentage, so re-measure locally before quoting a moved figure
- note: Oracle strength is recompile-only: the recovered source compiling proves it is legal C#, not that it means what the original IL meant. Named same-assembly dependencies use metadata-derived recovered declarations, with no reference to the original assembly; a changed-reference mutation must fail. Each type remains a standalone compilation unit when the compiler invocations are batched. A member that states a refusal does not count as recovered even when the type compiles. Measured locally; CI asserts the 29 named members in EDGECASES_RECOMPILE_MEMBERS, not the percentage.
