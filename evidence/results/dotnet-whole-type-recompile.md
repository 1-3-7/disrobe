# .NET CIL decompilation, whole-type recompile over the EdgeCases corpus

- id: `dotnet-whole-type-recompile`
- ecosystem: dotnet
- claim: disrobe decompiles a .NET CIL type to C# that recompiles error-free standalone under the real csc, across the EdgeCases corpus.
- measured: 51.43%
- oracle strength: recompile-only
- CI-attested: yes [CI]
- evidence basis: real csc (dotnet SDK 9.0.316): recovered C# must recompile standalone as its own single-file compilation unit
- reproduce: `cargo test -p disrobe-pass-dotnet --test whole_type_il_equivalence_oracle edgecases_whole_type_recompile_fraction_is_published_as_measured -- --nocapture`
- floor: 51.43 (holds)
- gate source: crates/disrobe-pass-dotnet/tests/whole_type_il_equivalence_oracle.rs (EDGECASES_RECOMPILE_MEMBERS pins the 18 names against EDGECASES_TYPES's 35 members; edgecases_whole_type_recompile_fraction_is_published_as_measured fails if any named member stops recompiling without a stated refusal); measured locally with dotnet SDK 9.0.316 (Roslyn csc bundled with that SDK, MSBuild 17.14.43.7001) via `cargo test -p disrobe-pass-dotnet --test whole_type_il_equivalence_oracle edgecases_whole_type_recompile_fraction_is_published_as_measured -- --nocapture`; CI asserts only the named-member floor, not the percentage, so re-measure locally before quoting a moved figure
- note: Oracle strength is recompile-only: the recovered source compiling proves it is legal C#, not that it means what the original IL meant. A member that states a refusal (an unreconstructed state machine or an unlowered compiler-generated construct) does not count as recovered even when the type compiles. Measured locally; CI does not assert the percentage, only that the named members in EDGECASES_RECOMPILE_MEMBERS keep recompiling.
