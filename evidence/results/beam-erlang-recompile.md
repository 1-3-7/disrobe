# BEAM stripped Core Erlang recompile-execution differential

- id: `beam-erlang-recompile`
- ecosystem: beam
- claim: On 18 of 19 committed Erlang modules, disrobe's stripped-Dbgi Core Erlang lift emits source that recompiles with the original exports and returns the same test/0 result under Erlang/OTP 27.3.4.
- measured: 94.74%
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: real erlc and erl from Erlang/OTP 27.3.4: compile the original source, strip Dbgi and Docs, recover through disrobe's Core Erlang path, recompile, compare exports, then compare test/0 exit status and stdout
- reproduce: `DISROBE_REQUIRE_ERLANG=1 cargo test -p disrobe-pass-beam --test erlc_recompile_equivalence -- --nocapture`
- floor: 94.74 (holds)
- gate source: crates/disrobe-pass-beam/tests/erlc_recompile_equivalence.rs pins the 19 module names, requires the live measured equivalent and population counts to equal this bar's raw 18 and 19, parses the raw original BEAM before stripping, proves stripped and raw exports agree, compares recompiled exports to that raw set, and compares test/0 exit status and stdout under real erl; real_erlang_runtime_rejects_a_recompiled_wrong_test_result injects a recovered test/0 that still recompiles with matching exports and requires the runtime differential to reject it; the shared Erlang helper and the Linux provisioning check in .github/workflows/ci.yml read releases/<major>/OTP_VERSION and reject any value other than 27.3.4 before DISROBE_REQUIRE_ERLANG=1 makes absence fatal
- note: The claim is scoped to the committed test/0 observation in each module. It does not establish equivalence for every input to every export. CI provisions OTP 27.3.4, reads releases/<major>/OTP_VERSION to reject any other full version, and makes Erlang mandatory on the Linux test leg; macOS and Windows retain explicit optional reporting rather than weakening the Linux gate. The 19 module names are pinned in the test, raw and stripped exports must agree, recompiled exports are compared to the raw original, and the live Linux measurement must equal the raw numerator and denominator published in recovery.json.
