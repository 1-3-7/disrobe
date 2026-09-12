# BEAM stripped Core Erlang recompile-execution differential

- id: `beam-erlang-recompile`
- ecosystem: beam
- claim: On 19 of 19 committed Erlang modules, disrobe's stripped-Dbgi Core Erlang lift emits source that recompiles with the original exports and returns the same test/0 result under Erlang/OTP 27.3.4.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: real erlc and erl from Erlang/OTP 27.3.4: compile the original source, strip Dbgi and Docs, recover through disrobe's Core Erlang path, recompile, compare exports, then compare test/0 exit status and stdout
- reproduce: `DISROBE_REQUIRE_ERLANG=1 cargo test -p disrobe-pass-beam --test erlc_recompile_equivalence -- --nocapture`
- floor: 94.74 (holds)
- gate source: crates/disrobe-pass-beam/tests/erlc_recompile_equivalence.rs pins the 19 module names and enforces 19 equivalent results. It compares recovered exports against the original BEAM and executes both versions with erl. A separate regression changes the recovered test/0 result and requires the comparison to reject it. The Linux gate checks releases/<major>/OTP_VERSION against the provisioned 27.3.4.15 and requires the measured counts to equal this bar.
- note: The claim is scoped to the committed test/0 observation in each module. It does not establish equivalence for every input to every export. CI provisions OTP 27.3.4.15, reads releases/<major>/OTP_VERSION to reject any other full version, and makes Erlang mandatory on the Linux test leg; macOS and Windows retain explicit optional reporting rather than weakening the Linux gate. The 19 module names are pinned in the test, raw and stripped exports must agree, recompiled exports are compared to the raw original, and the live Linux measurement must equal the raw numerator and denominator published in recovery.json.
