# Native taint analysis on Juliet CWE-78

- id: `taint-juliet-cwe78`
- ecosystem: taint
- claim: Disrobe detects 93 of 190 labeled command-injection flows in the NIST SARD Juliet v1.3 char/system C corpus with gcc 16.2.0 -O2, with zero false positives.
- measured: 48.90%
- oracle strength: strong
- CI-attested: no [local]
- evidence basis: NIST SARD Juliet Test Suite for C/C++ v1.3 (2017-10-01), CWE-78 char/system C files. The grader reads manifest.xml flaw locations and Flow Variant headers. Each group contributes one verdict for its bad-labeled call chain and one for its good-labeled chain.
- reproduce: `DISROBE_REQUIRE_JULIET_CORPUS=1 cargo test -p disrobe-taint --test graded_corpus juliet_cwe78_command_injection_precision_recall_o2 -- --exact --nocapture. CI does not provision the pinned Juliet corpus cache.`
- floor: 48.90 (holds)
- gate source: crates/disrobe-taint/tests/graded_corpus.rs, assert_fresh_o2_grade_still_clears_the_published_floor, sum over the 8 populated categories; ground truth is manifest.xml and each file's own Flow Variant header
- note: These figures cover native input compiled from C. Seven of the 15 declared flow categories have no cases in this slice: container, callback, virtual call, string operation, sanitiser, recursion, and library boundary. With gcc 16.2.0 -O0, detection is 12 of 190 flows (6.3%), with zero false positives. Flow across more than one call remains 0 of 15 at both optimization levels. The separate published_juliet_o2_bars_match_the_pinned_floors test checks the published counts without compiling the corpus.
