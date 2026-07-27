#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::yara::parse_ruleset;
use disrobe_core::yara_match::CompiledRuleset;

type OffsetMap = BTreeMap<String, BTreeMap<String, Vec<u64>>>;

struct Case {
    name: &'static str,
    rules: &'static str,
    sample: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        name: "text_overlapping",
        rules: r#"rule Overlap { strings: $x = "aa" condition: $x }"#,
        sample: b"aaaa baa",
    },
    Case {
        name: "text_multi_and",
        rules: r#"rule Both { strings: $a = "alpha" $b = "omega" condition: $a and $b }"#,
        sample: b"alpha in the middle omega and alpha again",
    },
    Case {
        name: "text_nocase",
        rules: r#"rule NoCase { strings: $x = "malware" nocase condition: $x }"#,
        sample: b"MALWARE malware MalWare clean",
    },
    Case {
        name: "text_wide",
        rules: r#"rule Wide { strings: $x = "user" wide condition: $x }"#,
        sample: b"user u\x00s\x00e\x00r\x00 tail",
    },
    Case {
        name: "text_wide_ascii",
        rules: r#"rule WideAscii { strings: $x = "key" wide ascii condition: $x }"#,
        sample: b"key k\x00e\x00y\x00",
    },
    Case {
        name: "text_fullword",
        rules: r#"rule FullWord { strings: $x = "cat" fullword condition: $x }"#,
        sample: b"cat category the cat.",
    },
    Case {
        name: "hex_fixed",
        rules: r"rule HexFixed { strings: $x = { 4D 5A 90 00 } condition: $x }",
        sample: b"..MZ\x90\x00..MZ\x90\x00",
    },
    Case {
        name: "hex_wildcard",
        rules: r"rule HexWild { strings: $x = { 41 ?? 43 } condition: $x }",
        sample: b"AxC AyC AZZ",
    },
    Case {
        name: "hex_nibble",
        rules: r"rule HexNibble { strings: $x = { 4? 5A } condition: $x }",
        sample: b"\x40\x5a\x4f\x5a\x30\x5a",
    },
    Case {
        name: "hex_jump_range",
        rules: r"rule HexJump { strings: $x = { 41 [1-3] 5A } condition: $x }",
        sample: b"A__Z AwwwwZ",
    },
    Case {
        name: "hex_jump_exact",
        rules: r"rule HexExact { strings: $x = { 41 [2] 5A } condition: $x }",
        sample: b"A__Z A_Z",
    },
    Case {
        name: "hex_alternation",
        rules: r"rule HexAlt { strings: $x = { ( 41 42 | 43 44 ) 45 } condition: $x }",
        sample: b"ABE__CDE__ABX",
    },
    Case {
        name: "regex_simple",
        rules: r"rule Rgx { strings: $x = /ab+c/ condition: $x }",
        sample: b"abc abbbc adc",
    },
    Case {
        name: "regex_overlap",
        rules: r"rule RgxOverlap { strings: $x = /a.a/ condition: $x }",
        sample: b"aaaa",
    },
    Case {
        name: "regex_class",
        rules: r"rule RgxClass { strings: $x = /[0-9]{3}/ condition: $x }",
        sample: b"12 345 6789",
    },
    Case {
        name: "cond_or_not",
        rules: r#"rule OrNot { strings: $a = "yes" $b = "no" condition: $a or not $b }"#,
        sample: b"only yes here",
    },
    Case {
        name: "cond_n_of_set",
        rules: r#"rule NOf { strings: $a = "aaa" $b = "bbb" $c = "ccc" condition: 2 of ($a, $b, $c) }"#,
        sample: b"aaa and bbb but not the third",
    },
    Case {
        name: "cond_any_of_them",
        rules: r#"rule AnyOf { strings: $a = "one" $b = "two" condition: any of them }"#,
        sample: b"just two here",
    },
    Case {
        name: "cond_all_of_wildcard",
        rules: r#"rule AllWild { strings: $s0 = "aa" $s1 = "bb" condition: all of ($s*) }"#,
        sample: b"aa bb cc",
    },
    Case {
        name: "cond_at_anchor",
        rules: r#"rule AtAnchor { strings: $x = "hello" condition: $x at 0 }"#,
        sample: b"hello world hello",
    },
    Case {
        name: "cond_at_or",
        rules: r#"rule AtOr { strings: $x = "hi" condition: $x at 0 or $x at 6 }"#,
        sample: b"hi xx hi yy hi",
    },
    Case {
        name: "cond_at_nonzero",
        rules: r#"rule AtNonzero { strings: $x = "mark" condition: $x at 4 }"#,
        sample: b"____mark____mark",
    },
    Case {
        name: "hex_jump_open",
        rules: r"rule HexOpen { strings: $x = { 41 42 [2-] 5A } condition: $x }",
        sample: b"AB____Z AB__Z",
    },
    Case {
        name: "cond_none_of_them",
        rules: r#"rule NoneOf { strings: $a = "xx" $b = "yy" condition: none of them }"#,
        sample: b"clean sample without markers",
    },
    Case {
        name: "cond_in_range",
        rules: r#"rule InRange { strings: $x = "sig" condition: $x in (0..4) }"#,
        sample: b"__sig___sig",
    },
    Case {
        name: "cond_count",
        rules: r#"rule Count { strings: $x = "ab" condition: #x == 3 }"#,
        sample: b"ab_ab_ab",
    },
    Case {
        name: "cond_filesize",
        rules: r"rule FileSize { condition: filesize > 4 }",
        sample: b"abcdef",
    },
    Case {
        name: "multi_rule",
        rules: r#"
rule First : demo { strings: $a = "foo" condition: $a }
rule Second { strings: $b = "bar" condition: $b and filesize < 100 }
"#,
        sample: b"foo and bar together",
    },
    Case {
        name: "near_miss_text",
        rules: r#"rule Miss { strings: $x = "absent" condition: $x }"#,
        sample: b"nothing to see here",
    },
    Case {
        name: "near_miss_fullword",
        rules: r#"rule MissFw { strings: $x = "cat" fullword condition: $x }"#,
        sample: b"category concatenate scattered",
    },
    Case {
        name: "near_miss_at",
        rules: r#"rule MissAt { strings: $x = "data" condition: $x at 0 }"#,
        sample: b"__data at offset two",
    },
    Case {
        name: "near_miss_count",
        rules: r#"rule MissCount { strings: $x = "z" condition: #x == 5 }"#,
        sample: b"only one z",
    },
];

fn find_yara() -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(explicit) = std::env::var("YARA") {
        candidates.push(explicit);
    }
    candidates.push("yara".to_owned());
    candidates.push("yara64".to_owned());
    for candidate in candidates {
        let ran: bool = Command::new(&candidate)
            .arg("--version")
            .output()
            .is_ok_and(|out: std::process::Output| out.status.success());
        if ran {
            return Some(candidate);
        }
    }
    None
}

fn engine_map(rules: &str, sample: &[u8]) -> (OffsetMap, Vec<String>) {
    let ruleset = parse_ruleset(rules).expect("corpus rule must parse");
    let compiled = CompiledRuleset::compile(&ruleset).expect("corpus rule must compile");
    let report = compiled.scan(sample);
    let mut map: OffsetMap = BTreeMap::new();
    for rule_match in &report.matches {
        let entry = map.entry(rule_match.rule.clone()).or_default();
        for string_match in &rule_match.strings {
            entry.insert(string_match.id.clone(), string_match.offsets.clone());
        }
    }
    let unevaluated: Vec<String> = report.unevaluated.iter().map(|u| u.rule.clone()).collect();
    (map, unevaluated)
}

fn parse_yara_output(stdout: &str) -> OffsetMap {
    let mut map: OffsetMap = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("0x") {
            let Some((offset_hex, tail)) = rest.split_once(':') else {
                continue;
            };
            let Ok(offset) = u64::from_str_radix(offset_hex, 16) else {
                continue;
            };
            let Some(id) = tail
                .split(':')
                .map(str::trim)
                .find(|segment: &&str| segment.starts_with('$'))
            else {
                continue;
            };
            if let Some(rule) = current.as_ref() {
                map.entry(rule.clone())
                    .or_default()
                    .entry(id.to_owned())
                    .or_default()
                    .push(offset);
            }
        } else {
            let name = line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            map.entry(name.clone()).or_default();
            current = Some(name);
        }
    }
    for strings in map.values_mut() {
        for offsets in strings.values_mut() {
            offsets.sort_unstable();
            offsets.dedup();
        }
    }
    map
}

fn run_yara(bin: &str, dir: &PathBuf, rule_file: &str, sample_file: &str) -> OffsetMap {
    let output = Command::new(bin)
        .arg("-s")
        .arg(rule_file)
        .arg(sample_file)
        .current_dir(dir)
        .output()
        .expect("yara must execute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error:"),
        "yara reported a rule error: {stderr}"
    );
    parse_yara_output(&String::from_utf8_lossy(&output.stdout))
}

#[test]
fn engine_agrees_with_real_yara() {
    let Some(bin) = find_yara() else {
        eprintln!(
            "SKIPPED engine_agrees_with_real_yara: the real yara CLI was not found on PATH or via the YARA env var; install VirusTotal yara to run this comparison"
        );
        return;
    };

    let scratch: ScratchDir = ScratchDir::create("disrobe-yara-oracle").expect("temp dir");
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut mismatches: Vec<String> = Vec::new();
    let mut compared: usize = 0;

    for case in CASES {
        let rule_file: PathBuf = dir.join(format!("{}.yar", case.name));
        let sample_name: String = format!("{}.bin", case.name);
        let sample_file: PathBuf = dir.join(&sample_name);
        std::fs::write(&rule_file, case.rules).expect("write rule");
        std::fs::write(&sample_file, case.sample).expect("write sample");

        let rule_file_name: String = format!("{}.yar", case.name);
        let expected: OffsetMap = run_yara(&bin, &dir, &rule_file_name, &sample_name);
        let (actual, unevaluated) = engine_map(case.rules, case.sample);

        assert!(
            unevaluated.is_empty(),
            "case {} unexpectedly produced unevaluated rules {unevaluated:?}",
            case.name
        );

        if expected != actual {
            mismatches.push(format!(
                "case {}\n  yara:   {expected:?}\n  engine: {actual:?}",
                case.name
            ));
        }
        compared += 1;
    }

    assert!(
        mismatches.is_empty(),
        "{} of {compared} cases disagreed with the real yara CLI:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert!(
        compared >= CASES.len(),
        "expected every case to be compared"
    );
    eprintln!("engine matched the real yara CLI on all {compared} cases");
}
