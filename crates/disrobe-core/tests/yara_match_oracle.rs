#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_core::yara::parse_ruleset;
use disrobe_core::yara_match::CompiledRuleset;

type OffsetMap = BTreeMap<String, BTreeMap<String, Vec<u64>>>;

const REQUIRE_YARA_VAR: &str = "DISROBE_REQUIRE_YARA";
const YARA_TIMEOUT: Duration = Duration::from_secs(15);
const YARA_CAPTURE_LIMIT: usize = 1024 * 1024;

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
        rules: r"rule HexWild { strings: $x = { 41 ?? 43 44 45 46 } condition: $x }",
        sample: b"AxCDEF AyCDEF AZZZZZ",
    },
    Case {
        name: "hex_nibble",
        rules: r"rule HexNibble { strings: $x = { 4? 5A 61 62 63 64 } condition: $x }",
        sample: b"\x40\x5aabcd\x4f\x5aabcd\x30\x5aabcd",
    },
    Case {
        name: "hex_jump_range",
        rules: r"rule HexJump { strings: $x = { 41 [1-3] 5A 61 62 63 64 } condition: $x }",
        sample: b"A__Zabcd AwwwwZabcd",
    },
    Case {
        name: "hex_jump_exact",
        rules: r"rule HexExact { strings: $x = { 41 [2] 5A 61 62 63 64 } condition: $x }",
        sample: b"A__Zabcd A_Zabcd",
    },
    Case {
        name: "hex_alternation",
        rules: r"rule HexAlt { strings: $x = { ( 41 42 | 43 44 ) 45 46 47 48 } condition: $x }",
        sample: b"ABEFGH__CDEFGH__ABX",
    },
    Case {
        name: "regex_simple",
        rules: r"rule Rgx { strings: $x = /ab+c/ condition: $x }",
        sample: b"abc abbbc adc",
    },
    Case {
        name: "regex_overlap",
        rules: r"rule RgxOverlap { strings: $x = /a.aaaaaaaa/ condition: $x }",
        sample: b"aaaaaaaaaaaa",
    },
    Case {
        name: "regex_class",
        rules: r"rule RgxClass { strings: $x = /[0-9]{3}ABCD/ condition: $x }",
        sample: b"12 345ABCD 6789ABCD",
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
        rules: r"rule HexOpen { strings: $x = { 41 42 [2-] 5A 61 62 63 64 } condition: $x }",
        sample: b"AB____Zabcd AB__Zabcd",
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
        rules: r#"rule MissCount { strings: $x = "zzzz" condition: #x == 5 }"#,
        sample: b"only one zzzz",
    },
];

fn output_text(bytes: Vec<u8>, stream: &str, purpose: &str) -> String {
    String::from_utf8(bytes).unwrap_or_else(|error: std::string::FromUtf8Error| {
        panic!("{purpose} returned non-UTF-8 {stream}: {error}")
    })
}

fn probe_yara(candidate: &Path) -> Result<PathBuf, String> {
    let args: [&OsStr; 1] = [OsStr::new("--version")];
    let output: CapturedOutput = run_captured(candidate, &args, YARA_TIMEOUT, YARA_CAPTURE_LIMIT)
        .map_err(|error: std::io::Error| {
            format!("could not start {}: {error}", candidate.display())
        })?
        .ok_or_else(|| {
            format!(
                "{} did not report its version within {YARA_TIMEOUT:?}",
                candidate.display()
            )
        })?;
    let stdout: String =
        String::from_utf8(output.stdout).map_err(|error: std::string::FromUtf8Error| {
            format!(
                "{} returned a non-UTF-8 version: {error}",
                candidate.display()
            )
        })?;
    let stderr: String =
        String::from_utf8(output.stderr).map_err(|error: std::string::FromUtf8Error| {
            format!(
                "{} returned non-UTF-8 stderr during its version probe: {error}",
                candidate.display()
            )
        })?;
    if output.exit_code != Some(0) {
        return Err(format!(
            "{} --version exited {:?}: {}",
            candidate.display(),
            output.exit_code,
            stderr.trim()
        ));
    }
    if !stderr.is_empty() {
        return Err(format!(
            "{} --version wrote to stderr: {}",
            candidate.display(),
            stderr.trim()
        ));
    }
    let version: &str = stdout.trim();
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part: &&str| {
            part.is_empty() || !part.bytes().all(|byte: u8| byte.is_ascii_digit())
        })
    {
        return Err(format!(
            "{} --version returned {version:?}, not a numeric YARA version",
            candidate.display()
        ));
    }
    Ok(candidate.to_path_buf())
}

fn required_yara() -> bool {
    let Some(raw): Option<OsString> = std::env::var_os(REQUIRE_YARA_VAR) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn find_yara() -> Option<PathBuf> {
    let explicit: Option<OsString> = std::env::var_os("YARA");
    if let Some(explicit) = explicit {
        let candidate: PathBuf = PathBuf::from(explicit);
        return Some(probe_yara(&candidate).unwrap_or_else(|defect: String| {
            panic!(
                "YARA names an unusable reference at {}: {defect}",
                candidate.display()
            )
        }));
    }
    let candidates: [PathBuf; 2] = [PathBuf::from("yara"), PathBuf::from("yara64")];
    let mut defects: Vec<String> = Vec::new();
    for candidate in candidates {
        match probe_yara(&candidate) {
            Ok(path) => return Some(path),
            Err(defect) => defects.push(defect),
        }
    }
    let defect: String = defects.join("; ");
    assert!(
        !required_yara(),
        "{REQUIRE_YARA_VAR} makes the real YARA CLI mandatory, so the matcher differential must not report success without it: {defect}"
    );
    eprintln!(
        "NOT MEASURED: the real YARA CLI differential compared nothing because no usable yara or yara64 executable was found. Set {REQUIRE_YARA_VAR}=1 to make this fatal. Probes: {defect}"
    );
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

fn parse_yara_output(stdout: &str, target: &Path) -> Result<OffsetMap, String> {
    let mut map: OffsetMap = BTreeMap::new();
    let mut current: Option<String> = None;
    let target_text: String = target.display().to_string();
    for (line_index, raw_line) in stdout.lines().enumerate() {
        let line: &str = raw_line.trim_end();
        if line.is_empty() {
            return Err(format!("YARA emitted an empty line at {}", line_index + 1));
        }
        if let Some(rest) = line.strip_prefix("0x") {
            let (offset_hex, tail): (&str, &str) = rest.split_once(':').ok_or_else(|| {
                format!(
                    "YARA match line {} has no offset delimiter: {line:?}",
                    line_index + 1
                )
            })?;
            let offset: u64 =
                u64::from_str_radix(offset_hex, 16).map_err(|error: std::num::ParseIntError| {
                    format!(
                        "YARA match line {} has invalid offset {offset_hex:?}: {error}",
                        line_index + 1
                    )
                })?;
            let (id, _data): (&str, &str) = tail.split_once(':').ok_or_else(|| {
                format!(
                    "YARA match line {} has no data delimiter: {line:?}",
                    line_index + 1
                )
            })?;
            let id: &str = id.trim();
            if !id.starts_with('$') || id.len() == 1 {
                return Err(format!(
                    "YARA match line {} has invalid string identifier {id:?}",
                    line_index + 1
                ));
            }
            let rule: &String = current.as_ref().ok_or_else(|| {
                format!(
                    "YARA emitted match line {} before a rule header: {line:?}",
                    line_index + 1
                )
            })?;
            map.entry(rule.clone())
                .or_default()
                .entry(id.to_owned())
                .or_default()
                .push(offset);
        } else {
            let (name, emitted_target): (&str, &str) = line.split_once(' ').ok_or_else(|| {
                format!(
                    "YARA rule header {} has no target path: {line:?}",
                    line_index + 1
                )
            })?;
            if name.is_empty() || emitted_target != target_text {
                return Err(format!(
                    "YARA rule header {} is not `<rule> {target_text}`: {line:?}",
                    line_index + 1
                ));
            }
            let name: String = name.to_owned();
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
    Ok(map)
}

fn run_yara(bin: &Path, rule_file: &Path, sample_file: &Path) -> OffsetMap {
    assert!(
        rule_file.is_absolute() && sample_file.is_absolute(),
        "the bounded YARA runner requires absolute fixture paths"
    );
    let args: [&OsStr; 5] = [
        OsStr::new("--print-strings"),
        OsStr::new("--fail-on-warnings"),
        OsStr::new("--timeout=5"),
        rule_file.as_os_str(),
        sample_file.as_os_str(),
    ];
    let output: CapturedOutput = run_captured(bin, &args, YARA_TIMEOUT, YARA_CAPTURE_LIMIT)
        .unwrap_or_else(|error: std::io::Error| {
            panic!("could not start YARA at {}: {error}", bin.display())
        })
        .unwrap_or_else(|| panic!("YARA at {} exceeded {YARA_TIMEOUT:?}", bin.display()));
    let stdout: String = output_text(output.stdout, "stdout", "YARA scan");
    let stderr: String = output_text(output.stderr, "stderr", "YARA scan");
    assert_eq!(
        output.exit_code,
        Some(0),
        "YARA at {} exited {:?}: {stderr}",
        bin.display(),
        output.exit_code
    );
    assert!(
        stderr.is_empty(),
        "YARA at {} wrote to stderr despite --fail-on-warnings: {stderr}",
        bin.display()
    );
    parse_yara_output(&stdout, sample_file).unwrap_or_else(|defect: String| {
        panic!("YARA at {} emitted invalid output: {defect}", bin.display())
    })
}

fn compare_maps(case_name: &str, expected: &OffsetMap, actual: &OffsetMap) -> Option<String> {
    (expected != actual)
        .then(|| format!("case {case_name}\n  YARA:   {expected:?}\n  engine: {actual:?}"))
}

#[test]
fn engine_agrees_with_real_yara() {
    let Some(bin): Option<PathBuf> = find_yara() else {
        return;
    };

    let scratch: ScratchDir = ScratchDir::create("disrobe-yara-oracle").expect("temp dir");
    let dir: PathBuf = scratch.path().to_path_buf();

    let mut mismatches: Vec<String> = Vec::new();
    let mut compared: usize = 0;
    let mut mutation_controls: usize = 0;

    for case in CASES {
        let rule_file: PathBuf = dir.join(format!("{}.yar", case.name));
        let sample_file: PathBuf = dir.join(format!("{}.bin", case.name));
        std::fs::write(&rule_file, case.rules).expect("write rule");
        std::fs::write(&sample_file, case.sample).expect("write sample");

        let expected: OffsetMap = run_yara(&bin, &rule_file, &sample_file);
        let (actual, unevaluated) = engine_map(case.rules, case.sample);

        assert!(
            unevaluated.is_empty(),
            "case {} unexpectedly produced unevaluated rules {unevaluated:?}",
            case.name
        );

        if let Some(mismatch) = compare_maps(case.name, &expected, &actual) {
            mismatches.push(mismatch);
        } else if case.name == "hex_fixed" {
            let mut mutant: OffsetMap = actual.clone();
            let offsets: &mut Vec<u64> = mutant
                .get_mut("HexFixed")
                .and_then(|strings: &mut BTreeMap<String, Vec<u64>>| strings.get_mut("$x"))
                .expect("the real baseline must contain HexFixed/$x offsets");
            let offset_index: usize = offsets
                .iter()
                .position(|offset: &u64| *offset == 2)
                .expect("the real baseline must contain the first match at offset 2");
            offsets.remove(offset_index);
            let control: String = compare_maps(case.name, &expected, &mutant)
                .expect("dropping a real YARA offset must make the comparator reject the map");
            assert!(
                control.contains("hex_fixed")
                    && control.contains("HexFixed")
                    && control.contains("$x")
                    && control.contains('2'),
                "the mutation diagnostic must name the case and removed match: {control}"
            );
            mutation_controls += 1;
        }
        compared += 1;
    }

    assert!(
        mismatches.is_empty(),
        "{} of {compared} cases disagreed with the real YARA CLI:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert!(
        compared >= CASES.len(),
        "expected every case to be compared"
    );
    assert_eq!(
        mutation_controls, 1,
        "exactly one dropped-offset mutation control must run"
    );
    eprintln!(
        "[evidence] YARA differential matched all {compared} cases; dropped-offset mutation control rejected"
    );
}
