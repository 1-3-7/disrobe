mod atoms;
mod cond;

use std::collections::BTreeMap;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::yara::{Rule, YaraRuleset, YaraString};
use atoms::{AtomSpec, StringProgram};
use cond::{CompiledCond, MatchView};

pub const YARA_MATCH_SCHEMA: &str = "disrobe.yara.scan/v0";

#[derive(Debug, Error)]
pub enum YaraMatchError {
    #[error("DR-YARAMATCH-0001: failed to build the atom automaton: {0}")]
    Automaton(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    pub id: String,
    pub offsets: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub meta: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<StringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnevaluatedRule {
    pub rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema: &'static str,
    pub matches: Vec<RuleMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unevaluated: Vec<UnevaluatedRule>,
}

#[derive(Debug)]
struct ReadyRule {
    name: String,
    tags: Vec<String>,
    meta: BTreeMap<String, String>,
    strings: Vec<StringProgram>,
    condition: CompiledCond,
}

#[derive(Debug)]
enum CompiledRule {
    Ready(ReadyRule),
    Unevaluated { name: String, reason: String },
}

#[derive(Debug, Clone, Copy)]
struct AtomOwner {
    rule: usize,
    string: usize,
    back: usize,
}

#[derive(Debug)]
pub struct CompiledRuleset {
    rules: Vec<CompiledRule>,
    automaton: Option<AhoCorasick>,
    atom_owners: Vec<Vec<AtomOwner>>,
}

impl CompiledRuleset {
    pub fn compile(ruleset: &YaraRuleset) -> Result<Self, YaraMatchError> {
        let mut rules: Vec<CompiledRule> = Vec::with_capacity(ruleset.rules.len());
        let mut atom_patterns: Vec<Vec<u8>> = Vec::new();
        let mut atom_owners: Vec<Vec<AtomOwner>> = Vec::new();
        let mut atom_index: BTreeMap<Vec<u8>, usize> = BTreeMap::new();

        for (rule_idx, rule) in ruleset.rules.iter().enumerate() {
            match compile_rule(rule) {
                CompiledRule::Ready(ready) => {
                    for (string_idx, program) in ready.strings.iter().enumerate() {
                        if let Some(AtomSpec { bytes, back }) = program.atom.as_ref() {
                            let owner: AtomOwner = AtomOwner {
                                rule: rule_idx,
                                string: string_idx,
                                back: *back,
                            };
                            if let Some(&pattern_id) = atom_index.get(bytes) {
                                atom_owners[pattern_id].push(owner);
                            } else {
                                let pattern_id: usize = atom_patterns.len();
                                atom_index.insert(bytes.clone(), pattern_id);
                                atom_patterns.push(bytes.clone());
                                atom_owners.push(vec![owner]);
                            }
                        }
                    }
                    rules.push(CompiledRule::Ready(ready));
                }
                unevaluated @ CompiledRule::Unevaluated { .. } => rules.push(unevaluated),
            }
        }

        let automaton: Option<AhoCorasick> =
            if atom_patterns.is_empty() {
                None
            } else {
                Some(AhoCorasick::builder().build(&atom_patterns).map_err(
                    |e: aho_corasick::BuildError| YaraMatchError::Automaton(e.to_string()),
                )?)
            };

        Ok(Self {
            rules,
            automaton,
            atom_owners,
        })
    }

    #[must_use]
    pub fn scan(&self, buf: &[u8]) -> ScanReport {
        let mut collected: Vec<Vec<Vec<u64>>> = self
            .rules
            .iter()
            .map(|rule: &CompiledRule| match rule {
                CompiledRule::Ready(ready) => vec![Vec::new(); ready.strings.len()],
                CompiledRule::Unevaluated { .. } => Vec::new(),
            })
            .collect();

        if let Some(automaton) = self.automaton.as_ref() {
            for hit in automaton.find_overlapping_iter(buf) {
                let pattern_id: usize = hit.pattern().as_usize();
                let start: usize = hit.start();
                let Some(owners): Option<&Vec<AtomOwner>> = self.atom_owners.get(pattern_id) else {
                    continue;
                };
                for owner in owners {
                    let Some(anchor): Option<usize> = start.checked_sub(owner.back) else {
                        continue;
                    };
                    if let CompiledRule::Ready(ready) = &self.rules[owner.rule]
                        && ready.strings[owner.string].verify_at(buf, anchor)
                    {
                        collected[owner.rule][owner.string].push(anchor as u64);
                    }
                }
            }
        }

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if let CompiledRule::Ready(ready) = rule {
                for (string_idx, program) in ready.strings.iter().enumerate() {
                    if program.atom.is_none() {
                        collected[rule_idx][string_idx] = program.find_all(buf);
                    }
                }
            }
        }

        for offsets in collected.iter_mut().flatten() {
            offsets.sort_unstable();
            offsets.dedup();
        }

        let mut matches: Vec<RuleMatch> = Vec::new();
        let mut unevaluated: Vec<UnevaluatedRule> = Vec::new();
        let filesize: i64 = i64::try_from(buf.len()).unwrap_or(i64::MAX);

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            match rule {
                CompiledRule::Ready(ready) => {
                    let view: MatchView<'_> = MatchView {
                        offsets: &collected[rule_idx],
                        filesize,
                    };
                    if ready.condition.evaluate(&view) {
                        matches.push(build_match(ready, &collected[rule_idx]));
                    }
                }
                CompiledRule::Unevaluated { name, reason } => {
                    unevaluated.push(UnevaluatedRule {
                        rule: name.clone(),
                        reason: reason.clone(),
                    });
                }
            }
        }

        ScanReport {
            schema: YARA_MATCH_SCHEMA,
            matches,
            unevaluated,
        }
    }
}

fn build_match(ready: &ReadyRule, collected: &[Vec<u64>]) -> RuleMatch {
    let mut strings: Vec<StringMatch> = Vec::new();
    for (idx, program) in ready.strings.iter().enumerate() {
        if program.private {
            continue;
        }
        let all_matches: &[u64] = collected.get(idx).map_or(&[][..], Vec::as_slice);
        let reported: Vec<u64> = ready.condition.reported_offsets(idx, all_matches);
        if !reported.is_empty() {
            strings.push(StringMatch {
                id: program.id.clone(),
                offsets: reported,
            });
        }
    }
    strings.sort_by(|a: &StringMatch, b: &StringMatch| a.id.cmp(&b.id));
    RuleMatch {
        rule: ready.name.clone(),
        tags: ready.tags.clone(),
        meta: ready.meta.clone(),
        strings,
    }
}

fn compile_rule(rule: &Rule) -> CompiledRule {
    let mut programs: Vec<StringProgram> = Vec::with_capacity(rule.strings.len());
    for string in &rule.strings {
        match StringProgram::compile(string) {
            Ok(program) => programs.push(program),
            Err(unsupported) => {
                return CompiledRule::Unevaluated {
                    name: rule.name.clone(),
                    reason: format!("string {}: {}", string.id, unsupported.reason),
                };
            }
        }
    }
    let ids: Vec<String> = collect_ids(&rule.strings);
    match CompiledCond::compile(&rule.condition, &ids) {
        Ok(condition) => CompiledRule::Ready(ReadyRule {
            name: rule.name.clone(),
            tags: rule.tags.clone(),
            meta: rule.meta.clone(),
            strings: programs,
            condition,
        }),
        Err(err) => CompiledRule::Unevaluated {
            name: rule.name.clone(),
            reason: format!("condition: {}", err.reason),
        },
    }
}

fn collect_ids(strings: &[YaraString]) -> Vec<String> {
    strings.iter().map(|s: &YaraString| s.id.clone()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::yara::parse_ruleset;

    fn scan(source: &str, buf: &[u8]) -> ScanReport {
        let ruleset: YaraRuleset = parse_ruleset(source).expect("ruleset must parse");
        let compiled: CompiledRuleset = CompiledRuleset::compile(&ruleset).expect("compile");
        compiled.scan(buf)
    }

    fn offsets(report: &ScanReport, rule: &str, id: &str) -> Vec<u64> {
        report
            .matches
            .iter()
            .find(|m: &&RuleMatch| m.rule == rule)
            .and_then(|m: &RuleMatch| m.strings.iter().find(|s: &&StringMatch| s.id == id))
            .map(|s: &StringMatch| s.offsets.clone())
            .unwrap_or_default()
    }

    fn matched(report: &ScanReport, rule: &str) -> bool {
        report.matches.iter().any(|m: &RuleMatch| m.rule == rule)
    }

    #[test]
    fn text_literal_reports_overlapping_offsets() {
        let src: &str = r#"rule R { strings: $x = "aa" condition: $x }"#;
        let report: ScanReport = scan(src, b"aaaa");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 1, 2]);
    }

    #[test]
    fn nocase_matches_all_cases() {
        let src: &str = r#"rule R { strings: $x = "abc" nocase condition: $x }"#;
        let report: ScanReport = scan(src, b"abc ABC AbC");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 4, 8]);
    }

    #[test]
    fn wide_matches_utf16() {
        let src: &str = r#"rule R { strings: $x = "hi" wide condition: $x }"#;
        let report: ScanReport = scan(src, b"hi h\x00i\x00");
        assert_eq!(offsets(&report, "R", "$x"), vec![3]);
    }

    #[test]
    fn fullword_respects_boundaries() {
        let src: &str = r#"rule R { strings: $x = "cat" fullword condition: $x }"#;
        let report: ScanReport = scan(src, b"cat category cat.");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 13]);
    }

    #[test]
    fn hex_wildcard_and_jump() {
        let src: &str = r"rule R { strings: $x = { 68 ?? 6c } condition: $x }";
        let report: ScanReport = scan(src, b"halloc hxlo");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 7]);
    }

    #[test]
    fn hex_jump_range() {
        let src: &str = r"rule R { strings: $x = { 41 [1-3] 44 } condition: $x }";
        let report: ScanReport = scan(src, b"A__D AzzzzD");
        assert_eq!(offsets(&report, "R", "$x"), vec![0]);
    }

    #[test]
    fn hex_alternation() {
        let src: &str = r"rule R { strings: $x = { ( 41 42 | 43 44 ) 45 } condition: $x }";
        let report: ScanReport = scan(src, b"ABE__CDE");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 5]);
    }

    #[test]
    fn regex_matches_every_start() {
        let src: &str = r"rule R { strings: $x = /a.a/ condition: $x }";
        let report: ScanReport = scan(src, b"aaaa");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 1]);
    }

    #[test]
    fn condition_at_limits_reported_offsets() {
        let src: &str = r#"rule R { strings: $x = "hello" condition: $x at 0 }"#;
        let report: ScanReport = scan(src, b"hello world hello");
        assert!(matched(&report, "R"));
        assert_eq!(offsets(&report, "R", "$x"), vec![0]);
    }

    #[test]
    fn condition_at_false_when_absent() {
        let src: &str = r#"rule R { strings: $x = "hello" condition: $x at 5 }"#;
        let report: ScanReport = scan(src, b"hello world hello");
        assert!(!matched(&report, "R"));
    }

    #[test]
    fn condition_plain_reference_reports_all() {
        let src: &str = r#"rule R { strings: $x = "hello" condition: $x and $x at 0 }"#;
        let report: ScanReport = scan(src, b"hello world hello");
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 12]);
    }

    #[test]
    fn condition_in_range_reports_all_matches() {
        let src: &str = r#"rule R { strings: $x = "hello" condition: $x in (0..3) }"#;
        let report: ScanReport = scan(src, b"hello world hello");
        assert!(matched(&report, "R"));
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 12]);
    }

    #[test]
    fn condition_count_comparison() {
        let src: &str = r#"rule R { strings: $x = "ab" condition: #x == 3 }"#;
        let report: ScanReport = scan(src, b"ab ab ab");
        assert!(matched(&report, "R"));
        assert_eq!(offsets(&report, "R", "$x"), vec![0, 3, 6]);
    }

    #[test]
    fn condition_of_quantifier() {
        let src: &str =
            r#"rule R { strings: $a = "aaa" $b = "bbb" $c = "ccc" condition: 2 of ($a, $b, $c) }"#;
        let report: ScanReport = scan(src, b"aaa___bbb");
        assert!(matched(&report, "R"));
    }

    #[test]
    fn condition_of_quantifier_below_threshold() {
        let src: &str =
            r#"rule R { strings: $a = "aaa" $b = "bbb" $c = "ccc" condition: 2 of ($a*, $b, $c) }"#;
        let report: ScanReport = scan(src, b"aaa______");
        assert!(!matched(&report, "R"));
    }

    #[test]
    fn condition_all_of_them_and_wildcard() {
        let src: &str = r#"rule R { strings: $s0 = "aa" $s1 = "bb" condition: all of ($s*) }"#;
        let report: ScanReport = scan(src, b"aa bb");
        assert!(matched(&report, "R"));
    }

    #[test]
    fn condition_filesize() {
        let src: &str = r"rule R { condition: filesize > 3 }";
        let report: ScanReport = scan(src, b"abcd");
        assert!(matched(&report, "R"));
        let empty: ScanReport = scan(src, b"ab");
        assert!(!matched(&empty, "R"));
    }

    #[test]
    fn unsupported_condition_is_reported_not_hidden() {
        let src: &str = r#"rule R { strings: $x = "x" condition: pe.entry_point == 0 }"#;
        let report: ScanReport = scan(src, b"x");
        assert!(!matched(&report, "R"));
        assert!(
            report
                .unevaluated
                .iter()
                .any(|u: &UnevaluatedRule| u.rule == "R")
        );
    }

    #[test]
    fn unsupported_modifier_marks_rule_unevaluated() {
        let src: &str = r#"rule R { strings: $x = "x" xor condition: $x }"#;
        let report: ScanReport = scan(src, b"x");
        assert!(
            report
                .unevaluated
                .iter()
                .any(|u: &UnevaluatedRule| u.rule == "R" && u.reason.contains("xor"))
        );
    }

    #[test]
    fn private_string_used_in_condition_not_reported() {
        let src: &str =
            r#"rule R { strings: $pub = "pub" $sec = "sec" private condition: $pub and $sec }"#;
        let report: ScanReport = scan(src, b"pub sec");
        assert!(matched(&report, "R"));
        assert_eq!(offsets(&report, "R", "$pub"), vec![0]);
        assert!(offsets(&report, "R", "$sec").is_empty());
    }

    #[test]
    fn multi_rule_and_boolean_logic() {
        let src: &str = r#"
rule Alpha : tag1 { strings: $a = "foo" $b = "bar" condition: $a and $b }
rule Beta { strings: $x = "baz" condition: not $x }
"#;
        let report: ScanReport = scan(src, b"foo bar");
        assert!(matched(&report, "Alpha"));
        assert!(matched(&report, "Beta"));
        let alpha: &RuleMatch = report
            .matches
            .iter()
            .find(|m: &&RuleMatch| m.rule == "Alpha")
            .expect("alpha");
        assert_eq!(alpha.tags, vec!["tag1".to_owned()]);
    }
}
