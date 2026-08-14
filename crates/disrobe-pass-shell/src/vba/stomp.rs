use std::collections::BTreeSet;

use serde::Serialize;

use super::extract::{
    ExtractedModule, ExtractedProject, extract_from_bytes, vba_project_bin_from_bytes,
};
use super::pcode_lift::{SemanticLift, semantic_lift};
use super::pcode_real::{RealModuleDisasm, RealPCodeReport, disassemble_pcode_real};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StompVerdict {
    Consistent,
    Stomped,
    SourceOnly,
    PCodeOnly,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStompReport {
    pub module: String,
    pub verdict: StompVerdict,
    pub source_procedures: Vec<String>,
    pub pcode_procedures: Vec<String>,
    pub source_calls: Vec<String>,
    pub pcode_calls: Vec<String>,
    pub source_strings: Vec<String>,
    pub pcode_strings: Vec<String>,
    pub pcode_only_procedures: Vec<String>,
    pub pcode_only_calls: Vec<String>,
    pub pcode_only_strings: Vec<String>,
    pub recovered_source: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StompReport {
    pub modules: Vec<ModuleStompReport>,
    pub any_stomped: bool,
}

#[must_use]
pub fn analyze_stomp_parts(project: &ExtractedProject, pcode: &RealPCodeReport) -> StompReport {
    let mut modules: Vec<ModuleStompReport> = Vec::with_capacity(pcode.modules.len());
    let mut any_stomped: bool = false;
    let mut paired_source_names: BTreeSet<String> = BTreeSet::new();
    for module in &pcode.modules {
        let paired: Option<&ExtractedModule> = project
            .modules
            .iter()
            .find(|m| names_match(&m.name, &module.name))
            .inspect(|m| {
                paired_source_names.insert(m.name.clone());
            });
        let report: ModuleStompReport = analyze_module(module, paired);
        if report.verdict == StompVerdict::Stomped {
            any_stomped = true;
        }
        modules.push(report);
    }
    for src in &project.modules {
        let already_paired: bool = paired_source_names.contains(&src.name)
            || pcode
                .modules
                .iter()
                .any(|m| names_match(&m.name, &src.name));
        if already_paired {
            continue;
        }
        let source_facts: SourceFacts = extract_source_facts(&src.recovered_source);
        if source_facts.is_empty() {
            continue;
        }
        modules.push(ModuleStompReport {
            module: src.name.clone(),
            verdict: StompVerdict::SourceOnly,
            source_procedures: source_facts.procedures.into_iter().collect(),
            pcode_procedures: Vec::new(),
            source_calls: source_facts.calls.into_iter().collect(),
            pcode_calls: Vec::new(),
            source_strings: source_facts.strings.into_iter().collect(),
            pcode_strings: Vec::new(),
            pcode_only_procedures: Vec::new(),
            pcode_only_calls: Vec::new(),
            pcode_only_strings: Vec::new(),
            recovered_source: trim_to_attribute(&src.recovered_source),
            evidence: vec!["module has compressed source but no compiled p-code".to_owned()],
        });
    }
    StompReport {
        modules,
        any_stomped,
    }
}

pub fn analyze_stomp(ole_or_ooxml_bytes: &[u8]) -> Result<StompReport> {
    let project: ExtractedProject = extract_from_bytes(ole_or_ooxml_bytes)?;
    let ole_bytes: Vec<u8> = vba_project_bin_from_bytes(ole_or_ooxml_bytes)?;
    let pcode: RealPCodeReport = disassemble_pcode_real(&ole_bytes)?;
    Ok(analyze_stomp_parts(&project, &pcode))
}

fn names_match(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[derive(Debug, Default)]
struct SourceFacts {
    procedures: BTreeSet<String>,
    calls: BTreeSet<String>,
    strings: BTreeSet<String>,
}

impl SourceFacts {
    fn is_empty(&self) -> bool {
        self.procedures.is_empty() && self.calls.is_empty() && self.strings.is_empty()
    }
}

fn trim_to_attribute(raw: &str) -> String {
    match raw.find("Attribute VB_Name") {
        Some(idx) => raw[idx..]
            .chars()
            .filter(|c| *c == '\n' || *c == '\t' || (*c as u32) >= 0x20)
            .collect(),
        None => raw
            .chars()
            .filter(|c| *c == '\n' || *c == '\t' || (*c as u32) >= 0x20)
            .collect(),
    }
}

fn extract_source_facts(raw: &str) -> SourceFacts {
    let text: String = trim_to_attribute(raw);
    let mut facts: SourceFacts = SourceFacts::default();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if let Some(name) = procedure_name(trimmed) {
            facts.procedures.insert(name);
        }
        for s in string_literals(trimmed) {
            facts.strings.insert(s);
        }
        for c in call_names(trimmed) {
            facts.calls.insert(c);
        }
    }
    facts
}

fn procedure_name(line: &str) -> Option<String> {
    let mut rest: &str = line;
    for prefix in ["Public ", "Private ", "Friend ", "Static "] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped.trim_start();
        }
    }
    for kw in [
        "Sub ",
        "Function ",
        "Property Get ",
        "Property Let ",
        "Property Set ",
    ] {
        if let Some(after) = rest.strip_prefix(kw) {
            let name: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn string_literals(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes: &[u8] = line.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j <= bytes.len() {
                let lit: &str = &line[start..j.min(line.len())];
                if !lit.is_empty() {
                    out.push(lit.to_owned());
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

const KNOWN_CALLS: &[&str] = &["MsgBox", "Shell", "CreateObject", "GetObject", "WScript"];

fn call_names(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let trimmed: &str = line.trim();
    if let Some(rest) = trimmed.strip_prefix("Call ") {
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !name.is_empty() {
            out.push(last_segment(&name));
        }
    }
    if !trimmed.is_empty() && !trimmed.starts_with('\'') && !is_block_keyword_line(trimmed) {
        let head: String = trimmed
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !head.is_empty() {
            let after: &str = trimmed[head.len()..].trim_start();
            let looks_call: bool = after.starts_with('(')
                || after.starts_with('"')
                || after.is_empty()
                || after.starts_with(|c: char| c.is_alphanumeric());
            let looks_assign: bool = after.starts_with('=') || trimmed.contains(" = ");
            if looks_call && !looks_assign && !is_keyword(&head) {
                out.push(last_segment(&head));
            }
        }
    }
    for known in KNOWN_CALLS {
        if trimmed.contains(known) {
            out.push((*known).to_owned());
        }
    }
    out
}

fn last_segment(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_owned()
}

fn is_block_keyword_line(line: &str) -> bool {
    const STARTS: &[&str] = &[
        "If ",
        "ElseIf ",
        "Else",
        "End ",
        "For ",
        "For Each ",
        "Next",
        "Do",
        "Loop",
        "While ",
        "Wend",
        "With ",
        "Select ",
        "Case ",
        "Exit ",
        "GoTo ",
        "GoSub ",
        "On Error",
        "Resume",
        "Set ",
        "Dim ",
        "Sub ",
        "Function ",
        "Property ",
        "Public ",
        "Private ",
    ];
    STARTS.iter().any(|s| line.starts_with(s))
}

fn is_keyword(word: &str) -> bool {
    const KW: &[&str] = &[
        "If", "Then", "Else", "ElseIf", "End", "For", "Each", "Next", "Do", "Loop", "While",
        "Wend", "With", "Select", "Case", "Exit", "GoTo", "GoSub", "Resume", "Return", "Set",
        "Dim", "Sub", "Function", "Property", "Public", "Private", "Stop", "Nothing", "Empty",
        "Default", "Me", "DoEvents",
    ];
    KW.iter().any(|k| k.eq_ignore_ascii_case(word))
}

fn analyze_module(
    module: &RealModuleDisasm,
    source_module: Option<&ExtractedModule>,
) -> ModuleStompReport {
    let lift: SemanticLift = semantic_lift(module);
    let pcode_facts: SourceFacts = extract_source_facts(&lift.pseudocode);
    let Some(source_module) = source_module else {
        return ModuleStompReport {
            module: module.name.clone(),
            verdict: StompVerdict::PCodeOnly,
            source_procedures: Vec::new(),
            pcode_procedures: pcode_facts.procedures.iter().cloned().collect(),
            source_calls: Vec::new(),
            pcode_calls: pcode_facts.calls.iter().cloned().collect(),
            source_strings: Vec::new(),
            pcode_strings: pcode_facts.strings.iter().cloned().collect(),
            pcode_only_procedures: pcode_facts.procedures.into_iter().collect(),
            pcode_only_calls: pcode_facts.calls.into_iter().collect(),
            pcode_only_strings: pcode_facts.strings.into_iter().collect(),
            recovered_source: lift.pseudocode,
            evidence: vec!["compiled p-code present with no recoverable source stream".to_owned()],
        };
    };
    let source_facts: SourceFacts = extract_source_facts(&source_module.recovered_source);
    let pcode_only_procedures: Vec<String> =
        difference_exact(&pcode_facts.procedures, &source_facts.procedures);
    let pcode_only_calls: Vec<String> = difference_exact(&pcode_facts.calls, &source_facts.calls);
    let pcode_only_strings: Vec<String> =
        difference_fuzzy(&pcode_facts.strings, &source_facts.strings);
    let pcode_has_behavior: bool = !pcode_facts.procedures.is_empty()
        || !pcode_facts.calls.is_empty()
        || !pcode_facts.strings.is_empty();
    let mut evidence: Vec<String> = Vec::new();
    if let Some(reason) = source_module.source_error.as_deref() {
        evidence.push(format!("module source stream did not decode: {reason}"));
    }
    if !pcode_only_procedures.is_empty() {
        evidence.push(format!(
            "p-code defines procedures absent from source: {}",
            pcode_only_procedures.join(", ")
        ));
    }
    if !pcode_only_calls.is_empty() {
        evidence.push(format!(
            "p-code calls routines absent from source: {}",
            pcode_only_calls.join(", ")
        ));
    }
    if !pcode_only_strings.is_empty() {
        evidence.push(format!(
            "p-code references string literals absent from source: {}",
            pcode_only_strings
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<String>>()
                .join(", ")
        ));
    }
    let source_has_behavior: bool = !source_facts.procedures.is_empty()
        || !source_facts.calls.is_empty()
        || !source_facts.strings.is_empty();
    let structural_mismatch: bool = !pcode_only_procedures.is_empty()
        || !pcode_only_calls.is_empty()
        || !pcode_only_strings.is_empty();
    let source_undecodable: bool = source_module.source_error.is_some();
    let verdict: StompVerdict = if source_undecodable
        || (pcode_has_behavior && (!source_has_behavior || structural_mismatch))
    {
        StompVerdict::Stomped
    } else {
        StompVerdict::Consistent
    };
    if verdict == StompVerdict::Consistent {
        evidence
            .push("source and compiled p-code agree on procedures, calls, and strings".to_owned());
    }
    ModuleStompReport {
        module: module.name.clone(),
        verdict,
        source_procedures: source_facts.procedures.into_iter().collect(),
        pcode_procedures: pcode_facts.procedures.into_iter().collect(),
        source_calls: source_facts.calls.into_iter().collect(),
        pcode_calls: pcode_facts.calls.into_iter().collect(),
        source_strings: source_facts.strings.into_iter().collect(),
        pcode_strings: pcode_facts.strings.into_iter().collect(),
        pcode_only_procedures,
        pcode_only_calls,
        pcode_only_strings,
        recovered_source: lift.pseudocode,
        evidence,
    }
}

fn difference_exact(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Vec<String> {
    a.iter()
        .filter(|k| !b.iter().any(|x| x.eq_ignore_ascii_case(k)))
        .cloned()
        .collect()
}

fn difference_fuzzy(a: &BTreeSet<String>, b: &BTreeSet<String>) -> Vec<String> {
    a.iter()
        .filter(|k| {
            let needle: String = k.to_ascii_lowercase();
            !b.iter().any(|x| {
                let hay: String = x.to_ascii_lowercase();
                hay.contains(&needle) || needle.contains(&hay)
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vba::pcode::PCodeInstruction;
    use crate::vba::pcode_real::RealPCodeLine;

    fn line(idx: usize, text: &str) -> RealPCodeLine {
        RealPCodeLine {
            line_index: idx,
            instructions: Vec::<PCodeInstruction>::new(),
            text: text.to_owned(),
        }
    }

    fn module(name: &str, lines: Vec<RealPCodeLine>) -> RealModuleDisasm {
        RealModuleDisasm {
            name: name.to_owned(),
            pcode_offset_in_stream: 0,
            num_lines: lines.len(),
            lines,
        }
    }

    fn source_module(name: &str, text: &str) -> ExtractedModule {
        ExtractedModule {
            name: name.to_owned(),
            raw_bytes_len: text.len(),
            text_offset: Some(0),
            recovered_source: text.to_owned(),
            source_error: None,
        }
    }

    fn undecodable_module(name: &str, reason: &str) -> ExtractedModule {
        ExtractedModule {
            name: name.to_owned(),
            raw_bytes_len: 0,
            text_offset: Some(0),
            recovered_source: String::new(),
            source_error: Some(reason.to_owned()),
        }
    }

    #[test]
    fn procedure_name_handles_modifiers() {
        assert_eq!(procedure_name("Public Sub Main()"), Some("Main".to_owned()));
        assert_eq!(
            procedure_name("Private Function Calc(x)"),
            Some("Calc".to_owned())
        );
        assert_eq!(
            procedure_name("Property Get Value()"),
            Some("Value".to_owned())
        );
        assert_eq!(procedure_name("Dim x As Long"), None);
    }

    #[test]
    fn string_literals_extracted() {
        let s: Vec<String> = string_literals("MsgBox \"hello world\"");
        assert_eq!(s, vec!["hello world".to_owned()]);
    }

    #[test]
    fn consistent_when_source_matches_pcode() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x000B \"hello world\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let source: ExtractedModule = source_module(
            "Module1",
            "Attribute VB_Name = \"Module1\"\nSub Main()\n    MsgBox \"hello world\"\nEnd Sub\n",
        );
        let r: ModuleStompReport = analyze_module(&m, Some(&source));
        assert_eq!(r.verdict, StompVerdict::Consistent, "report: {r:?}");
        assert!(r.pcode_only_strings.is_empty());
        assert!(r.pcode_only_calls.is_empty());
    }

    #[test]
    fn stomped_when_source_stripped_but_pcode_intact() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x000B \"hello world\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let source: ExtractedModule = source_module("Module1", "Attribute VB_Name = \"Module1\"\n");
        let r: ModuleStompReport = analyze_module(&m, Some(&source));
        assert_eq!(r.verdict, StompVerdict::Stomped, "report: {r:?}");
        assert!(
            r.pcode_only_strings.contains(&"hello world".to_owned()),
            "expected stripped string flagged: {:?}",
            r.pcode_only_strings
        );
        assert!(r.recovered_source.contains("MsgBox \"hello world\""));
    }

    #[test]
    fn stomped_when_source_fakes_benign_macro() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x0007 \"cmd.exe\"\nArgsCall Shell 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let source: ExtractedModule = source_module(
            "Module1",
            "Attribute VB_Name = \"Module1\"\nSub Main()\n    MsgBox \"benign\"\nEnd Sub\n",
        );
        let r: ModuleStompReport = analyze_module(&m, Some(&source));
        assert_eq!(r.verdict, StompVerdict::Stomped, "report: {r:?}");
        assert!(r.pcode_only_calls.contains(&"Shell".to_owned()));
        assert!(r.pcode_only_strings.contains(&"cmd.exe".to_owned()));
    }

    #[test]
    fn undecodable_source_stream_is_reported_as_a_stomp_with_its_reason() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x000B \"hello world\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let source: ExtractedModule =
            undecodable_module("Module1", "MS-OVBA signature byte must be 0x01, got 0x53");
        let r: ModuleStompReport = analyze_module(&m, Some(&source));
        assert_eq!(r.verdict, StompVerdict::Stomped, "report: {r:?}");
        assert!(
            r.evidence.iter().any(
                |e: &String| e.contains("module source stream did not decode")
                    && e.contains("0x53")
            ),
            "the decode failure must be named in the evidence; evidence={:?}",
            r.evidence
        );
        assert!(r.recovered_source.contains("MsgBox \"hello world\""));
    }

    #[test]
    fn pcode_only_when_no_source() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x0001 \"x\"\nArgsCall Print 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let r: ModuleStompReport = analyze_module(&m, None);
        assert_eq!(r.verdict, StompVerdict::PCodeOnly);
    }
}
