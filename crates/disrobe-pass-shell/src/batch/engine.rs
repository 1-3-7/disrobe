use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::batch::arith;
use crate::batch::chain::{DecryptedStage, recover_stages};
use crate::batch::emulate::{EmuResult, EmuState, emulate, scan_chcp};
use crate::batch::expand::{ExpandStats, expand_repeated};
use crate::batch::forloop::{ForLoop, parse_for_f_string, parse_for_l, unroll};
use crate::batch::iff::{IfOutcome, eval_if};
use crate::batch::ioc::{BatchIocReport, surface};
use crate::batch::normalize::{NormalizeReport, normalize};
use crate::batch::payload::{EmbeddedPayload, extract_embedded};

const MAX_EXPANSION_ROUNDS: usize = 16;
const MAX_LINES: usize = 50_000;
const MAX_TOTAL_OUTPUT: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BatchDeobReport {
    pub caret_escapes_removed: usize,
    pub line_continuations_joined: usize,
    pub var_expansions: usize,
    pub delayed_expansions: usize,
    pub substring_expansions: usize,
    pub substitution_expansions: usize,
    pub tilde_expansions: usize,
    pub arithmetic_folds: usize,
    pub for_loops_unrolled: usize,
    pub if_branches_folded: usize,
    pub commands_emulated: usize,
    pub embedded_payloads: Vec<EmbeddedPayload>,
    pub decrypted_stages: Vec<DecryptedStage>,
    pub iocs: BatchIocReport,
    pub output: String,
}

#[derive(Debug, Default)]
struct Counters {
    var_expansions: usize,
    delayed_expansions: usize,
    substring_expansions: usize,
    substitution_expansions: usize,
    tilde_expansions: usize,
    arithmetic_folds: usize,
    for_loops_unrolled: usize,
    if_branches_folded: usize,
    commands_emulated: usize,
}

impl Counters {
    fn add_expand(&mut self, stats: ExpandStats) {
        self.var_expansions += stats.var_refs;
        self.delayed_expansions += stats.delayed_refs;
        self.substring_expansions += stats.substrings;
        self.substitution_expansions += stats.substitutions;
        self.tilde_expansions += stats.tilde_params;
    }
}

static SET_PLAIN: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)^\s*set\s+(?:"(?P<qname>[^=]+)=(?P<qval>[^"]*)"|(?P<name>[^=\s/][^=]*)=(?P<val>.*))$"#,
    )
});

static SET_A: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?i)^\s*set\s+/a\s+(?:"(?P<qname>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<qexpr>[^"]*)"|(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>.*))$"#,
    )
});

static DELAYED_ON: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(r"(?i)^\s*setlocal\b.*\benabledelayedexpansion\b")
});

static FOR_LEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)^\s*for\s+/"));

static IF_LEADER: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"(?i)^\s*if\b"));

#[must_use]
pub fn deobfuscate_batch(input: &str, args: &[String]) -> BatchDeobReport {
    let norm: NormalizeReport = normalize(input);
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut counters: Counters = Counters::default();
    let mut emu_state: EmuState = EmuState::default();
    let mut delayed: bool = false;
    let mut output_lines: Vec<String> = Vec::new();

    let lines: Vec<String> = coalesce_blocks(&norm.output);
    let mut worklist: Vec<String> = lines;
    let mut processed: usize = 0;
    let mut output_bytes: usize = 0;
    let mut output_counted: usize = 0;

    while let Some(line) = pop_front(&mut worklist) {
        processed += 1;
        while output_counted < output_lines.len() {
            output_bytes = output_bytes.saturating_add(output_lines[output_counted].len());
            output_counted = output_counted.saturating_add(1);
        }
        if processed > MAX_LINES || output_bytes > MAX_TOTAL_OUTPUT {
            break;
        }
        let trimmed: &str = line.trim();
        if trimmed.is_empty() {
            output_lines.push(line);
            continue;
        }

        if DELAYED_ON.is_match(trimmed) {
            delayed = true;
            output_lines.push(line);
            continue;
        }
        if let Some(cp) = scan_chcp(trimmed) {
            emu_state.codepage = Some(cp);
        }

        if let Some(rewritten) = handle_set_a(trimmed, &mut env, &mut counters, args, delayed) {
            output_lines.push(rewritten);
            continue;
        }
        if let Some(rewritten) = handle_set(trimmed, &mut env, &mut counters, args, delayed) {
            output_lines.push(rewritten);
            continue;
        }
        if FOR_LEADER.is_match(trimmed)
            && handle_for(trimmed, &env, args, delayed, &mut counters, &mut worklist)
        {
            continue;
        }
        if IF_LEADER.is_match(trimmed)
            && handle_if(trimmed, &env, args, delayed, &mut counters, &mut worklist)
        {
            continue;
        }

        let (expanded, stats): (String, ExpandStats) =
            expand_repeated(trimmed, &env, args, delayed, MAX_EXPANSION_ROUNDS);
        counters.add_expand(stats);

        let emulated: String = apply_emulation(&expanded, &env, &emu_state, &mut counters);
        output_lines.push(emulated);
    }

    let output: String = output_lines.join("\n");
    let embedded_payloads: Vec<EmbeddedPayload> = extract_embedded(&output);
    let decrypted_stages: Vec<DecryptedStage> = recover_stages(&env);

    let mut recovered_layers: Vec<String> = Vec::new();
    recovered_layers.extend(
        embedded_payloads
            .iter()
            .map(|p: &EmbeddedPayload| p.content.clone()),
    );
    recovered_layers.extend(
        decrypted_stages
            .iter()
            .map(|s: &DecryptedStage| s.content.clone()),
    );
    let layer_refs: Vec<&str> = recovered_layers.iter().map(String::as_str).collect();
    let iocs: BatchIocReport = surface(&output, &layer_refs);

    BatchDeobReport {
        caret_escapes_removed: norm.caret_escapes_removed,
        line_continuations_joined: norm.line_continuations_joined,
        var_expansions: counters.var_expansions,
        delayed_expansions: counters.delayed_expansions,
        substring_expansions: counters.substring_expansions,
        substitution_expansions: counters.substitution_expansions,
        tilde_expansions: counters.tilde_expansions,
        arithmetic_folds: counters.arithmetic_folds,
        for_loops_unrolled: counters.for_loops_unrolled,
        if_branches_folded: counters.if_branches_folded,
        commands_emulated: counters.commands_emulated,
        embedded_payloads,
        decrypted_stages,
        iocs,
        output,
    }
}

fn pop_front(list: &mut Vec<String>) -> Option<String> {
    if list.is_empty() {
        None
    } else {
        Some(list.remove(0))
    }
}

fn coalesce_blocks(source: &str) -> Vec<String> {
    let raw: Vec<&str> = source.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let mut depth: isize = paren_delta(raw[i]);
        let mut combined: String = raw[i].to_owned();
        while depth > 0 && i + 1 < raw.len() {
            i += 1;
            combined.push('\n');
            combined.push_str(raw[i]);
            depth += paren_delta(raw[i]);
        }
        out.push(combined);
        i += 1;
    }
    out
}

fn paren_delta(line: &str) -> isize {
    let mut depth: isize = 0;
    let mut in_quote: bool = false;
    let mut prev: char = ' ';
    for c in line.chars() {
        match c {
            '"' => in_quote = !in_quote,
            '(' if !in_quote && prev != '%' && prev != '!' => depth += 1,
            ')' if !in_quote => depth -= 1,
            _ => {}
        }
        prev = c;
    }
    depth
}

fn handle_set_a(
    line: &str,
    env: &mut BTreeMap<String, String>,
    counters: &mut Counters,
    args: &[String],
    delayed: bool,
) -> Option<String> {
    let cap: regex::Captures<'_> = SET_A.captures(line)?;
    let name: String = cap
        .name("qname")
        .or_else(|| cap.name("name"))?
        .as_str()
        .trim()
        .to_ascii_uppercase();
    let expr_raw: &str = cap
        .name("qexpr")
        .or_else(|| cap.name("expr"))?
        .as_str()
        .trim();
    let (expr_expanded, stats): (String, ExpandStats) =
        expand_repeated(expr_raw, env, args, delayed, MAX_EXPANSION_ROUNDS);
    counters.add_expand(stats);
    match arith::eval(&expr_expanded, env) {
        Some(value) => {
            counters.arithmetic_folds += 1;
            env.insert(name.clone(), value.to_string());
            Some(format!("set {name}={value}"))
        }
        None => Some(format!("set /a {name}={expr_expanded}")),
    }
}

fn handle_set(
    line: &str,
    env: &mut BTreeMap<String, String>,
    counters: &mut Counters,
    args: &[String],
    delayed: bool,
) -> Option<String> {
    if SET_A.is_match(line) {
        return None;
    }
    let cap: regex::Captures<'_> = SET_PLAIN.captures(line)?;
    let name_raw: &str = cap.name("qname").or_else(|| cap.name("name"))?.as_str();
    let val_raw: &str = cap
        .name("qval")
        .or_else(|| cap.name("val"))
        .map_or("", |m: regex::Match<'_>| m.as_str());
    if name_raw.trim_start().starts_with('/') {
        return None;
    }
    let name: String = name_raw.trim().to_ascii_uppercase();
    let (val, stats): (String, ExpandStats) =
        expand_repeated(val_raw, env, args, delayed, MAX_EXPANSION_ROUNDS);
    counters.add_expand(stats);
    env.insert(name.clone(), val.clone());
    Some(format!("set {name}={val}"))
}

fn handle_for(
    line: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    delayed: bool,
    counters: &mut Counters,
    worklist: &mut Vec<String>,
) -> bool {
    let loop_def: Option<ForLoop> =
        parse_for_l(line).or_else(|| parse_for_f_string(line, env, args, delayed));
    let Some(def): Option<ForLoop> = loop_def else {
        return false;
    };
    let unrolled: Vec<String> = unroll(&def);
    if unrolled.is_empty() {
        return false;
    }
    counters.for_loops_unrolled += 1;
    prepend_all(worklist, unrolled);
    true
}

fn handle_if(
    line: &str,
    env: &BTreeMap<String, String>,
    args: &[String],
    delayed: bool,
    counters: &mut Counters,
    worklist: &mut Vec<String>,
) -> bool {
    let (expanded, stats): (String, ExpandStats) =
        expand_repeated(line, env, args, delayed, MAX_EXPANSION_ROUNDS);
    counters.add_expand(stats);
    match eval_if(&expanded) {
        IfOutcome::Taken(body) => {
            counters.if_branches_folded += 1;
            prepend_block(worklist, &body);
            true
        }
        IfOutcome::NotTaken(else_body) => {
            counters.if_branches_folded += 1;
            if let Some(body) = else_body {
                prepend_block(worklist, &body);
            }
            true
        }
        IfOutcome::Unknown => false,
    }
}

fn prepend_block(worklist: &mut Vec<String>, body: &str) {
    if body.trim().is_empty() {
        return;
    }
    let lines: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l: &&str| !l.is_empty())
        .map(str::to_owned)
        .collect();
    if !lines.is_empty() {
        prepend_all(worklist, lines);
    }
}

fn prepend_all(worklist: &mut Vec<String>, mut items: Vec<String>) {
    items.append(worklist);
    *worklist = items;
}

fn apply_emulation(
    line: &str,
    env: &BTreeMap<String, String>,
    state: &EmuState,
    counters: &mut Counters,
) -> String {
    match emulate(line, env, state) {
        EmuResult::Output(text) => {
            counters.commands_emulated += 1;
            if text == line {
                line.to_owned()
            } else {
                format!(
                    "{line}\nrem [emulated output] {}",
                    text.replace('\n', " | ")
                )
            }
        }
        EmuResult::Unresolved => line.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn folds_set_a_and_propagates() {
        let src: &str = "@echo off\nset /a X=2+3*4\nset /a Y=X*2\n";
        let r: BatchDeobReport = deobfuscate_batch(src, &[]);
        assert!(r.output.contains("set X=14"), "{}", r.output);
        assert!(r.output.contains("set Y=28"), "{}", r.output);
        assert_eq!(r.arithmetic_folds, 2);
    }

    #[test]
    fn varsplit_reassembles() {
        let src: &str =
            "@echo off\nsetlocal EnableDelayedExpansion\nset A=hel\nset B=lo\necho !A!!B!\n";
        let r: BatchDeobReport = deobfuscate_batch(src, &[]);
        assert!(r.output.contains("echo hello"), "{}", r.output);
        assert!(r.delayed_expansions >= 2);
    }

    #[test]
    fn for_l_unrolls_in_engine() {
        let src: &str = "@echo off\nfor /l %%i in (1,1,3) do echo line%%i\n";
        let r: BatchDeobReport = deobfuscate_batch(src, &[]);
        assert!(r.output.contains("echo line1"), "{}", r.output);
        assert!(r.output.contains("echo line3"), "{}", r.output);
        assert_eq!(r.for_loops_unrolled, 1);
    }

    #[test]
    fn caret_normalised_in_engine() {
        let src: &str = "@e^cho o^ff\necho^ ^hi\n";
        let r: BatchDeobReport = deobfuscate_batch(src, &[]);
        assert!(r.output.contains("echo hi"), "{}", r.output);
        assert!(r.caret_escapes_removed >= 2);
    }

    #[test]
    fn empty_input_no_panic() {
        let r: BatchDeobReport = deobfuscate_batch("", &[]);
        assert!(r.output.is_empty());
    }
}
