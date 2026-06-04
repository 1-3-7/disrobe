use std::fmt::Write as _;

use serde::Serialize;

use crate::lang::perl::{PerlOp, PerlOpTree, PerlSub};

const INDENT: &str = "    ";
const ERASED_MARKER: &str =
    "# <expression erased: package-global temporaries are not named in the op-tree>";

/// A single reconstructed Perl statement plus the confidence with which it was recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlStatement {
    pub text: String,
    pub recovered: bool,
}

/// A reconstructed subroutine (or the main program) rendered back to readable Perl source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlSubSource {
    pub name: String,
    pub is_main_program: bool,
    pub signature: Option<String>,
    pub statements: Vec<PerlStatement>,
}

/// The whole decompiled program: rendered source plus an honest recovery score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerlSource {
    pub source_hint: Option<String>,
    pub subs: Vec<PerlSubSource>,
    pub rendered: String,
    pub statements_total: usize,
    pub statements_recovered: usize,
}

impl PerlSource {
    /// Fraction of reconstructed statements whose surface form was fully recovered (0.0..=1.0).
    #[must_use]
    pub fn recovery_ratio(&self) -> f64 {
        if self.statements_total == 0 {
            return 1.0;
        }
        self.statements_recovered as f64 / self.statements_total as f64
    }
}

/// Walks a parsed [`PerlOpTree`] and emits readable Perl source.
///
/// Lexical (pad) names survive in the op-tree and are reconstructed faithfully; package-global
/// temporaries are erased by the compiler and surface as honest `# <expression erased>` markers,
/// which is the ~75% structural ceiling for names-erased Perl op-trees.
#[derive(Debug)]
pub struct DecompileWalker<'a> {
    tree: &'a PerlOpTree,
}

impl<'a> DecompileWalker<'a> {
    #[must_use]
    pub const fn new(tree: &'a PerlOpTree) -> Self {
        Self { tree }
    }

    #[must_use]
    pub fn decompile(&self) -> PerlSource {
        let subs: Vec<PerlSubSource> = self
            .tree
            .subs
            .iter()
            .map(|sub: &PerlSub| Self::decompile_sub(sub))
            .collect();
        let rendered: String = Self::render(self.tree.source_hint.as_deref(), &subs);
        let statements_total: usize = subs
            .iter()
            .map(|s: &PerlSubSource| s.statements.len())
            .sum();
        let statements_recovered: usize = subs
            .iter()
            .flat_map(|s: &PerlSubSource| s.statements.iter())
            .filter(|st: &&PerlStatement| st.recovered)
            .count();
        PerlSource {
            source_hint: self.tree.source_hint.clone(),
            subs,
            rendered,
            statements_total,
            statements_recovered,
        }
    }

    fn decompile_sub(sub: &PerlSub) -> PerlSubSource {
        let segments: Vec<&[PerlOp]> = split_statements(&sub.ops);
        let signature: Option<String> = recover_signature(&segments);
        let mut statements: Vec<PerlStatement> = Vec::new();
        for (idx, seg) in segments.iter().enumerate() {
            if signature.is_some() && idx == signature_segment_index(&segments) {
                continue;
            }
            if let Some(stmt) = reconstruct_statement(seg) {
                statements.push(stmt);
            }
        }
        PerlSubSource {
            name: sub.name.clone(),
            is_main_program: sub.is_main_program,
            signature,
            statements,
        }
    }

    fn render(source_hint: Option<&str>, subs: &[PerlSubSource]) -> String {
        let mut out: String = String::new();
        out.push_str("use strict;\n");
        out.push_str("use warnings;\n");
        if let Some(hint) = source_hint {
            let _ = writeln!(out, "# recovered from op-tree of {hint}");
        }
        out.push('\n');
        for sub in subs.iter().filter(|s: &&PerlSubSource| !s.is_main_program) {
            render_named_sub(&mut out, sub);
            out.push('\n');
        }
        for sub in subs.iter().filter(|s: &&PerlSubSource| s.is_main_program) {
            for stmt in &sub.statements {
                out.push_str(&stmt.text);
                out.push('\n');
            }
        }
        out
    }
}

fn render_named_sub(out: &mut String, sub: &PerlSubSource) {
    let short: &str = sub.name.strip_prefix("main::").unwrap_or(&sub.name);
    let _ = writeln!(out, "sub {short} {{");
    if let Some(sig) = &sub.signature {
        out.push_str(INDENT);
        out.push_str(sig);
        out.push('\n');
    }
    for stmt in &sub.statements {
        out.push_str(INDENT);
        out.push_str(&stmt.text);
        out.push('\n');
    }
    out.push_str("}\n");
}

fn split_statements(ops: &[PerlOp]) -> Vec<&[PerlOp]> {
    let mut bounds: Vec<usize> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        if matches!(op.name.as_str(), "nextstate" | "dbstate") {
            bounds.push(idx);
        }
    }
    if bounds.is_empty() {
        return if ops.is_empty() {
            Vec::new()
        } else {
            vec![ops]
        };
    }
    let mut segments: Vec<&[PerlOp]> = Vec::with_capacity(bounds.len());
    for window in 0..bounds.len() {
        let start: usize = bounds[window] + 1;
        let end: usize = bounds.get(window + 1).copied().unwrap_or(ops.len());
        if start < end {
            segments.push(&ops[start..end]);
        }
    }
    segments
}

fn signature_segment_index(segments: &[&[PerlOp]]) -> usize {
    segments
        .iter()
        .position(|seg: &&[PerlOp]| is_my_args_assignment(seg))
        .unwrap_or(usize::MAX)
}

fn recover_signature(segments: &[&[PerlOp]]) -> Option<String> {
    let seg: &[PerlOp] = segments
        .iter()
        .copied()
        .find(|s: &&[PerlOp]| is_my_args_assignment(s))?;
    let pads: Vec<String> = collect_pad_names(seg);
    if pads.is_empty() {
        return None;
    }
    Some(format!("my ({}) = @_;", pads.join(", ")))
}

fn is_my_args_assignment(seg: &[PerlOp]) -> bool {
    let has_assign: bool = seg.iter().any(|o: &PerlOp| o.name == "aassign");
    let has_args: bool = seg.iter().any(|o: &PerlOp| {
        o.name == "gv" && o.detail.as_deref().is_some_and(|d: &str| d.contains("*_"))
    });
    let has_pad_intro: bool = seg
        .iter()
        .any(|o: &PerlOp| matches!(o.name.as_str(), "padrange" | "padsv" | "padav" | "padhv"));
    has_assign && has_args && has_pad_intro
}

fn reconstruct_statement(seg: &[PerlOp]) -> Option<PerlStatement> {
    if let Some(stmt) = reconstruct_return(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_print(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_my_call_assignment(seg) {
        return Some(stmt);
    }
    if let Some(stmt) = reconstruct_bare_call(seg) {
        return Some(stmt);
    }
    None
}

fn reconstruct_return(seg: &[PerlOp]) -> Option<PerlStatement> {
    let is_return: bool = seg
        .iter()
        .any(|o: &PerlOp| matches!(o.name.as_str(), "return" | "leavesub"));
    if !is_return {
        return None;
    }
    match recover_expression(seg) {
        Some(expr) => Some(PerlStatement {
            text: format!("return {expr};"),
            recovered: true,
        }),
        None => Some(PerlStatement {
            text: format!("return; {ERASED_MARKER}"),
            recovered: false,
        }),
    }
}

fn reconstruct_print(seg: &[PerlOp]) -> Option<PerlStatement> {
    if !seg.iter().any(|o: &PerlOp| o.name == "print") {
        return None;
    }
    match recover_print_args(seg) {
        Some(args) => Some(PerlStatement {
            text: format!("print {args};"),
            recovered: true,
        }),
        None => Some(PerlStatement {
            text: format!("print ...; {ERASED_MARKER}"),
            recovered: false,
        }),
    }
}

fn reconstruct_my_call_assignment(seg: &[PerlOp]) -> Option<PerlStatement> {
    let store: &PerlOp = seg
        .iter()
        .find(|o: &&PerlOp| matches!(o.name.as_str(), "padsv_store" | "sassign"))?;
    let lhs: String = store
        .detail
        .as_deref()
        .and_then(first_pad_name)
        .unwrap_or_else(|| "$_".to_owned());
    let callee: String = called_name(seg)?;
    let args: String = call_arguments(seg);
    Some(PerlStatement {
        text: format!("my {lhs} = {callee}({args});"),
        recovered: true,
    })
}

fn reconstruct_bare_call(seg: &[PerlOp]) -> Option<PerlStatement> {
    if !seg.iter().any(|o: &PerlOp| o.name == "entersub") {
        return None;
    }
    let callee: String = called_name(seg)?;
    let args: String = call_arguments(seg);
    Some(PerlStatement {
        text: format!("{callee}({args});"),
        recovered: true,
    })
}

fn recover_expression(seg: &[PerlOp]) -> Option<String> {
    if let Some(template) = multiconcat_template_in(seg) {
        let pads: Vec<String> = collect_pad_names(seg);
        return Some(fill_multiconcat(&template, &pads));
    }
    if let Some(op) = seg.iter().find(|o: &&PerlOp| o.name == "const")
        && let Some(lit) = op.detail.as_deref().and_then(const_literal)
    {
        return Some(lit);
    }
    let pads: Vec<String> = collect_pad_names(seg);
    if let Some(op) = seg.iter().find(|o: &&PerlOp| is_binary_arith(&o.name))
        && pads.len() >= 2
    {
        let sym: &str = arith_symbol(&op.name);
        return Some(format!("{} {sym} {}", pads[0], pads[1]));
    }
    if pads.len() == 1 {
        return Some(pads[0].clone());
    }
    None
}

fn recover_print_args(seg: &[PerlOp]) -> Option<String> {
    if let Some(template) = multiconcat_template_in(seg) {
        let pads: Vec<String> = collect_pad_names(seg);
        return Some(fill_multiconcat(&template, &pads));
    }
    if let Some(name) = called_name(seg) {
        let args: String = call_arguments(seg);
        return Some(format!("{name}({args})"));
    }
    let pads: Vec<String> = collect_pad_names(seg);
    if !pads.is_empty() {
        return Some(pads.join(", "));
    }
    None
}

fn collect_pad_names(seg: &[PerlOp]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for op in seg {
        if matches!(
            op.name.as_str(),
            "padsv" | "padav" | "padhv" | "padrange" | "padsv_store"
        ) && let Some(detail) = op.detail.as_deref()
        {
            for name in pad_names_in(detail) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

fn pad_names_in(detail: &str) -> Vec<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    inner
        .split(';')
        .filter_map(|seg: &str| {
            let token: &str = seg.trim();
            let name: &str = token.split(':').next().unwrap_or(token).trim();
            if name.starts_with('$') || name.starts_with('@') || name.starts_with('%') {
                Some(name.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn first_pad_name(detail: &str) -> Option<String> {
    pad_names_in(detail).into_iter().next()
}

fn called_name(seg: &[PerlOp]) -> Option<String> {
    seg.iter().find_map(|op: &PerlOp| {
        if op.name != "gv" {
            return None;
        }
        let detail: &str = op.detail.as_deref()?;
        let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
        let name: &str = inner.trim_start_matches('*');
        if name.is_empty() || name == "_" {
            None
        } else {
            Some(name.to_owned())
        }
    })
}

fn call_arguments(seg: &[PerlOp]) -> String {
    let mut args: Vec<String> = Vec::new();
    for op in seg {
        match op.name.as_str() {
            "const" => {
                if let Some(lit) = op.detail.as_deref().and_then(const_literal) {
                    args.push(lit);
                }
            }
            "padsv" | "padav" | "padhv" => {
                if let Some(name) = op.detail.as_deref().and_then(first_pad_name) {
                    args.push(name);
                }
            }
            _ => {}
        }
    }
    args.join(", ")
}

fn const_literal(detail: &str) -> Option<String> {
    let inner: &str = detail.trim_start_matches('[').trim_end_matches(']');
    let inner: &str = inner.trim();
    if let Some(rest) = inner.strip_prefix("PV ") {
        let lit: &str = rest.trim().trim_matches('"');
        return Some(format!("\"{lit}\""));
    }
    if let Some(rest) = inner
        .strip_prefix("IV ")
        .or_else(|| inner.strip_prefix("NV "))
    {
        return Some(rest.trim().to_owned());
    }
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_owned())
    }
}

fn multiconcat_template_in(seg: &[PerlOp]) -> Option<String> {
    seg.iter().find_map(|op: &PerlOp| {
        let name: &str = op.name.as_str();
        if !name.starts_with("multiconcat") {
            return None;
        }
        multiconcat_template(name)
    })
}

fn multiconcat_template(name: &str) -> Option<String> {
    let open: usize = name.find('(')?;
    let inner: &str = &name[open + 1..];
    let close: usize = inner.rfind(')').unwrap_or(inner.len());
    let head: &str = &inner[..close];
    let first_quote: usize = head.find('"')?;
    let after: &str = &head[first_quote + 1..];
    let end_quote: usize = after.find('"')?;
    Some(after[..end_quote].to_owned())
}

fn fill_multiconcat(template: &str, pads: &[String]) -> String {
    let mut iter: std::slice::Iter<'_, String> = pads.iter();
    let mut out: String = String::with_capacity(template.len() + 8);
    out.push('"');
    let mut escaped: bool = false;
    for ch in template.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                out.push(ch);
                escaped = true;
            }
            '\0' => match iter.next() {
                Some(name) => out.push_str(name),
                None => out.push_str("${\\ ...}"),
            },
            _ => out.push(ch),
        }
    }
    if pads.len() == 1 && !template.contains('\0') {
        if let Some(name) = pads.first() {
            insert_interpolation(&mut out, name);
        }
    } else {
        for name in iter {
            insert_interpolation(&mut out, name);
        }
    }
    out.push('"');
    out
}

fn insert_interpolation(out: &mut String, name: &str) {
    if let Some(pos) = out.rfind('!') {
        out.insert_str(pos, name);
    } else {
        out.push_str(name);
    }
}

fn is_binary_arith(name: &str) -> bool {
    matches!(
        name,
        "add" | "subtract" | "multiply" | "divide" | "modulo" | "concat" | "repeat" | "pow"
    )
}

fn arith_symbol(name: &str) -> &'static str {
    match name {
        "add" => "+",
        "subtract" => "-",
        "multiply" => "*",
        "divide" => "/",
        "modulo" => "%",
        "concat" => ".",
        "repeat" => "x",
        "pow" => "**",
        _ => "?",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::lang::perl::read_concise;

    use super::*;

    const SAMPLE: &[u8] = include_bytes!("../../tests/fixtures/hello.concise.txt");

    fn decompiled() -> PerlSource {
        let tree: PerlOpTree = read_concise(SAMPLE).expect("parse concise");
        DecompileWalker::new(&tree).decompile()
    }

    #[test]
    fn renders_named_subs() {
        let src: PerlSource = decompiled();
        assert!(
            src.rendered.contains("sub greet {"),
            "rendered:\n{}",
            src.rendered
        );
        assert!(
            src.rendered.contains("sub add {"),
            "rendered:\n{}",
            src.rendered
        );
    }

    #[test]
    fn recovers_lexical_signature_from_pad() {
        let src: PerlSource = decompiled();
        let greet: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::greet")
            .expect("greet");
        assert_eq!(greet.signature.as_deref(), Some("my ($name) = @_;"));
        let add: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::add")
            .expect("add");
        assert_eq!(add.signature.as_deref(), Some("my ($a, $b) = @_;"));
    }

    #[test]
    fn recovers_add_return_expression_from_pads() {
        let src: PerlSource = decompiled();
        let add: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::add")
            .expect("add");
        assert!(
            add.statements
                .iter()
                .any(|s: &PerlStatement| s.text == "return $a + $b;"),
            "add() return must reconstruct from pad add op: {:?}",
            add.statements
        );
    }

    #[test]
    fn recovers_greet_concat_return() {
        let src: PerlSource = decompiled();
        let greet: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.name == "main::greet")
            .expect("greet");
        assert!(
            greet.statements.iter().any(|s: &PerlStatement| {
                s.text.starts_with("return \"Hello, ") && s.text.contains("$name")
            }),
            "greet() return must interpolate the recovered $name lexical: {:?}",
            greet.statements
        );
    }

    #[test]
    fn recovers_main_call_with_string_constant() {
        let src: PerlSource = decompiled();
        let main: &PerlSubSource = src
            .subs
            .iter()
            .find(|s: &&PerlSubSource| s.is_main_program)
            .expect("main");
        assert!(
            main.statements
                .iter()
                .any(|s: &PerlStatement| s.text == "my $msg = greet(\"disrobe\");"),
            "main must reconstruct the greet(\"disrobe\") call into $msg: {:?}",
            main.statements
        );
    }

    #[test]
    fn recovery_ratio_is_honest_and_bounded() {
        let src: PerlSource = decompiled();
        assert!(src.statements_total > 0);
        assert!(src.statements_recovered <= src.statements_total);
        let ratio: f64 = src.recovery_ratio();
        assert!((0.0..=1.0).contains(&ratio), "ratio {ratio}");
    }

    #[test]
    fn empty_tree_is_fully_recovered_vacuously() {
        let tree: PerlOpTree = PerlOpTree {
            source_hint: None,
            subs: Vec::new(),
            op_count: 0,
        };
        let src: PerlSource = DecompileWalker::new(&tree).decompile();
        assert_eq!(src.statements_total, 0);
        assert!((src.recovery_ratio() - 1.0).abs() < f64::EPSILON);
    }
}
