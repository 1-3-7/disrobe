use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPatternKind, Declaration, ExportDefaultDeclarationKind, FormalParameter, Function,
    Program, Statement, VariableDeclaration,
};
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use super::TypeScriptEmitStats;
use super::corpus::{DtsCorpus, DtsSymbolKind};
use super::flow_infer::{InferredType, TypeFlowReport, analyze};

#[derive(Debug, Clone, Serialize)]
pub struct TypeRecoveryResult {
    pub emitted_ts: String,
    pub stats: TypeScriptEmitStats,
    pub annotations: BTreeMap<String, String>,
}

#[must_use]
pub fn recover_types(source: &str, corpus: &DtsCorpus) -> TypeRecoveryResult {
    let flow: TypeFlowReport = analyze(source);
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("recover.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return TypeRecoveryResult {
            emitted_ts: source.to_owned(),
            stats: TypeScriptEmitStats::default(),
            annotations: BTreeMap::new(),
        };
    }
    let mut stats: TypeScriptEmitStats = TypeScriptEmitStats::default();
    let mut annotations: BTreeMap<String, String> = BTreeMap::new();
    collect_annotations(&parsed.program, &flow, corpus, &mut annotations, &mut stats);
    let emitted: String = emit_typescript(source, &annotations);
    stats.annotations_emitted = annotations.len();
    TypeRecoveryResult {
        emitted_ts: emitted,
        stats,
        annotations,
    }
}

fn collect_annotations(
    program: &Program<'_>,
    flow: &TypeFlowReport,
    corpus: &DtsCorpus,
    out: &mut BTreeMap<String, String>,
    stats: &mut TypeScriptEmitStats,
) {
    for stmt in &program.body {
        match stmt {
            Statement::VariableDeclaration(decl) => {
                annotate_var_decl(decl, flow, corpus, out, stats);
            }
            Statement::FunctionDeclaration(func) => {
                annotate_function(func, corpus, out, stats);
            }
            Statement::ExportNamedDeclaration(exp) => {
                if let Some(Declaration::VariableDeclaration(decl)) = &exp.declaration {
                    annotate_var_decl(decl, flow, corpus, out, stats);
                } else if let Some(Declaration::FunctionDeclaration(func)) = &exp.declaration {
                    annotate_function(func, corpus, out, stats);
                }
            }
            Statement::ExportDefaultDeclaration(exp) => {
                if let ExportDefaultDeclarationKind::FunctionDeclaration(func) = &exp.declaration {
                    annotate_function(func, corpus, out, stats);
                }
            }
            _ => {}
        }
    }
}

fn annotate_var_decl(
    decl: &VariableDeclaration<'_>,
    flow: &TypeFlowReport,
    corpus: &DtsCorpus,
    out: &mut BTreeMap<String, String>,
    stats: &mut TypeScriptEmitStats,
) {
    for d in &decl.declarations {
        let BindingPatternKind::BindingIdentifier(id) = &d.id.kind else {
            continue;
        };
        let name: String = id.name.as_str().to_owned();
        if let Some(sym) = corpus.lookup_global(&name) {
            out.insert(name.clone(), sym.signature.clone());
            stats.symbols_matched_via_corpus += 1;
            continue;
        }
        if let Some(t) = flow.bindings.get(&name) {
            let rendered: String = t.render();
            if matches!(t, InferredType::Unknown) {
                stats.unknown_symbols += 1;
            } else {
                stats.symbols_inferred_via_flow += 1;
            }
            out.insert(name, rendered);
        } else {
            stats.unknown_symbols += 1;
            out.insert(name, "unknown".to_owned());
        }
    }
}

fn annotate_function(
    func: &Function<'_>,
    corpus: &DtsCorpus,
    out: &mut BTreeMap<String, String>,
    stats: &mut TypeScriptEmitStats,
) {
    let Some(id) = &func.id else {
        return;
    };
    let name: String = id.name.as_str().to_owned();
    if let Some(sym) = corpus.lookup_global(&name)
        && matches!(sym.kind, DtsSymbolKind::Function)
    {
        out.insert(name, sym.signature.clone());
        stats.symbols_matched_via_corpus += 1;
        return;
    }
    let mut param_sig: Vec<String> = Vec::with_capacity(func.params.items.len());
    for (i, p) in func.params.items.iter().enumerate() {
        param_sig.push(format!("{}: {}", param_name(p, i), "unknown"));
    }
    let sig: String = format!("({}) => unknown", param_sig.join(", "));
    out.insert(name, sig);
    stats.unknown_symbols += 1;
}

fn param_name(param: &FormalParameter<'_>, fallback_index: usize) -> String {
    if let BindingPatternKind::BindingIdentifier(id) = &param.pattern.kind {
        return id.name.as_str().to_owned();
    }
    format!("p{fallback_index}")
}

fn emit_typescript(source: &str, annotations: &BTreeMap<String, String>) -> String {
    use std::fmt::Write;
    let mut header: String = String::with_capacity(source.len() + 256);
    header.push_str("// recovered TypeScript surface. annotations are best-effort\n");
    for (name, ty) in annotations {
        let _ = writeln!(header, "declare const {name}: {ty};");
    }
    header.push('\n');
    header.push_str(source);
    header
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn recovers_literal_types_from_simple_source() {
        let src: &str = "var x = 'hi'; var n = 42; var b = true;";
        let res: TypeRecoveryResult = recover_types(src, &DtsCorpus::well_known());
        assert!(res.annotations.contains_key("x"));
        assert!(res.annotations.contains_key("n"));
        assert!(res.annotations.contains_key("b"));
        assert!(res.emitted_ts.contains("declare const x:"));
        assert_eq!(res.stats.annotations_emitted, 3);
    }

    #[test]
    fn corpus_match_overrides_inference() {
        let src: &str = "var useState = function(s){return [s, function(){}];};";
        let res: TypeRecoveryResult = recover_types(src, &DtsCorpus::well_known());
        let annotation: &String = res.annotations.get("useState").expect("got useState");
        assert!(
            annotation.contains("=>"),
            "expected corpus signature, got {annotation}"
        );
        assert_eq!(res.stats.symbols_matched_via_corpus, 1);
    }

    #[test]
    fn handles_parse_error_gracefully() {
        let src: &str = "var = @@@ not valid";
        let res: TypeRecoveryResult = recover_types(src, &DtsCorpus::new());
        assert_eq!(res.emitted_ts, src);
    }
}
