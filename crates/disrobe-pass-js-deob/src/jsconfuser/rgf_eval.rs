use std::collections::BTreeMap;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::{
    apply_splice_edits, decode_string_literal_at, find_paren_close, scan_balanced_brace,
    scan_balanced_bracket, skip_whitespace,
};

#[derive(Debug, Clone, Serialize)]
pub struct RgfEvalReversalResult {
    pub array_id: Option<String>,
    pub bodies_resolved: usize,
    pub wrappers_inlined: usize,
    pub runtime_payload_walls: usize,
    pub runtime_wall_reason: Option<String>,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_rgf_eval(source: &str) -> RgfEvalReversalResult {
    let Some(decl): Option<ArrayDecl> = find_rgf_eval_array(source) else {
        return passthrough(source, None, 0, None);
    };
    let entries: Vec<EvalEntry> = parse_eval_entries(source, &decl);
    if entries.is_empty() {
        return passthrough(source, Some(decl.array_id), 0, None);
    }

    let mut bodies: BTreeMap<usize, ReplFn> = BTreeMap::new();
    let mut runtime_walls: usize = 0;
    let mut runtime_wall_reason: Option<String> = None;
    for entry in &entries {
        match &entry.payload {
            PayloadKind::StaticCode(code) => {
                if let Some(repl) = extract_replacement(code) {
                    bodies.insert(entry.index, repl);
                } else {
                    runtime_walls += 1;
                }
            }
            PayloadKind::RuntimeDerived => {
                runtime_walls += 1;
                runtime_wall_reason.get_or_insert_with(runtime_derived_reason);
            }
        }
    }
    if bodies.is_empty() {
        return passthrough(
            source,
            Some(decl.array_id),
            runtime_walls,
            runtime_wall_reason,
        );
    }

    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let wrappers: Vec<Wrapper> = find_wrappers(source, &decl.array_id, &bodies);
    let mut inlined: usize = 0;
    for wrapper in &wrappers {
        let Some(repl): Option<&ReplFn> = bodies.get(&wrapper.index) else {
            continue;
        };
        let replacement: String = render_wrapper(&wrapper.name, repl);
        edits.push((wrapper.range.clone(), Some(replacement)));
        inlined += 1;
    }
    if inlined == 0 {
        return passthrough(
            source,
            Some(decl.array_id),
            runtime_walls,
            runtime_wall_reason,
        );
    }

    edits.push((decl.decl_range.clone(), Some(String::new())));
    if let Some(range) = decl.eval_fn_range.clone() {
        edits.push((range, Some(String::new())));
    }
    if let Some(range) = decl.integrity_decl_range.clone() {
        edits.push((range, Some(String::new())));
    }
    if let Some(range) = decl.integrity_fn_range.clone() {
        edits.push((range, Some(String::new())));
    }

    let (rewritten, _): (String, usize) = apply_splice_edits(source, &mut edits);
    RgfEvalReversalResult {
        array_id: Some(decl.array_id),
        bodies_resolved: bodies.len(),
        wrappers_inlined: inlined,
        runtime_payload_walls: runtime_walls,
        runtime_wall_reason,
        rewritten_source: rewritten,
    }
}

fn runtime_derived_reason() -> String {
    "RGF eval body resolves to a host-injected runtime global (e.g. atob(window.__k)); the injected value has no static definition anywhere in the file, so the body is runtime-only".to_owned()
}

fn passthrough(
    source: &str,
    array_id: Option<String>,
    runtime_walls: usize,
    runtime_wall_reason: Option<String>,
) -> RgfEvalReversalResult {
    RgfEvalReversalResult {
        array_id,
        bodies_resolved: 0,
        wrappers_inlined: 0,
        runtime_payload_walls: runtime_walls,
        runtime_wall_reason,
        rewritten_source: source.to_owned(),
    }
}

#[derive(Debug, Clone)]
struct ArrayDecl {
    array_id: String,
    eval_fn: String,
    decl_range: Range<usize>,
    entries_inner: Range<usize>,
    eval_fn_range: Option<Range<usize>>,
    integrity_decl_range: Option<Range<usize>>,
    integrity_fn_range: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
struct EvalEntry {
    index: usize,
    payload: PayloadKind,
}

#[derive(Debug, Clone)]
enum PayloadKind {
    StaticCode(String),
    RuntimeDerived,
}

#[derive(Debug, Clone)]
struct ReplFn {
    params: String,
    body: String,
}

#[derive(Debug, Clone)]
struct Wrapper {
    name: String,
    index: usize,
    range: Range<usize>,
}

fn find_rgf_eval_array(source: &str) -> Option<ArrayDecl> {
    let header_re: Regex = Regex::new(
        r"(?ms)(?:var|let|const)\s+([A-Za-z_$][\w$]*_rgf)\s*=\s*\[\s*([A-Za-z_$][\w$]*)\s*\(",
    )
    .ok()?;
    let cap: regex::Captures<'_> = header_re.captures(source)?;
    let array_id: String = cap.get(1)?.as_str().to_owned();
    let eval_fn: String = cap.get(2)?.as_str().to_owned();
    let whole: regex::Match<'_> = cap.get(0)?;
    let decl_start: usize = whole.start();

    let open_bracket_rel: usize = source[decl_start..whole.end()].rfind('[')?;
    let open_bracket: usize = decl_start + open_bracket_rel;
    let close_bracket: usize = scan_balanced_bracket(source, open_bracket + 1)?;
    let semi_end: usize = consume_semi(source, close_bracket + 1);

    let eval_fn_range: Option<Range<usize>> = find_named_fn_range(source, &eval_fn);
    let (integrity_decl_range, integrity_fn_range): (Option<Range<usize>>, Option<Range<usize>>) =
        find_integrity_ranges(source, &eval_fn);

    Some(ArrayDecl {
        array_id,
        eval_fn,
        decl_range: decl_start..semi_end,
        entries_inner: open_bracket + 1..close_bracket,
        eval_fn_range,
        integrity_decl_range,
        integrity_fn_range,
    })
}

fn consume_semi(source: &str, after: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = skip_whitespace(bytes, after);
    if i < bytes.len() && bytes[i] == b';' {
        i += 1;
    }
    i
}

fn find_named_fn_range(source: &str, name: &str) -> Option<Range<usize>> {
    let escaped: String = regex::escape(name);
    let re: Regex = Regex::new(&format!(r"(?ms)function\s+{escaped}\s*\(")).ok()?;
    let mat: regex::Match<'_> = re.find(source)?;
    let bytes: &[u8] = source.as_bytes();
    let open_paren: usize = mat.end() - 1;
    let close_paren: usize = find_paren_close(bytes, open_paren + 1)?;
    let body_open: usize = skip_whitespace(bytes, close_paren + 1);
    if body_open >= bytes.len() || bytes[body_open] != b'{' {
        return None;
    }
    let body_close: usize = scan_balanced_brace(source, body_open + 1)?;
    let end: usize = consume_semi(source, body_close + 1);
    Some(mat.start()..end)
}

fn find_integrity_ranges(
    source: &str,
    eval_fn: &str,
) -> (Option<Range<usize>>, Option<Range<usize>>) {
    let escaped: String = regex::escape(eval_fn);
    let body_re: Option<Regex> =
        Regex::new(&format!(r"(?ms)function\s+{escaped}\s*\([^)]*\)\s*\{{")).ok();
    let Some(body_re): Option<Regex> = body_re else {
        return (None, None);
    };
    let Some(mat): Option<regex::Match<'_>> = body_re.find(source) else {
        return (None, None);
    };
    let Some(body_close): Option<usize> = scan_balanced_brace(source, mat.end()) else {
        return (None, None);
    };
    let Some(body): Option<&str> = source.get(mat.end()..body_close) else {
        return (None, None);
    };
    let guard_re: Option<Regex> = Regex::new(r"if\s*\(\s*([A-Za-z_$][\w$]*)\s*\)").ok();
    let Some(guard_re): Option<Regex> = guard_re else {
        return (None, None);
    };
    let Some(guard): Option<regex::Captures<'_>> = guard_re.captures(body) else {
        return (None, None);
    };
    let Some(integrity_var): Option<&str> = guard.get(1).map(|m: regex::Match<'_>| m.as_str())
    else {
        return (None, None);
    };
    let decl_range: Option<Range<usize>> = find_var_decl_range(source, integrity_var);
    let setter_fn: Option<String> = find_integrity_setter_fn(source, integrity_var);
    let setter_range: Option<Range<usize>> =
        setter_fn.and_then(|name: String| find_named_fn_range(source, &name));
    (decl_range, setter_range)
}

fn find_var_decl_range(source: &str, var: &str) -> Option<Range<usize>> {
    let escaped: String = regex::escape(var);
    let re: Regex = Regex::new(&format!(
        r"(?ms)(?:var|let|const)\s+{escaped}\s*=\s*[A-Za-z_$][\w$]*\s*\([^;]*\)\s*;"
    ))
    .ok()?;
    let mat: regex::Match<'_> = re.find(source)?;
    Some(mat.start()..mat.end())
}

fn find_integrity_setter_fn(source: &str, integrity_var: &str) -> Option<String> {
    let escaped: String = regex::escape(integrity_var);
    let re: Regex = Regex::new(&format!(
        r"(?ms)(?:var|let|const)\s+{escaped}\s*=\s*([A-Za-z_$][\w$]*)\s*\("
    ))
    .ok()?;
    let cap: regex::Captures<'_> = re.captures(source)?;
    Some(cap.get(1)?.as_str().to_owned())
}

fn parse_eval_entries(source: &str, decl: &ArrayDecl) -> Vec<EvalEntry> {
    let inner: &str = match source.get(decl.entries_inner.clone()) {
        Some(slice) => slice,
        None => return Vec::new(),
    };
    let escaped: String = regex::escape(&decl.eval_fn);
    let call_re: Regex = match Regex::new(&format!(r"(?ms){escaped}\s*\(")) {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    let bytes: &[u8] = inner.as_bytes();
    let mut out: Vec<EvalEntry> = Vec::new();
    for (index, mat) in call_re.find_iter(inner).enumerate() {
        let open_paren: usize = mat.end() - 1;
        let arg_start: usize = skip_whitespace(bytes, open_paren + 1);
        if arg_start >= bytes.len() {
            break;
        }
        let payload: PayloadKind = if matches!(bytes[arg_start], b'"' | b'\'') {
            match decode_string_literal_at(bytes, arg_start) {
                Some((code, _)) => PayloadKind::StaticCode(code),
                None => PayloadKind::RuntimeDerived,
            }
        } else {
            PayloadKind::RuntimeDerived
        };
        out.push(EvalEntry { index, payload });
    }
    out
}

fn extract_replacement(code: &str) -> Option<ReplFn> {
    let inner_re: Regex =
        Regex::new(r"(?ms)function\s+[A-Za-z_$][\w$]*\s*\(\s*([^)]*)\)\s*\{").ok()?;
    let mut best: Option<ReplFn> = None;
    for cap in inner_re.captures_iter(code) {
        let Some(params_match): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let body_open: usize = whole.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(code, body_open + 1) else {
            continue;
        };
        let Some(body): Option<&str> = code.get(body_open + 1..body_close) else {
            continue;
        };
        let params: &str = params_match.as_str().trim();
        if params.contains('[') {
            continue;
        }
        let candidate: ReplFn = ReplFn {
            params: params.to_owned(),
            body: body.trim().to_owned(),
        };
        if !validate_fn(&candidate.params, &candidate.body) {
            continue;
        }
        best = Some(candidate);
    }
    best
}

fn validate_fn(params: &str, body: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("rgf-repl.js").unwrap_or_default();
    let wrapped: String = format!("(function({params}){{{body}}});");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn find_wrappers(source: &str, array_id: &str, bodies: &BTreeMap<usize, ReplFn>) -> Vec<Wrapper> {
    let id: String = regex::escape(array_id);
    let pattern: String = format!(
        r#"(?ms)function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{{\s*return\s+{id}\s*\[\s*(\d+)\s*\]\s*\[\s*["']apply["']\s*\]\s*\(\s*this\s*,\s*\[\s*{id}\s*,\s*arguments\s*\]\s*\)\s*;?\s*\}}"#
    );
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out: Vec<Wrapper> = Vec::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(name): Option<String> =
            cap.get(1).map(|m: regex::Match<'_>| m.as_str().to_owned())
        else {
            continue;
        };
        let Some(index): Option<usize> = cap
            .get(2)
            .and_then(|m: regex::Match<'_>| m.as_str().parse::<usize>().ok())
        else {
            continue;
        };
        if !bodies.contains_key(&index) {
            continue;
        }
        out.push(Wrapper {
            name,
            index,
            range: whole.start()..whole.end(),
        });
    }
    out
}

fn render_wrapper(name: &str, repl: &ReplFn) -> String {
    format!("function {name}({}) {{ {} }}", repl.params, repl.body)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const REAL_SHAPE: &str = "function __p_k(__p__flag = true) { return __p__flag; }\nvar __p_q_rgf_eval_integrity = __p_k();\nvar __p_e_rgf = [__p_p_rgf_eval(\"function __p_a_embedded(){var[__p_e_rgf,__p_b_args]=arguments;function __p_c_replacement(a,b){return a+b}return __p_c_replacement[\\\"apply\\\"](this,__p_b_args)}__p_a_embedded;\")];\nfunction add() {\n  return __p_e_rgf[0][\"apply\"](this, [__p_e_rgf, arguments]);\n}\nvar r = add(3, 4);\nfunction __p_p_rgf_eval(code) {\n  if (__p_q_rgf_eval_integrity) {\n    return eval(code);\n  }\n}\nconsole.log(r);";

    #[test]
    fn inlines_real_rgf_eval_wrapper() {
        let r: RgfEvalReversalResult = reverse_rgf_eval(REAL_SHAPE);
        assert_eq!(r.bodies_resolved, 1);
        assert_eq!(r.wrappers_inlined, 1);
        let out: &str = &r.rewritten_source;
        assert!(out.contains("function add(a,b)"), "got: {out}");
        assert!(out.contains("return a+b"), "got: {out}");
        assert!(
            !out.contains("_rgf_eval"),
            "eval scaffolding must be gone: {out}"
        );
        assert!(
            !out.contains("[\"apply\"](this, [__p_e_rgf"),
            "wrapper apply must be gone: {out}"
        );
    }

    #[test]
    fn extracts_replacement_params_and_body() {
        let code: &str = "function f(){var[arr,args]=arguments;function repl(x,y){return x*y}return repl[\"apply\"](this,args)}f;";
        let repl: ReplFn = extract_replacement(code).expect("repl");
        assert_eq!(repl.params, "x,y");
        assert!(repl.body.contains("return x*y"));
    }

    #[test]
    fn runtime_payload_is_walled() {
        let src: &str = "var z_rgf = [z_eval(atob(globalThis.__k))];\nfunction run(){ return z_rgf[0][\"apply\"](this, [z_rgf, arguments]); }\nfunction z_eval(code){ if(zi){ return eval(code); } }";
        let r: RgfEvalReversalResult = reverse_rgf_eval(src);
        assert_eq!(r.wrappers_inlined, 0);
        assert_eq!(r.runtime_payload_walls, 1);
        assert_eq!(r.rewritten_source, src);
    }
}
