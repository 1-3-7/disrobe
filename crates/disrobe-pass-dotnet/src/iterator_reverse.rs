use std::collections::BTreeMap;

use crate::structurize::StructuredMethod;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

pub fn reconstruct_iterator_stubs(
    methods: &mut [StructuredMethod],
    hoisted_types: &BTreeMap<String, BTreeMap<String, String>>,
) -> u32 {
    let move_next: BTreeMap<String, String> = collect_move_next_inner(methods);
    if move_next.is_empty() {
        return 0;
    }
    let mut rebuilt: u32 = 0;
    for m in methods.iter_mut() {
        if declaring_type(&m.signature).is_some_and(is_state_machine_type) {
            continue;
        }
        let Some(params): Option<Vec<String>> = method_params(&m.signature) else {
            continue;
        };
        if let Some(body) = rebuild_iterator_stub(&m.body, &move_next, &params, hoisted_types) {
            m.body = body;
            rebuilt = rebuilt.saturating_add(1);
            continue;
        }
        if let Some((sig, body)) =
            rebuild_async_stub(&m.signature, &m.body, &move_next, &params, hoisted_types)
        {
            m.signature = sig;
            m.body = body;
            rebuilt = rebuilt.saturating_add(1);
        }
    }
    rebuilt
}

fn rebuild_async_stub(
    signature: &str,
    body: &str,
    move_next: &BTreeMap<String, String>,
    params: &[String],
    hoisted_types: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<(String, String)> {
    let sm_type: String = async_builder_state_machine(body)?;
    let inner: &String = move_next.get(&sm_type)?;
    if !inner.contains("await ") {
        return None;
    }
    let recovered: String = substitute_params(inner, params);
    if recovered.contains("this.") || recovered.contains(">d__") {
        return None;
    }
    let field_types: &BTreeMap<String, String> = hoisted_types.get(&sm_type)?;
    let decls: String = local_declarations(&recovered, params, field_types);
    let cleaned: String = qualify_task_statics(&clean_async_result_tail(&recovered)?);
    let pruned: String = drop_unused_local_decls(&format!("{decls}{cleaned}"));
    let async_sig: String = add_async_modifier(signature)?;
    let async_body: String = add_async_modifier(body)?;
    let new_body: String = rewrap_method(&async_body, &pruned);
    Some((async_sig, new_body))
}

fn drop_unused_local_decls(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut kept: Vec<String> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(name) = local_decl_name(line) {
            let used_below: bool = lines[idx + 1..]
                .iter()
                .any(|l: &&str| references_word(l, &name));
            if !used_below {
                continue;
            }
        }
        kept.push((*line).to_owned());
    }
    kept.join("\n")
}

fn local_decl_name(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let name: &str = inner.rsplit([' ', '\t']).next()?;
    let is_decl: bool = inner.split_whitespace().count() >= 2
        && name.starts_with("local")
        && name[5..].bytes().all(|b: u8| b.is_ascii_digit())
        && name.len() > 5;
    is_decl.then(|| name.to_owned())
}

fn references_word(line: &str, name: &str) -> bool {
    let mut rest: &str = line;
    while let Some(pos) = rest.find(name) {
        let before_ok: bool = pos == 0
            || !rest.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && rest.as_bytes()[pos - 1] != b'_';
        let after: &str = &rest[pos + name.len()..];
        let after_ok: bool = after
            .bytes()
            .next()
            .is_none_or(|b: u8| !b.is_ascii_alphanumeric() && b != b'_');
        if before_ok && after_ok {
            return true;
        }
        rest = &rest[pos + name.len()..];
    }
    false
}

fn async_builder_state_machine(body: &str) -> Option<String> {
    let constructs: bool = body.lines().any(|l: &str| {
        let t: &str = l.trim();
        t.contains("__builder).Start(") || t.contains("__builder = ") || t.contains(">d__")
    });
    if !constructs {
        return None;
    }
    body.lines().find_map(|line: &str| {
        let t: &str = line.trim();
        let decl: &str = t.split_whitespace().next()?;
        is_state_machine_type(decl).then(|| decl.to_owned())
    })
}

fn clean_async_result_tail(inner: &str) -> Option<String> {
    let mut lines: Vec<&str> = inner.lines().collect();
    while lines.last().is_some_and(|l: &&str| l.trim().is_empty()) {
        lines.pop();
    }
    if lines.last().map(|l: &&str| l.trim()) == Some("return;") {
        lines.pop();
    }
    let return_idx: usize = lines.len().checked_sub(1)?;
    let ret_local: &str = lines[return_idx]
        .trim()
        .strip_prefix("return ")?
        .strip_suffix(';')?;
    let bind_idx: usize = return_idx.checked_sub(1)?;
    let (lhs, rhs): (&str, &str) = lines[bind_idx]
        .trim()
        .strip_suffix(';')?
        .split_once(" = ")?;
    if lhs != ret_local {
        return None;
    }
    let indent: &str = {
        let l: &str = lines[bind_idx];
        &l[..l.len() - l.trim_start().len()]
    };
    let collapsed: String = format!("{indent}return {rhs};");
    let mut kept: Vec<String> = lines[..bind_idx]
        .iter()
        .map(|l: &&str| (*l).to_owned())
        .collect();
    kept.push(collapsed);
    Some(kept.join("\n"))
}

fn add_async_modifier(signature: &str) -> Option<String> {
    let header_idx: usize = signature.lines().position(|l: &str| {
        let t: &str = l.trim_start();
        !t.starts_with("//") && t.contains('(')
    })?;
    let lines: Vec<&str> = signature.lines().collect();
    let header: &str = lines[header_idx];
    if header.contains(" async ") {
        return Some(signature.to_owned());
    }
    let with_async: String = inject_async_keyword(header)?;
    let mut out: Vec<String> = lines.iter().map(|s: &&str| (*s).to_owned()).collect();
    out[header_idx] = with_async;
    Some(out.join("\n"))
}

fn inject_async_keyword(header: &str) -> Option<String> {
    for kw in ["static ", "private ", "public ", "protected ", "internal "] {
        if let Some(pos) = header.rfind(kw) {
            let insert_at: usize = pos + kw.len();
            return Some(format!(
                "{}async {}",
                &header[..insert_at],
                &header[insert_at..]
            ));
        }
    }
    None
}

fn collect_move_next_inner(methods: &[StructuredMethod]) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for m in methods {
        let Some(ty): Option<&str> = declaring_type(&m.signature) else {
            continue;
        };
        if !is_state_machine_type(ty) || !is_move_next(&m.signature) {
            continue;
        }
        if let Some(inner) = method_inner_block(&m.body) {
            map.insert(ty.to_owned(), inner);
        }
    }
    map
}

fn declaring_type(signature: &str) -> Option<&str> {
    let first: &str = signature.lines().next()?;
    let rest: &str = first.trim_start().strip_prefix("//")?.trim();
    rest.split_whitespace()
        .next()
        .filter(|s: &&str| !s.is_empty())
}

fn is_state_machine_type(full_name: &str) -> bool {
    let short: &str = full_name.rsplit('.').next().unwrap_or(full_name);
    short.contains(">d__")
}

fn qualify_task_statics(body: &str) -> String {
    const TASK_STATICS: [&str; 4] = ["Yield(", "Delay(", "WhenAll(", "WhenAny("];
    let mut out: String = body.to_owned();
    for needle in TASK_STATICS {
        let qualified: String = format!("Task.{needle}");
        out = replace_unqualified_call(&out, needle, &qualified);
    }
    out
}

fn replace_unqualified_call(body: &str, needle: &str, qualified: &str) -> String {
    let mut out: String = String::with_capacity(body.len());
    let mut rest: &str = body;
    while let Some(pos) = rest.find(needle) {
        let preceded_by_dot: bool = pos > 0 && rest.as_bytes()[pos - 1] == b'.';
        let preceded_by_ident: bool = pos > 0
            && (rest.as_bytes()[pos - 1].is_ascii_alphanumeric()
                || rest.as_bytes()[pos - 1] == b'_');
        out.push_str(&rest[..pos]);
        if preceded_by_dot || preceded_by_ident {
            out.push_str(needle);
        } else {
            out.push_str(qualified);
        }
        rest = &rest[pos + needle.len()..];
    }
    out.push_str(rest);
    out
}

fn is_move_next(signature: &str) -> bool {
    signature
        .lines()
        .any(|l: &str| l.contains("MoveNext(") && !l.trim_start().starts_with("//"))
}

fn method_params(signature: &str) -> Option<Vec<String>> {
    let header: &str = signature
        .lines()
        .find(|l: &&str| {
            let t: &str = l.trim_start();
            !t.starts_with("//") && !t.starts_with('\'') && t.contains('(')
        })
        .unwrap_or(signature);
    let open: usize = header.find('(')?;
    let close: usize = header.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner: &str = header[open + 1..close].trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    inner
        .split(',')
        .map(|p: &str| param_name(p.trim()))
        .collect()
}

fn param_name(decl: &str) -> Option<String> {
    let name: &str = decl.rsplit([' ', '\t']).next()?;
    (!name.is_empty() && is_identifier(name)).then(|| name.to_owned())
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c: char| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c: char| c == '_' || c.is_ascii_alphanumeric())
}

fn method_inner_block(body: &str) -> Option<String> {
    let open_line: usize = body.lines().position(|l: &str| l.trim() == "{")?;
    let lines: Vec<&str> = body.lines().collect();
    let mut depth: i32 = 0;
    let mut close_line: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(open_line) {
        depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
        depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
        if depth == 0 {
            close_line = Some(i);
            break;
        }
    }
    let close: usize = close_line?;
    if close <= open_line + 1 {
        return None;
    }
    Some(lines[open_line + 1..close].join("\n"))
}

fn constructed_state_machine(body: &str) -> Option<String> {
    body.lines().find_map(|line: &str| {
        let pos: usize = line.find("new <")?;
        let after: &str = &line[pos + "new ".len()..];
        let end: usize = after.find('(')?;
        let name: &str = &after[..end];
        is_state_machine_type(name).then(|| name.to_owned())
    })
}

fn rebuild_iterator_stub(
    body: &str,
    move_next: &BTreeMap<String, String>,
    params: &[String],
    hoisted_types: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<String> {
    if !returns_state_machine(body) {
        return None;
    }
    let sm_type: String = constructed_state_machine(body)?;
    let inner: &String = move_next.get(&sm_type)?;
    if !inner.contains("yield return") && !inner.contains("yield break") {
        return None;
    }
    let recovered: String = substitute_params(inner, params);
    if recovered.contains("this.") || recovered.contains(">d__") {
        return None;
    }
    let field_types: &BTreeMap<String, String> = hoisted_types.get(&sm_type)?;
    let decls: String = local_declarations(&recovered, params, field_types);
    let normalized: String = normalize_int_conditions(&recovered);
    Some(rewrap_method(body, &format!("{decls}{normalized}")))
}

fn normalize_int_conditions(inner: &str) -> String {
    inner
        .lines()
        .map(rewrite_int_condition_line)
        .collect::<Vec<String>>()
        .join("\n")
}

fn rewrite_int_condition_line(line: &str) -> String {
    let trimmed: &str = line.trim_start();
    let indent: &str = &line[..line.len() - trimmed.len()];
    let Some(rest): Option<&str> = trimmed.strip_prefix("if (") else {
        return line.to_owned();
    };
    let Some(cond): Option<&str> = rest.strip_suffix(')') else {
        return line.to_owned();
    };
    if is_boolean_condition(cond) {
        return line.to_owned();
    }
    format!("{indent}if (({cond}) != 0)")
}

fn is_boolean_condition(cond: &str) -> bool {
    const BOOL_MARKERS: [&str; 8] = ["==", "!=", "<", ">", "<=", ">=", "&&", "||"];
    cond.starts_with('!')
        || cond.contains(".IsCompleted")
        || BOOL_MARKERS.iter().any(|m: &&str| cond.contains(m))
}

fn local_declarations(
    inner: &str,
    params: &[String],
    field_types: &BTreeMap<String, String>,
) -> String {
    let mut decls: String = String::new();
    for (name, ty) in field_types {
        if params.iter().any(|p: &String| p == name) {
            continue;
        }
        if assigns_local(inner, name) {
            push_format(&mut decls, format_args!("    {ty} {name};\n"));
        }
    }
    decls
}

fn assigns_local(inner: &str, name: &str) -> bool {
    let needle: String = format!("{name} = ");
    inner.lines().any(|l: &str| l.trim().starts_with(&needle))
}

fn returns_state_machine(body: &str) -> bool {
    body.lines().any(|l: &str| {
        let t: &str = l.trim();
        t.starts_with("return new <") && t.contains(">d__")
    })
}

fn substitute_params(inner: &str, params: &[String]) -> String {
    let mut out: String = inner.to_owned();
    for p in params {
        out = out.replace(&format!("this.{p}"), p);
    }
    out
}

fn rewrap_method(original: &str, recovered_inner: &str) -> String {
    let header: String = original
        .lines()
        .take_while(|l: &&str| l.trim() != "{")
        .collect::<Vec<&str>>()
        .join("\n");
    format!("{header}\n{{\n{recovered_inner}\n}}\n")
}
