use std::collections::BTreeMap;

use crate::structurize::StructuredMethod;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug, Clone)]
struct LambdaBody {
    params: Vec<String>,
    return_expr: String,
}

pub fn inline_lambdas(methods: &mut [StructuredMethod]) -> u32 {
    let bodies: BTreeMap<String, LambdaBody> = collect_lambda_bodies(methods);
    let mut inlined: u32 = 0;
    for m in methods.iter_mut() {
        if is_lambda_method(&m.signature) {
            continue;
        }
        if !bodies.is_empty()
            && let Some(rewritten) = rewrite_capturing_factory(&m.body, &bodies)
        {
            m.body = chain_extension_calls(&rewritten);
            inlined = inlined.saturating_add(1);
            continue;
        }
        if !bodies.is_empty()
            && let Some(enclosing) = declared_method_name(&m.signature)
            && let Some(rewritten) = inline_cached_lambda_args(&m.body, &enclosing, &bodies)
        {
            m.body = chain_extension_calls(&rewritten);
            inlined = inlined.saturating_add(1);
            continue;
        }
        let rewoven: String = chain_extension_calls(&m.body);
        if rewoven != m.body {
            m.body = rewoven;
            inlined = inlined.saturating_add(1);
        }
    }
    inlined
}

pub(crate) const LINQ_EXTENSIONS: [&str; 14] = [
    "Select",
    "Where",
    "Sum",
    "Count",
    "ToList",
    "ToArray",
    "First",
    "FirstOrDefault",
    "Any",
    "All",
    "OrderBy",
    "OrderByDescending",
    "Aggregate",
    "Average",
];

fn chain_extension_calls(body: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut inside_body: bool = false;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if !inside_body {
            inside_body = trimmed.ends_with('{');
            out.push(line.to_owned());
            continue;
        }
        if trimmed.starts_with("//") {
            out.push(line.to_owned());
            continue;
        }
        out.push(chain_extension_calls_line(line));
    }
    out.join("\n")
}

fn chain_extension_calls_line(line: &str) -> String {
    let mut current: String = line.to_owned();
    while let Some(next) = rewrite_outermost_extension_call(&current) {
        current = next;
    }
    current
}

fn rewrite_outermost_extension_call(line: &str) -> Option<String> {
    for ext in LINQ_EXTENSIONS {
        let needle: String = format!("{ext}(");
        let mut search_from: usize = 0;
        while let Some(rel) = line[search_from..].find(&needle) {
            let pos: usize = search_from + rel;
            let is_member_call: bool = pos > 0 && line.as_bytes()[pos - 1] == b'.';
            let is_word_boundary: bool = pos == 0
                || !line.as_bytes()[pos - 1].is_ascii_alphanumeric()
                    && line.as_bytes()[pos - 1] != b'_';
            if !is_member_call
                && is_word_boundary
                && let Some(rewritten) = reattach_receiver(line, pos, ext)
            {
                return Some(rewritten);
            }
            search_from = pos + needle.len();
        }
    }
    None
}

fn reattach_receiver(line: &str, call_start: usize, ext: &str) -> Option<String> {
    let args_open: usize = call_start + ext.len();
    let args_close: usize = matching_paren(line, args_open)?;
    let args: &str = &line[args_open + 1..args_close];
    let (receiver, rest): (String, String) = split_first_arg(args)?;
    let new_call: String = if rest.is_empty() {
        format!("{receiver}.{ext}()")
    } else {
        format!("{receiver}.{ext}({rest})")
    };
    Some(format!(
        "{}{new_call}{}",
        &line[..call_start],
        &line[args_close + 1..]
    ))
}

fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: i32 = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_first_arg(args: &str) -> Option<(String, String)> {
    let mut depth: i32 = 0;
    let bytes: &[u8] = args.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                let first: String = args[..i].trim().to_owned();
                let rest: String = args[i + 1..].trim().to_owned();
                return (!first.is_empty()).then_some((first, rest));
            }
            _ => {}
        }
    }
    let first: String = args.trim().to_owned();
    (!first.is_empty()).then_some((first, String::new()))
}

fn lambda_arrow(lambda: &LambdaBody) -> String {
    let param_list: String = match lambda.params.as_slice() {
        [single] => single.clone(),
        many => format!("({})", many.join(", ")),
    };
    format!("{param_list} => {}", lambda.return_expr)
}

const CACHED_DELEGATE_PREFIX: &str = "<>9__";

fn inline_cached_lambda_args(
    body: &str,
    enclosing: &str,
    bodies: &BTreeMap<String, LambdaBody>,
) -> Option<String> {
    let mut out: String = String::with_capacity(body.len());
    let mut rest: &str = body;
    let mut hit: bool = false;
    while let Some(pos) = rest.find(CACHED_DELEGATE_PREFIX) {
        let after: &str = &rest[pos + CACHED_DELEGATE_PREFIX.len()..];
        let width: usize = after
            .bytes()
            .take_while(|b: &u8| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        out.push_str(&rest[..pos]);
        match bodies.get(&format!("<{enclosing}>b__{}", &after[..width])) {
            Some(lambda) => {
                out.push_str(&lambda_arrow(lambda));
                hit = true;
            }
            None => out.push_str(&rest[pos..pos + CACHED_DELEGATE_PREFIX.len() + width]),
        }
        rest = &after[width..];
    }
    out.push_str(rest);
    hit.then_some(out)
}

fn declared_method_name(signature: &str) -> Option<String> {
    let header: &str = signature_header_line(signature);
    let before_paren: &str = header.split('(').next()?;
    let ident: &str = before_paren.split_whitespace().next_back()?;
    let ident: &str = ident.split('<').next()?;
    is_identifier(ident).then(|| ident.to_owned())
}

fn collect_lambda_bodies(methods: &[StructuredMethod]) -> BTreeMap<String, LambdaBody> {
    let mut map: BTreeMap<String, LambdaBody> = BTreeMap::new();
    for m in methods {
        let Some(name): Option<&str> = lambda_method_name(&m.signature) else {
            continue;
        };
        let Some(params): Option<Vec<String>> = lambda_params(&m.signature) else {
            continue;
        };
        let Some(return_expr): Option<String> = single_return_expr(&m.body) else {
            continue;
        };
        map.insert(
            name.to_owned(),
            LambdaBody {
                params,
                return_expr,
            },
        );
    }
    map
}

fn is_lambda_method(signature: &str) -> bool {
    lambda_method_name(signature).is_some()
}

fn lambda_method_name(signature: &str) -> Option<&str> {
    let header: &str = signature_header_line(signature);
    let start: usize = header.find(">b__")?;
    let open_angle: usize = header[..start].rfind('<')?;
    let paren: usize = header[start..].find('(')? + start;
    let name: &str = header[open_angle..paren].trim();
    let last_segment: &str = name.rsplit([' ', '.']).next()?;
    last_segment.starts_with('<').then_some(last_segment)
}

fn signature_header_line(signature: &str) -> &str {
    signature
        .lines()
        .find(|l: &&str| {
            let t: &str = l.trim_start();
            !t.starts_with("//") && !t.starts_with('\'') && t.contains('(')
        })
        .unwrap_or(signature)
}

fn lambda_params(signature: &str) -> Option<Vec<String>> {
    let header: &str = signature_header_line(signature);
    let open: usize = header.find('(')?;
    let close: usize = header.rfind(')')?;
    if close <= open {
        return None;
    }
    let inner: &str = header[open + 1..close].trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let names: Option<Vec<String>> =
        crate::structurize::split_csharp_parameter_declarations(inner)?
            .into_iter()
            .map(|parameter: &str| param_name(parameter.trim()))
            .collect();
    names
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

fn single_return_expr(body: &str) -> Option<String> {
    let mut statements: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut seen_open: bool = false;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        let opens: i32 = i32::try_from(trimmed.matches('{').count()).unwrap_or(0);
        let closes: i32 = i32::try_from(trimmed.matches('}').count()).unwrap_or(0);
        if !seen_open {
            if opens > 0 {
                seen_open = true;
                depth += opens - closes;
            }
            continue;
        }
        depth += opens - closes;
        if depth <= 0 {
            break;
        }
        if !trimmed.is_empty() && trimmed != "{" {
            statements.push(trimmed);
        }
    }
    let [only]: [&str; 1] = statements.try_into().ok()?;
    let expr: &str = only.strip_prefix("return ")?.strip_suffix(';')?;
    (!expr.is_empty()).then(|| expr.to_owned())
}

fn rewrite_capturing_factory(body: &str, bodies: &BTreeMap<String, LambdaBody>) -> Option<String> {
    let lines: Vec<&str> = body.lines().collect();
    let return_idx: usize = lines
        .iter()
        .position(|l: &&str| l.trim_start().starts_with("return new <>c__DisplayClass"))?;
    let return_line: &str = lines[return_idx].trim();
    let lambda_ref: &str = return_line.strip_prefix("return new ")?.strip_suffix(';')?;
    let (display_type, lambda_name): (&str, &str) = lambda_ref.split_once(").<")?;
    let display_type: &str = display_type.strip_suffix("(")?;
    let lambda_marker: String = format!("<{lambda_name}");
    let lambda: &LambdaBody = bodies.get(lambda_marker.as_str())?;

    let captures: BTreeMap<String, String> = collect_captures(&lines, display_type);
    let mut expr: String = lambda.return_expr.clone();
    for (field, value) in &captures {
        expr = expr.replace(&format!("this.{field}"), value);
    }
    if expr.contains("this.") {
        return None;
    }
    let param_list: String = match lambda.params.as_slice() {
        [single] => single.clone(),
        many => format!("({})", many.join(", ")),
    };
    let indent: &str = leading_indent(lines[return_idx]);
    let capture_prefix: String = format!("new {display_type}().");
    let mut out: String = String::with_capacity(body.len());
    for (i, line) in lines.iter().enumerate() {
        if i == return_idx {
            push_format(
                &mut out,
                format_args!("{indent}return {param_list} => {expr};\n"),
            );
            continue;
        }
        if line.trim().starts_with(&capture_prefix) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

fn collect_captures(lines: &[&str], display_type: &str) -> BTreeMap<String, String> {
    let assign_prefix: String = format!("new {display_type}().");
    let mut captures: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix(&assign_prefix) else {
            continue;
        };
        let Some((field, value)): Option<(&str, &str)> = rest.split_once(" = ") else {
            continue;
        };
        if let Some(value) = value.strip_suffix(';') {
            captures.insert(field.trim().to_owned(), value.trim().to_owned());
        }
    }
    captures
}

fn leading_indent(line: &str) -> &str {
    let trimmed: &str = line.trim_start();
    &line[..line.len() - trimmed.len()]
}
