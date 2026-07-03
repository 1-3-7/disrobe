use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::GzDecoder;

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_INFLATE: u64 = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_REPEAT: usize = 1 << 20;

#[derive(Debug, Clone)]
pub(crate) struct EvalEnv {
    vars: BTreeMap<String, String>,
    pub steps: Vec<String>,
    pub walls: Vec<String>,
    depth: usize,
    pub eval_depth: usize,
    max_eval_depth: usize,
}

impl Default for EvalEnv {
    fn default() -> Self {
        Self {
            vars: BTreeMap::new(),
            steps: Vec::new(),
            walls: Vec::new(),
            depth: 0,
            eval_depth: 0,
            max_eval_depth: MAX_DEPTH,
        }
    }
}

impl EvalEnv {
    pub(crate) fn with_eval_cap(max_eval_depth: usize) -> Self {
        Self {
            max_eval_depth,
            ..Self::default()
        }
    }

    fn note(&mut self, step: &str) {
        if self.steps.last().map(String::as_str) != Some(step) {
            self.steps.push(step.to_owned());
        }
    }

    fn wall(&mut self, why: String) {
        if !self.walls.contains(&why) {
            self.walls.push(why);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Resolved {
    Value(String),
    Runtime(String),
}

impl Resolved {
    fn is_runtime(&self) -> bool {
        matches!(self, Self::Runtime(_))
    }

    fn into_string(self) -> String {
        match self {
            Self::Value(s) | Self::Runtime(s) => s,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Value(s) | Self::Runtime(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DecodeResult {
    pub output: String,
}

pub(crate) fn evaluate(input: &str, env: &mut EvalEnv) -> DecodeResult {
    let (normalized, ifs_hit): (String, bool) = substitute_ifs(input);
    if ifs_hit {
        env.note("substitute-ifs");
    }
    let lines: Vec<String> = split_statements(&normalized);
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    for stmt in &lines {
        let trimmed: &str = stmt.trim();
        if trimmed.is_empty() {
            out_lines.push(stmt.clone());
            continue;
        }
        match eval_statement(trimmed, env) {
            Some(rendered) => {
                if !rendered.is_empty() {
                    out_lines.push(rendered);
                }
            }
            None => out_lines.push(stmt.clone()),
        }
        let total: usize = out_lines.iter().map(String::len).sum();
        if total > MAX_OUTPUT {
            env.wall("static evaluation exceeded output ceiling".to_owned());
            break;
        }
    }
    DecodeResult {
        output: out_lines.join("\n"),
    }
}

fn eval_statement(stmt: &str, env: &mut EvalEnv) -> Option<String> {
    let assignments: Vec<(String, String)> = split_leading_assignments(stmt);
    if !assignments.is_empty() {
        let rest_start: usize = assignment_prefix_len(stmt, assignments.len());
        let rest: &str = stmt[rest_start..].trim_start();
        if rest.is_empty() {
            for (name, raw) in &assignments {
                let resolved: Resolved = expand_word(raw, env);
                if resolved.is_runtime() {
                    env.wall(format!(
                        "variable `{name}` bound to runtime value; left symbolic"
                    ));
                } else {
                    env.note("resolve-assignment");
                }
                env.vars.insert(name.clone(), resolved.into_string());
            }
            return Some(stmt.to_owned());
        }
    }
    if let Some(inner) = strip_command_wrapper(stmt) {
        return eval_wrapped_command(&inner, env);
    }
    if let Some(rendered) = eval_standalone_printf(stmt, env) {
        return Some(rendered);
    }
    let resolved: Resolved = expand_word_full(stmt, env);
    if resolved.as_str() == stmt {
        return None;
    }
    if resolved.is_runtime() {
        return None;
    }
    env.note("expand-substitution");
    Some(resolved.into_string())
}

fn eval_standalone_printf(stmt: &str, env: &mut EvalEnv) -> Option<String> {
    let rest: &str = stmt.strip_prefix("printf ")?;
    let trimmed: &str = rest.trim();
    if trimmed.contains('%') || trimmed.contains('|') {
        return None;
    }
    let unquoted: &str = trimmed.trim_matches(|c: char| c == '\'' || c == '"');
    if !unquoted.contains("\\x")
        && !unquoted.contains("\\0")
        && !unquoted.bytes().any(|b: u8| b == b'\\')
    {
        return None;
    }
    let arg: Resolved = expand_word_raw(unquoted, env);
    if arg.is_runtime() {
        return None;
    }
    let decoded: String = decode_printf_escapes(arg.as_str());
    if decoded == trimmed {
        return None;
    }
    env.note("printf-escape-decode");
    Some(decoded)
}

fn eval_wrapped_command(inner: &str, env: &mut EvalEnv) -> Option<String> {
    let resolved: Resolved = expand_word(inner, env);
    if resolved.is_runtime() {
        env.wall("eval/shell -c body depends on runtime value; left symbolic".to_owned());
        return None;
    }
    let body: String = resolved.into_string();
    let next_eval: usize = env.eval_depth + 1;
    if next_eval > env.max_eval_depth {
        env.wall(format!(
            "eval depth {next_eval} exceeds cap {}; re-run with --allow-dynamic to peel further",
            env.max_eval_depth
        ));
        return None;
    }
    if env.depth >= MAX_DEPTH {
        env.wall("eval recursion depth ceiling reached".to_owned());
        return Some(body);
    }
    env.note("peel-eval");
    env.eval_depth = next_eval;
    env.depth += 1;
    let nested: DecodeResult = evaluate(&body, env);
    env.depth -= 1;
    Some(nested.output)
}

fn strip_command_wrapper(stmt: &str) -> Option<String> {
    let bytes: &[u8] = stmt.as_bytes();
    if let Some(rest) = match_keyword(bytes, b"eval") {
        return Some(stmt[rest..].trim().to_owned());
    }
    for prog in [b"bash".as_slice(), b"sh".as_slice()] {
        if let Some(after) = match_keyword(bytes, prog) {
            let tail: &str = stmt[after..].trim_start();
            if let Some(c_rest) = tail.strip_prefix("-c") {
                let arg: &str = c_rest.trim_start();
                if !arg.is_empty() {
                    return Some(arg.to_owned());
                }
            }
        }
    }
    None
}

fn match_keyword(bytes: &[u8], kw: &[u8]) -> Option<usize> {
    if bytes.len() < kw.len() {
        return None;
    }
    if &bytes[..kw.len()] != kw {
        return None;
    }
    match bytes.get(kw.len()) {
        Some(b' ' | b'\t') => Some(kw.len()),
        _ => None,
    }
}

fn expand_word_full(word: &str, env: &mut EvalEnv) -> Resolved {
    let expanded: Resolved = expand_word(word, env);
    if let Resolved::Value(ref decoded) = expanded
        && let Some(piped) = decode_pipeline(decoded, env)
    {
        return Resolved::Value(piped);
    }
    expanded
}

fn split_statements(input: &str) -> Vec<String> {
    let bytes: &[u8] = input.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut sq: bool = false;
    let mut dq: bool = false;
    let mut paren: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && !sq && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\'' && !dq {
            sq = !sq;
        } else if b == b'"' && !sq {
            dq = !dq;
        } else if !sq && !dq {
            match b {
                b'(' => paren += 1,
                b')' => paren = paren.saturating_sub(1),
                b';' | b'\n' if paren == 0 => {
                    out.push(input[start..i].to_owned());
                    start = i + 1;
                }
                b'&' | b'|' if paren == 0 && bytes.get(i + 1) == Some(&b) => {
                    out.push(input[start..i].to_owned());
                    i += 2;
                    start = i;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }
    if start < input.len() {
        out.push(input[start..].to_owned());
    } else if start == input.len() && start != 0 {
        out.push(String::new());
    }
    out
}

fn split_leading_assignments(stmt: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut rest: &str = stmt;
    loop {
        let trimmed: &str = rest.trim_start();
        let Some((name, value, consumed)) = parse_one_assignment(trimmed) else {
            break;
        };
        let leading: usize = rest.len() - trimmed.len();
        out.push((name, value));
        rest = &rest[leading + consumed..];
        if rest.starts_with(' ') || rest.is_empty() {
            break;
        }
    }
    out
}

fn parse_one_assignment(s: &str) -> Option<(String, String, usize)> {
    let bytes: &[u8] = s.as_bytes();
    if bytes.is_empty() || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return None;
    }
    let mut i: usize = 0;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i == 0 || i >= bytes.len() || bytes[i] != b'=' {
        return None;
    }
    let name: String = s[..i].to_owned();
    let value_start: usize = i + 1;
    let (value, end): (String, usize) = read_word(&bytes[value_start..]);
    Some((name, value, value_start + end))
}

fn read_word(bytes: &[u8]) -> (String, usize) {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    let mut sq: bool = false;
    let mut dq: bool = false;
    let mut paren: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && !sq {
            out.push(b);
            if i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if b == b'\'' && !dq {
            sq = !sq;
            out.push(b);
            i += 1;
            continue;
        }
        if b == b'"' && !sq {
            dq = !dq;
            out.push(b);
            i += 1;
            continue;
        }
        if !sq && !dq {
            if b == b'$' && bytes.get(i + 1) == Some(&b'(') {
                paren += 1;
                out.push(b);
                i += 1;
                continue;
            }
            if b == b'(' {
                paren += 1;
            } else if b == b')' {
                if paren == 0 {
                    break;
                }
                paren -= 1;
            } else if paren == 0 && matches!(b, b' ' | b'\t' | b';' | b'\n') {
                break;
            }
        }
        out.push(b);
        i += 1;
    }
    (String::from_utf8_lossy(&out).into_owned(), i)
}

fn assignment_prefix_len(stmt: &str, count: usize) -> usize {
    let mut rest: &str = stmt;
    let mut consumed_total: usize = 0;
    for _ in 0..count {
        let trimmed: &str = rest.trim_start();
        let leading: usize = rest.len() - trimmed.len();
        let Some((_, _, consumed)) = parse_one_assignment(trimmed) else {
            break;
        };
        consumed_total += leading + consumed;
        rest = &stmt[consumed_total..];
    }
    consumed_total
}

fn expand_word(word: &str, env: &mut EvalEnv) -> Resolved {
    expand_word_inner(word, env, true)
}

fn expand_word_raw(word: &str, env: &mut EvalEnv) -> Resolved {
    expand_word_inner(word, env, false)
}

fn expand_word_inner(word: &str, env: &mut EvalEnv, decode_backslash: bool) -> Resolved {
    let bytes: &[u8] = word.as_bytes();
    let mut out: String = String::with_capacity(word.len());
    let mut runtime: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' => {
                let (seg, end): (String, usize) = read_single_quote(bytes, i + 1);
                out.push_str(&seg);
                i = end;
            }
            b'"' => {
                let (seg, end, rt): (String, usize, bool) = read_double_quote(bytes, i + 1, env);
                out.push_str(&seg);
                runtime |= rt;
                i = end;
            }
            b'$' if bytes.get(i + 1) == Some(&b'\'') => {
                let (seg, end): (String, usize) = read_ansi_c(bytes, i + 2);
                out.push_str(&seg);
                i = end;
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                let (seg, end, rt): (String, usize, bool) = read_command_subst(bytes, i + 2, env);
                out.push_str(&seg);
                runtime |= rt;
                i = end;
            }
            b'$' if matches!(bytes.get(i + 1), Some(&b'{')) || is_var_start(bytes.get(i + 1)) => {
                let (seg, end, rt): (String, usize, bool) = read_var(bytes, i + 1, env);
                out.push_str(&seg);
                runtime |= rt;
                i = end;
            }
            b'\\' if i + 1 < bytes.len() => {
                if !decode_backslash {
                    out.push('\\');
                }
                out.push(bytes[i + 1] as char);
                i += 2;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    if runtime {
        Resolved::Runtime(out)
    } else {
        Resolved::Value(out)
    }
}

fn read_single_quote(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i: usize = start;
    let mut out: String = String::new();
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            return (out, i + 1);
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, i)
}

fn read_double_quote(bytes: &[u8], start: usize, env: &mut EvalEnv) -> (String, usize, bool) {
    let mut i: usize = start;
    let mut out: String = String::new();
    let mut runtime: bool = false;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'"' => return (out, i + 1, runtime),
            b'\\' if i + 1 < bytes.len() => {
                let n: u8 = bytes[i + 1];
                if !matches!(n, b'"' | b'\\' | b'$' | b'`') {
                    out.push('\\');
                }
                out.push(n as char);
                i += 2;
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                let (seg, end, rt): (String, usize, bool) = read_command_subst(bytes, i + 2, env);
                out.push_str(&seg);
                runtime |= rt;
                i = end;
            }
            b'$' if matches!(bytes.get(i + 1), Some(&b'{')) || is_var_start(bytes.get(i + 1)) => {
                let (seg, end, rt): (String, usize, bool) = read_var(bytes, i + 1, env);
                out.push_str(&seg);
                runtime |= rt;
                i = end;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    (out, i, runtime)
}

fn is_var_start(b: Option<&u8>) -> bool {
    matches!(b, Some(c) if c.is_ascii_alphabetic() || *c == b'_')
}

fn read_var(bytes: &[u8], start: usize, env: &mut EvalEnv) -> (String, usize, bool) {
    if bytes.get(start) == Some(&b'{') {
        let mut j: usize = start + 1;
        while j < bytes.len() && bytes[j] != b'}' {
            j += 1;
        }
        let name: &str = std::str::from_utf8(&bytes[start + 1..j]).unwrap_or("");
        let end: usize = if j < bytes.len() { j + 1 } else { j };
        return resolve_var(name, env, end, bytes);
    }
    let mut j: usize = start;
    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
        j += 1;
    }
    let name: &str = std::str::from_utf8(&bytes[start..j]).unwrap_or("");
    resolve_var(name, env, j, bytes)
}

fn resolve_var(name: &str, env: &mut EvalEnv, end: usize, bytes: &[u8]) -> (String, usize, bool) {
    let _ = bytes;
    if let Some(value) = env.vars.get(name).cloned() {
        env.note("expand-variable");
        return (value, end, false);
    }
    if is_runtime_var(name) {
        return (format!("${{{name}}}"), end, true);
    }
    (format!("${{{name}}}"), end, true)
}

fn is_runtime_var(name: &str) -> bool {
    matches!(
        name,
        "RANDOM" | "SECONDS" | "LINENO" | "BASHPID" | "PPID" | "UID" | "EUID" | "HOSTNAME"
    ) || name.chars().all(|c: char| c.is_ascii_digit())
        || name == "@"
        || name == "*"
        || name == "#"
        || name == "?"
}

fn read_ansi_c(bytes: &[u8], start: usize) -> (String, usize) {
    let mut i: usize = start;
    let mut out: String = String::new();
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\'' {
            return (out, i + 1);
        }
        if b == b'\\' && i + 1 < bytes.len() {
            let (ch, consumed): (Option<char>, usize) = decode_escape(&bytes[i + 1..]);
            if let Some(c) = ch {
                out.push(c);
            }
            i += 1 + consumed;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    (out, i)
}

fn decode_escape(rest: &[u8]) -> (Option<char>, usize) {
    if rest.is_empty() {
        return (None, 0);
    }
    match rest[0] {
        b'x' => {
            let mut j: usize = 1;
            while j < rest.len() && j <= 2 && rest[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j == 1 {
                return (Some('x'), 1);
            }
            let Some(v): Option<u8> = parse_escape_u8(&rest[1..j], 16) else {
                return (Some('\\'), 0);
            };
            (Some(v as char), j)
        }
        b'0'..=b'7' => {
            let mut j: usize = 0;
            while j < rest.len() && j < 3 && (b'0'..=b'7').contains(&rest[j]) {
                j += 1;
            }
            let Some(v): Option<u32> = parse_escape_u32(&rest[..j], 8) else {
                return (Some('\\'), 0);
            };
            (Some((v as u8) as char), j)
        }
        b'n' => (Some('\n'), 1),
        b't' => (Some('\t'), 1),
        b'r' => (Some('\r'), 1),
        b'\\' => (Some('\\'), 1),
        b'\'' => (Some('\''), 1),
        b'"' => (Some('"'), 1),
        b'a' => (Some('\x07'), 1),
        b'b' => (Some('\x08'), 1),
        b'f' => (Some('\x0c'), 1),
        b'v' => (Some('\x0b'), 1),
        b'e' => (Some('\x1b'), 1),
        other => (Some(other as char), 1),
    }
}

fn parse_escape_u8(bytes: &[u8], radix: u32) -> Option<u8> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    u8::from_str_radix(text, radix).ok()
}

fn parse_escape_u32(bytes: &[u8], radix: u32) -> Option<u32> {
    let text: &str = std::str::from_utf8(bytes).ok()?;
    u32::from_str_radix(text, radix).ok()
}

fn read_command_subst(bytes: &[u8], start: usize, env: &mut EvalEnv) -> (String, usize, bool) {
    let mut depth: usize = 1;
    let mut i: usize = start;
    let mut sq: bool = false;
    let mut dq: bool = false;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && !sq && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\'' && !dq {
            sq = !sq;
        } else if b == b'"' && !sq {
            dq = !dq;
        } else if !sq && !dq {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
        }
        i += 1;
    }
    let inner: &str = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
    let end: usize = if i < bytes.len() { i + 1 } else { i };
    let resolved: Option<String> = resolve_command_subst(inner, env);
    match resolved {
        Some(value) => {
            env.note("command-substitution");
            (value, end, false)
        }
        None => (format!("$({inner})"), end, true),
    }
}

fn resolve_command_subst(inner: &str, env: &mut EvalEnv) -> Option<String> {
    let trimmed: &str = inner.trim();
    if let Some(decoded) = decode_pipeline(trimmed, env) {
        return Some(decoded);
    }
    if let Some(rest) = trimmed.strip_prefix("echo ") {
        let arg: Resolved = expand_word(rest.trim(), env);
        if arg.is_runtime() {
            return None;
        }
        return Some(arg.into_string());
    }
    if let Some(rest) = trimmed.strip_prefix("printf ") {
        let unquoted: &str = rest.trim().trim_matches(|c: char| c == '\'' || c == '"');
        let arg: Resolved = expand_word_raw(unquoted, env);
        if arg.is_runtime() {
            return None;
        }
        return Some(decode_printf_escapes(arg.as_str()));
    }
    None
}

fn decode_pipeline(input: &str, env: &mut EvalEnv) -> Option<String> {
    let stages: Vec<&str> = split_pipeline(input);
    if stages.len() < 2 {
        return None;
    }
    let head: &str = stages[0].trim();
    let mut data: Vec<u8> = initial_data(head, env)?;
    let mut applied: bool = false;
    for (idx, stage) in stages[1..].iter().enumerate() {
        let cmd: &str = stage.trim();
        if let Some(next) = apply_decoder(cmd, &data, env) {
            data = next;
            applied = true;
        } else if applied {
            let text: String = String::from_utf8_lossy(&data).into_owned();
            let remaining: String = stages[idx + 1..]
                .iter()
                .map(|s: &&str| s.trim())
                .collect::<Vec<&str>>()
                .join(" | ");
            return Some(format!("{text} | {remaining}"));
        } else {
            return None;
        }
        if data.len() > MAX_OUTPUT {
            env.wall("pipeline output exceeded ceiling".to_owned());
            break;
        }
    }
    if !applied {
        return None;
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

fn split_pipeline(input: &str) -> Vec<&str> {
    let bytes: &[u8] = input.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut sq: bool = false;
    let mut dq: bool = false;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && !sq && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\'' && !dq {
            sq = !sq;
        } else if b == b'"' && !sq {
            dq = !dq;
        } else if b == b'|' && !sq && !dq && bytes.get(i + 1) != Some(&b'|') {
            out.push(&input[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&input[start..]);
    out
}

fn initial_data(head: &str, env: &mut EvalEnv) -> Option<Vec<u8>> {
    if let Some(rest) = head.strip_prefix("echo ") {
        let mut body: &str = rest.trim_start();
        let mut suppress_newline: bool = false;
        let mut interpret_escapes: bool = false;
        while body.starts_with('-') {
            let Some((flag, tail)): Option<(&str, &str)> = body.split_once(char::is_whitespace)
            else {
                break;
            };
            if !flag
                .chars()
                .skip(1)
                .all(|c: char| matches!(c, 'n' | 'e' | 'E'))
            {
                break;
            }
            suppress_newline |= flag.contains('n');
            interpret_escapes |= flag.contains('e');
            body = tail.trim_start();
        }
        let arg: Resolved = expand_word(body.trim(), env);
        if arg.is_runtime() {
            return None;
        }
        let payload: String = if interpret_escapes {
            decode_printf_escapes(arg.as_str())
        } else {
            arg.into_string()
        };
        let mut data: Vec<u8> = payload.into_bytes();
        if !suppress_newline {
            data.push(b'\n');
        }
        return Some(data);
    }
    if let Some(rest) = head.strip_prefix("printf ") {
        let trimmed: &str = rest.trim();
        let unquoted: &str = trimmed.trim_matches(|c: char| c == '\'' || c == '"');
        let arg: Resolved = expand_word_raw(unquoted, env);
        if arg.is_runtime() {
            return None;
        }
        return Some(decode_printf_escapes(arg.as_str()).into_bytes());
    }
    None
}

fn apply_decoder(cmd: &str, data: &[u8], env: &mut EvalEnv) -> Option<Vec<u8>> {
    let norm: String = cmd.split_whitespace().collect::<Vec<&str>>().join(" ");
    if norm.starts_with("base64 -d")
        || norm.starts_with("base64 --decode")
        || norm == "base64 -D"
        || norm.starts_with("base64 -di")
    {
        let cleaned: String = String::from_utf8_lossy(data)
            .chars()
            .filter(|c: &char| !c.is_whitespace())
            .collect();
        let raw: Vec<u8> = BASE64_STD.decode(cleaned.as_bytes()).ok()?;
        env.note("base64-decode");
        return Some(raw);
    }
    if norm.starts_with("xxd -r -p") || norm.starts_with("xxd -p -r") {
        let cleaned: String = String::from_utf8_lossy(data)
            .chars()
            .filter(|c: &char| c.is_ascii_hexdigit())
            .collect();
        let mut raw: Vec<u8> = Vec::with_capacity(cleaned.len() / 2);
        let cb: &[u8] = cleaned.as_bytes();
        let mut i: usize = 0;
        while i + 1 < cb.len() {
            let pair: &str = std::str::from_utf8(&cb[i..i + 2]).ok()?;
            raw.push(u8::from_str_radix(pair, 16).ok()?);
            i += 2;
        }
        env.note("xxd-hex-decode");
        return Some(raw);
    }
    if norm == "rev" {
        let mut raw: Vec<u8> = Vec::with_capacity(data.len());
        for line in String::from_utf8_lossy(data).split_inclusive('\n') {
            let (content, nl): (&str, bool) = match line.strip_suffix('\n') {
                Some(c) => (c, true),
                None => (line, false),
            };
            raw.extend(content.chars().rev().collect::<String>().into_bytes());
            if nl {
                raw.push(b'\n');
            }
        }
        env.note("rev");
        return Some(raw);
    }
    if norm == "tac" {
        let text: String = String::from_utf8_lossy(data).into_owned();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.reverse();
        env.note("tac");
        return Some(lines.join("\n").into_bytes());
    }
    if norm.starts_with("gunzip") || norm.starts_with("zcat") || norm.starts_with("gzip -d") {
        let dec: GzDecoder<&[u8]> = GzDecoder::new(data);
        let mut out: Vec<u8> = Vec::new();
        let produced: u64 = dec
            .take(MAX_INFLATE.saturating_add(1))
            .read_to_end(&mut out)
            .ok()? as u64;
        if produced > MAX_INFLATE {
            out.truncate(MAX_INFLATE as usize);
            env.note("gzip-inflate-capped");
        } else {
            env.note("gzip-inflate");
        }
        return Some(out);
    }
    if let Some(spec) = norm.strip_prefix("tr ") {
        if let Some(translated) = apply_tr(spec, data) {
            env.note("tr-translate");
            return Some(translated);
        }
        return None;
    }
    if norm == "base64" {
        env.note("base64-encode");
        return Some(BASE64_STD.encode(data).into_bytes());
    }
    if is_terminal_sink(&norm) {
        env.note("strip-terminal-sink");
        return Some(data.to_vec());
    }
    None
}

fn is_terminal_sink(norm: &str) -> bool {
    matches!(norm, "bash" | "sh" | "cat" | "more")
        || norm.starts_with("bash ")
        || norm.starts_with("sh ")
}

fn apply_tr(spec: &str, data: &[u8]) -> Option<Vec<u8>> {
    let parts: Vec<String> = tokenize_tr_args(spec);
    if parts.len() != 2 {
        return None;
    }
    let from: Vec<u8> = expand_tr_set(&parts[0]);
    let to: Vec<u8> = expand_tr_set(&parts[1]);
    if from.is_empty() || to.is_empty() {
        return None;
    }
    let mut map: BTreeMap<u8, u8> = BTreeMap::new();
    for (idx, &f) in from.iter().enumerate() {
        let t: u8 = *to.get(idx).or_else(|| to.last()).unwrap_or(&f);
        map.insert(f, t);
    }
    let out: Vec<u8> = data.iter().map(|b: &u8| *map.get(b).unwrap_or(b)).collect();
    Some(out)
}

fn tokenize_tr_args(spec: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes: &[u8] = spec.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote: Option<u8> = match bytes[i] {
            b'\'' | b'"' => Some(bytes[i]),
            _ => None,
        };
        if let Some(q) = quote {
            i += 1;
            let start: usize = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            out.push(spec[start..i].to_owned());
            if i < bytes.len() {
                i += 1;
            }
        } else {
            let start: usize = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push(spec[start..i].to_owned());
        }
    }
    out
}

fn expand_tr_set(set: &str) -> Vec<u8> {
    let bytes: &[u8] = set.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(set.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let (ch, consumed): (Option<char>, usize) = decode_escape(&bytes[i + 1..]);
            if let Some(c) = ch {
                out.push(c as u8);
            }
            i += 1 + consumed;
            continue;
        }
        if i + 2 < bytes.len() && bytes[i + 1] == b'-' && bytes[i + 2] != b'\\' {
            let lo: u8 = bytes[i];
            let hi: u8 = bytes[i + 2];
            if lo <= hi && (hi - lo) as usize <= MAX_REPEAT {
                for c in lo..=hi {
                    out.push(c);
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn decode_printf_escapes(s: &str) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: String = String::with_capacity(s.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let (ch, consumed): (Option<char>, usize) = decode_escape(&bytes[i + 1..]);
            if let Some(c) = ch {
                out.push(c);
            }
            i += 1 + consumed;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub(crate) fn substitute_ifs(input: &str) -> (String, bool) {
    let mut out: String = String::with_capacity(input.len());
    let bytes: &[u8] = input.as_bytes();
    let mut i: usize = 0;
    let mut hit: bool = false;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if bytes.get(i + 1) == Some(&b'{')
                && bytes.get(i + 2) == Some(&b'I')
                && bytes.get(i + 3) == Some(&b'F')
                && bytes.get(i + 4) == Some(&b'S')
                && bytes.get(i + 5) == Some(&b'}')
            {
                out.push(' ');
                i += 6;
                hit = true;
                continue;
            }
            if bytes.get(i + 1) == Some(&b'I')
                && bytes.get(i + 2) == Some(&b'F')
                && bytes.get(i + 3) == Some(&b'S')
                && !matches!(bytes.get(i + 4), Some(c) if c.is_ascii_alphanumeric() || *c == b'_')
            {
                out.push(' ');
                i += 4;
                hit = true;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, hit)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn run(input: &str) -> (String, EvalEnv) {
        let mut env: EvalEnv = EvalEnv::default();
        let r: DecodeResult = evaluate(input, &mut env);
        (r.output, env)
    }

    #[test]
    fn echo_base64_pipe_to_bash() {
        let b64: String = BASE64_STD.encode("whoami");
        let (out, env): (String, EvalEnv) = run(&format!("echo {b64} | base64 -d | bash"));
        assert!(out.contains("whoami"), "out={out}");
        assert!(env.steps.iter().any(|s: &String| s == "base64-decode"));
    }

    #[test]
    fn double_base64_chain() {
        let inner: String = BASE64_STD.encode("id\n");
        let outer: String = BASE64_STD.encode(format!("{inner}\n"));
        let (out, _): (String, EvalEnv) = run(&format!("echo {outer} | base64 -d | base64 -d"));
        assert!(out.contains("id"), "out={out}");
    }

    #[test]
    fn command_subst_assignment_then_call() {
        let b64: String = BASE64_STD.encode("whoami");
        let (out, _): (String, EvalEnv) = run(&format!("CMD=$(echo {b64} | base64 -d); $CMD"));
        assert!(out.contains("whoami"), "out={out}");
    }

    #[test]
    fn eval_concatenated_strings() {
        let (out, _): (String, EvalEnv) = run(r#"a=who; b=ami; eval "$a$b""#);
        assert!(out.contains("whoami"), "out={out}");
    }

    #[test]
    fn printf_octal_escapes() {
        let (out, _): (String, EvalEnv) = run(r#"printf '\167\150\157' | base64"#);
        let decoded: Vec<u8> = BASE64_STD.decode(out.trim()).expect("b64");
        assert_eq!(&decoded, b"who");
    }

    #[test]
    fn ansi_c_hex_quoting() {
        let (out, _): (String, EvalEnv) = run(r#"eval $'\x69\x64'"#);
        assert!(out.contains("id"), "out={out}");
    }

    #[test]
    fn runtime_var_is_walled() {
        let (_out, env): (String, EvalEnv) = run(r#"eval "$RANDOM_PAYLOAD""#);
        assert!(!env.walls.is_empty(), "expected wall, env={env:?}");
    }

    #[test]
    fn curl_subst_is_walled() {
        let (out, _env): (String, EvalEnv) = run(r#"eval "$(curl http://x)""#);
        assert!(out.contains("curl") || out.contains("$(curl"), "out={out}");
    }

    #[test]
    fn tr_rot13_decode() {
        let (out, _): (String, EvalEnv) = run("echo 'jubnzv' | tr 'a-zA-Z' 'n-za-mN-ZA-M'");
        assert!(out.contains("whoami"), "out={out}");
    }

    #[test]
    fn ifs_substitution() {
        let (sub, hit): (String, bool) = substitute_ifs("c${IFS}a${IFS}t");
        assert!(hit);
        assert_eq!(sub, "c a t");
    }

    #[test]
    fn clean_control_yields_nothing() {
        let (out, env): (String, EvalEnv) = run("echo hello world\nls -la");
        assert_eq!(out, "echo hello world\nls -la");
        assert!(env.steps.is_empty(), "steps={:?}", env.steps);
    }
}
