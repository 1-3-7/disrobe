//! Async / iterator state-machine reversal at the rendered-method level.
//!
//! Rewrites a recovered `MoveNext` body back toward its original `async`/`yield` source by folding
//! the compiler's lowering idioms: `yield return`/`yield break`, `await`, hoisted-field-to-local
//! renaming, and removal of the `<>1__state` resume plumbing. Driven by the field roles recovered by
//! [`crate::state_machine`].
//!
//! Clean-room reimplementation of the reversal performed by `ILSpy`'s `YieldReturnDecompiler` /
//! `AsyncAwaitDecompiler` (MIT): the same lowering idioms are recognized and undone, but the pattern
//! matching here is original and operates on disrobe's structured output, not on `ILSpy`'s IL AST.
//! No source is copied.

use std::fmt::Write as _;

use crate::state_machine::{StateMachine, StateMachineKind};

/// Rewrite a rendered `MoveNext` body in place, undoing the state-machine lowering for the given
/// machine. Returns the rewritten body and a count of folded yield/await points (for metrics).
#[must_use]
pub fn reverse_move_next(body: &str, sm: &StateMachine) -> (String, u32) {
    let renamed: Vec<String> = body
        .lines()
        .map(|l: &str| rename_hoisted_fields(l, sm))
        .collect();
    let (folded, points): (Vec<String>, u32) = match sm.kind {
        StateMachineKind::Iterator => fold_iterator(&renamed, sm),
        StateMachineKind::Async | StateMachineKind::AsyncIterator => fold_async(&renamed, sm),
    };
    let stripped: Vec<String> = strip_state_plumbing(&folded, sm);
    let mut out: String = String::with_capacity(body.len());
    for line in &stripped {
        let _ = writeln!(out, "{line}");
    }
    (out, points)
}

/// Rename hoisted-local fields `this.<name>5__N` -> `name`, the captured-this field `this.<>4__this`
/// -> `this`, and the current backing field reads to a neutral form. Obfuscated machines keep their
/// raw names (no `<name>` to extract), which is still correct, just less pretty.
fn rename_hoisted_fields(line: &str, sm: &StateMachine) -> String {
    let mut out: String = line.to_owned();
    out = replace_captured_this(&out);
    out = replace_param_fields(&out);
    out = replace_hoisted_locals(&out);
    if let Some(current) = &sm.current_field {
        out = out.replace(&format!("this.{current}"), "/*current*/");
    }
    out
}

/// Replace parameter-backing fields `this.<>N__name` -> `name` (Roslyn stores the original method
/// parameters in `<>3__name` fields inside the state machine).
fn replace_param_fields(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let mut rest: &str = line;
    while let Some(pos) = rest.find("this.<>") {
        out.push_str(&rest[..pos]);
        let after: &str = &rest[pos + "this.<>".len()..];
        if let Some((name, consumed)) = parse_param_field(after) {
            out.push_str(&name);
            rest = &after[consumed..];
        } else {
            out.push_str("this.<>");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Parse a `N__name` parameter-field suffix (after the `this.<>` prefix), returning the bare `name`
/// and bytes consumed. Rejects the structural `1__state`/`2__current`/`4__this`/`t__builder` markers
/// so only real parameter names are rewritten.
fn parse_param_field(s: &str) -> Option<(String, usize)> {
    let digits: usize = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let after_digits: &str = &s[digits..];
    let underscores: usize = after_digits.bytes().take_while(|&b: &u8| b == b'_').count();
    if underscores < 2 {
        return None;
    }
    let name_part: &str = &after_digits[underscores..];
    let name_len: usize = name_part
        .bytes()
        .take_while(|&b: &u8| b == b'_' || b.is_ascii_alphanumeric())
        .count();
    let name: &str = &name_part[..name_len];
    if name.is_empty() || matches!(name, "state" | "current" | "this" | "builder") {
        return None;
    }
    Some((name.to_owned(), digits + underscores + name_len))
}

fn replace_captured_this(line: &str) -> String {
    line.replace("this.<>4__this.", "this.")
        .replace("this.<>4__this", "this")
}

/// Replace `this.<ident>5__N` occurrences with `ident`. Scans for the `<...>5__` marker and rewrites
/// each, leaving non-matching text untouched.
fn replace_hoisted_locals(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let bytes: &[u8] = line.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if line[i..].starts_with("this.<")
            && let Some((ident, consumed)) = parse_hoisted(&line[i..])
        {
            out.push_str(&ident);
            i += consumed;
            continue;
        }
        let ch: char = line[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Parse a `this.<ident>5__N` (or `this.<ident>N__M`) prefix, returning the bare `ident` and the
/// number of bytes consumed.
fn parse_hoisted(s: &str) -> Option<(String, usize)> {
    let rest: &str = s.strip_prefix("this.<")?;
    let close: usize = rest.find('>')?;
    let ident: &str = &rest[..close];
    if ident.is_empty() || ident.starts_with('>') {
        return None;
    }
    let after: &str = &rest[close + 1..];
    let mut digits: usize = 0;
    for c in after.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else {
            break;
        }
    }
    let tail: &str = &after[digits..];
    let underscores: usize = tail.bytes().take_while(|&b: &u8| b == b'_').count();
    if digits == 0 || underscores < 2 {
        return None;
    }
    let mut num: usize = 0;
    for c in tail[underscores..].chars() {
        if c.is_ascii_digit() {
            num += 1;
        } else {
            break;
        }
    }
    if num == 0 {
        return None;
    }
    let consumed: usize = "this.<".len() + close + 1 + digits + underscores + num;
    Some((ident.to_owned(), consumed))
}

/// Fold iterator yield idioms: a `current = X` assignment followed by a `state = N` and
/// `return true`/`return 1` becomes `yield return X;`; bare `return false`/`return 0` becomes
/// `yield break;`.
fn fold_iterator(lines: &[String], _sm: &StateMachine) -> (Vec<String>, u32) {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut points: u32 = 0;
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some((value, indent, consumed)) = match_yield_return(&lines[i..]) {
            out.push(format!("{indent}yield return {value};"));
            points += 1;
            i += consumed;
            continue;
        }
        if let Some(indent) = match_yield_break(&lines[i]) {
            out.push(format!("{indent}yield break;"));
            points += 1;
            i += 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    (out, points)
}

/// Match `<current> = X;` then `state = N;` then `return true|1;`. Tolerates the current field
/// already rewritten to the `/*current*/` marker.
fn match_yield_return(lines: &[String]) -> Option<(String, String, usize)> {
    let first: &str = lines.first()?;
    let trimmed: &str = first.trim_start();
    let indent: String = first[..first.len() - trimmed.len()].to_owned();
    let value: &str = trimmed
        .strip_prefix("/*current*/ = ")
        .or_else(|| trimmed.strip_prefix("/*current*/="))?
        .strip_suffix(';')?;
    let mut idx: usize = 1;
    while idx < lines.len() && is_state_assignment(&lines[idx]) {
        idx += 1;
    }
    let ret: &str = lines.get(idx)?.trim_start();
    if matches!(ret, "return true;" | "return 1;") {
        return Some((value.to_owned(), indent, idx + 1));
    }
    None
}

fn match_yield_break(line: &str) -> Option<String> {
    let trimmed: &str = line.trim_start();
    if matches!(trimmed, "return false;" | "return 0;") {
        return Some(line[..line.len() - trimmed.len()].to_owned());
    }
    None
}

/// Fold async await idioms: the `awaiter = expr.GetAwaiter(); if(!awaiter.IsCompleted){...} ...
/// result = awaiter.GetResult();` sequence collapses to `await expr`. Conservative: only rewrites
/// the clearly-recognizable `GetAwaiter()`/`GetResult()` call lines into an `await` annotation so the
/// reader sees the await points; full re-weaving of the resume control flow is left structural.
fn fold_async(lines: &[String], _sm: &StateMachine) -> (Vec<String>, u32) {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut points: u32 = 0;
    for line in lines {
        if let Some((indent, target, expr)) = match_get_awaiter(line) {
            out.push(format!("{indent}{target} = await {expr};"));
            points += 1;
            continue;
        }
        if let Some(rewritten) = rewrite_set_result(line) {
            out.push(rewritten);
            continue;
        }
        out.push(line.clone());
    }
    (out, points)
}

/// Match `X = <expr>.GetAwaiter();` -> capture target `X` and `<expr>`.
fn match_get_awaiter(line: &str) -> Option<(String, String, String)> {
    let trimmed: &str = line.trim_start();
    let indent: String = line[..line.len() - trimmed.len()].to_owned();
    let (target, rhs): (&str, &str) = trimmed.split_once(" = ")?;
    let expr: &str = rhs.strip_suffix(".GetAwaiter();")?;
    let expr: &str = expr
        .strip_suffix(".ConfigureAwait(0)")
        .or_else(|| expr.strip_suffix(".ConfigureAwait(false)"))
        .unwrap_or(expr);
    Some((indent, target.to_owned(), expr.to_owned()))
}

/// Rewrite `(&this.<>t__builder).SetResult(X);` -> `return X;` and the parameterless form ->
/// `return;`.
fn rewrite_set_result(line: &str) -> Option<String> {
    let trimmed: &str = line.trim_start();
    let indent: &str = &line[..line.len() - trimmed.len()];
    let inner: &str = trimmed.split_once("SetResult(")?.1.strip_suffix(");")?;
    if inner.is_empty() {
        Some(format!("{indent}return;"))
    } else {
        Some(format!("{indent}return {inner};"))
    }
}

/// Remove the state-machine resume plumbing: `local = this.<state>;`, `this.<state> = N;`,
/// awaiter-field stores/clears, and `(&this.<>t__builder)....` builder bookkeeping that no longer
/// has meaning after folding. Lines that become empty are dropped.
fn strip_state_plumbing(lines: &[String], sm: &StateMachine) -> Vec<String> {
    lines
        .iter()
        .filter(|line: &&String| !is_plumbing_line(line, sm))
        .cloned()
        .collect()
}

fn is_plumbing_line(line: &str, sm: &StateMachine) -> bool {
    let t: &str = line.trim();
    let state: &str = &sm.state_field;
    t == format!("this.{state} = -1;")
        || t == format!("this.{state} = -2;")
        || t.starts_with(&format!("this.{state} = "))
        || t.starts_with(&format!("this.{state};"))
        || t.contains("__builder).Start(")
        || t.contains("AwaitUnsafeOnCompleted")
        || t.contains("SetStateMachine(")
}

fn is_state_assignment(line: &str) -> bool {
    let t: &str = line.trim();
    t.contains("__state = ") || t.contains("1__state =")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn iterator_sm() -> StateMachine {
        StateMachine {
            kind: StateMachineKind::Iterator,
            type_token: 0,
            state_field: "<>1__state".to_owned(),
            builder_field: None,
            current_field: Some("<>2__current".to_owned()),
        }
    }

    fn async_sm() -> StateMachine {
        StateMachine {
            kind: StateMachineKind::Async,
            type_token: 0,
            state_field: "<>1__state".to_owned(),
            builder_field: Some("<>t__builder".to_owned()),
            current_field: None,
        }
    }

    #[test]
    fn folds_yield_return() {
        let body: &str = concat!(
            "    this.<>2__current = this.<i>5__2;\n",
            "    this.<>1__state = 1;\n",
            "    return true;\n"
        );
        let (out, points): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(out.contains("yield return i;"), "got:\n{out}");
        assert!(
            !out.contains("<>1__state"),
            "state plumbing removed:\n{out}"
        );
        assert_eq!(points, 1);
    }

    #[test]
    fn folds_yield_break() {
        let body: &str = "    return false;\n";
        let (out, points): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(out.contains("yield break;"), "got:\n{out}");
        assert_eq!(points, 1);
    }

    #[test]
    fn renames_hoisted_local() {
        let body: &str = "    this.<count>5__3 = this.<count>5__3 + 1;\n";
        let (out, _): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(out.contains("count = count + 1;"), "got:\n{out}");
    }

    #[test]
    fn folds_await_get_awaiter() {
        let body: &str = "    local4 = foo.Bar().ConfigureAwait(0).GetAwaiter();\n";
        let (out, points): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(out.contains("local4 = await foo.Bar();"), "got:\n{out}");
        assert_eq!(points, 1);
    }

    #[test]
    fn rewrites_set_result_to_return() {
        let body: &str = "    (&this.<>t__builder).SetResult(local2);\n";
        let (out, _): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(out.contains("return local2;"), "got:\n{out}");
    }

    #[test]
    fn captured_this_field_collapses() {
        let body: &str = "    local5 = this.<>4__this._repository;\n";
        let (out, _): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(out.contains("this._repository"), "got:\n{out}");
    }

    #[test]
    fn param_backing_field_renamed() {
        let body: &str = "    i = this.<>3__from;\n";
        let (out, _): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(out.contains("i = from;"), "got:\n{out}");
    }

    #[test]
    fn param_rename_keeps_state_field_intact() {
        let body: &str = "    local0 = this.<>1__state == 0;\n";
        let (out, _): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(
            out.contains("this.<>1__state"),
            "state field must not be renamed to a param:\n{out}"
        );
    }
}
