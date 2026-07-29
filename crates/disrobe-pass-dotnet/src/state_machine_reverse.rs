use std::fmt::Write as _;

use crate::debug::dbg_kv;
use crate::state_machine::{StateMachine, StateMachineKind};

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
    dbg_kv("state-machine-reverse", || {
        format!(
            "kind={:?} input_lines={} folded_lines={} fold_points={points}",
            sm.kind,
            renamed.len(),
            folded.len()
        )
    });
    let mirror: Option<String> = state_mirror_local(&folded, sm);
    let dispatched: Vec<String> = linearize_dispatch(&folded, sm, mirror.as_deref());
    let stripped: Vec<String> = strip_state_plumbing(&dispatched, sm, mirror.as_deref());
    let unwrapped: Vec<String> = match sm.kind {
        StateMachineKind::Async | StateMachineKind::AsyncIterator => {
            unwrap_async_exception_wrapper(&stripped)
        }
        StateMachineKind::Iterator => stripped,
    };
    let rethrows_balanced: Vec<String> = collapse_dispatch_info_rethrow(&unwrapped);
    let retyped_throws: Vec<String> = retype_thrown_object_locals(&rethrows_balanced);
    let cleared_enumerators: Vec<String> = drop_enumerator_disposal_clears(&retyped_throws);
    let degated: Vec<String> = collapse_completion_gates(&cleared_enumerators);
    let redeferred: Vec<String> = match sm.kind {
        StateMachineKind::Async | StateMachineKind::AsyncIterator => {
            drop_dead_awaiter_locals(&collapse_awaiter_deref(&simplify_awaiter_results(&degated)))
        }
        StateMachineKind::Iterator => degated,
    };
    let reflowed: Vec<String> = match sm.kind {
        StateMachineKind::AsyncIterator | StateMachineKind::Iterator => {
            fold_yield_assignments(&redeferred, sm)
        }
        StateMachineKind::Async => redeferred,
    };
    let relabeled: Vec<String> = drop_orphan_labels(&reflowed);
    let determined: Vec<String> = drop_dead_after_transfer(&relabeled);
    let int_typed: Vec<String> = normalize_int_mirror_conditions(&determined);
    let rewoven: Vec<String> = reconstruct_resume_goto_dispatch(&int_typed);
    let inlined: Vec<String> = collapse_entry_state_dispatch(&rewoven);
    let ref_typed: Vec<String> = normalize_reference_null_conditions(&inlined);
    let bool_typed: Vec<String> = normalize_bool_literal_residue(&ref_typed);
    let deref_simplified: Vec<String> = simplify_local_deref_assign(&bool_typed);
    let rewrapped: Vec<String> = match sm.kind {
        StateMachineKind::Async | StateMachineKind::AsyncIterator => {
            unwrap_async_exception_wrapper(&deref_simplified)
        }
        StateMachineKind::Iterator => deref_simplified,
    };
    let yield_broken: Vec<String> = match sm.kind {
        StateMachineKind::Iterator | StateMachineKind::AsyncIterator => {
            fold_iterator_return_register(&rewrapped)
        }
        StateMachineKind::Async => rewrapped,
    };
    let hoisted: Vec<String> = match sm.kind {
        StateMachineKind::Async | StateMachineKind::AsyncIterator => {
            hoist_result_register_returns(&yield_broken)
        }
        StateMachineKind::Iterator => yield_broken,
    };
    let no_bare: Vec<String> = drop_bare_value_statements(&hoisted);
    let pruned: Vec<String> = drop_unreferenced_local_decls(&no_bare);
    let collapsed: Vec<String> = drop_redundant_blank_runs(&pruned);
    let mut out: String = String::with_capacity(body.len());
    for line in &collapsed {
        let _ = writeln!(out, "{line}");
    }
    (out, points)
}

#[must_use]
pub fn sanitize_generated_residue(body: &str) -> String {
    if !body.contains("<>")
        && !body.contains(">b__")
        && !body.contains(">d__")
        && !body.contains('$')
    {
        return body.to_owned();
    }
    let mut out: String = String::with_capacity(body.len());
    for line in body.lines() {
        if line.trim_start().starts_with("//") {
            out.push_str(line);
        } else {
            out.push_str(&sanitize_generated_residue_line(line));
        }
        out.push('\n');
    }
    out
}

fn sanitize_generated_residue_line(line: &str) -> String {
    let bytes: &[u8] = line.as_bytes();
    let mut out: String = String::with_capacity(line.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'<'
            && !preceded_by_identifier(bytes, i)
            && let Some(consumed) = sanitize_generated_name_at(&line[i..], &mut out)
        {
            i += consumed;
            continue;
        }
        if bytes[i] == b'$' && dollar_in_identifier(bytes, i) {
            out.push('_');
            i += 1;
            continue;
        }
        let ch: char = line[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn preceded_by_identifier(bytes: &[u8], idx: usize) -> bool {
    idx.checked_sub(1)
        .and_then(|p: usize| bytes.get(p))
        .is_some_and(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_')
}

fn dollar_in_identifier(bytes: &[u8], idx: usize) -> bool {
    let before: bool = idx
        .checked_sub(1)
        .and_then(|p: usize| bytes.get(p))
        .is_some_and(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_');
    let after: bool = bytes
        .get(idx + 1)
        .is_some_and(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'<');
    before || after
}

fn sanitize_generated_name_at(s: &str, out: &mut String) -> Option<usize> {
    let rest: &str = s.strip_prefix('<')?;
    let close: usize = rest.find('>')?;
    let inner: &str = &rest[..close];
    if inner.contains('<') || inner.contains('(') || inner.contains(' ') {
        return None;
    }
    let after: &str = &rest[close + 1..];
    let tail_len: usize = after
        .bytes()
        .take_while(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_')
        .count();
    let tail: &str = &after[..tail_len];
    if inner.is_empty() && tail.is_empty() {
        return None;
    }
    out.push('_');
    out.push_str(inner);
    out.push('_');
    out.push_str(tail);
    Some(1 + close + 1 + tail_len)
}

#[must_use]
pub fn lower_generic_placeholders(
    body: &str,
    type_param_names: &[String],
    method_param_names: &[String],
) -> String {
    if (type_param_names.is_empty() && method_param_names.is_empty()) || !body.contains('!') {
        return body.to_owned();
    }
    let bytes: &[u8] = body.as_bytes();
    let mut out: String = String::with_capacity(body.len());
    let mut i: usize = 0;
    let mut copy_from: usize = 0;
    while i < bytes.len() {
        if bytes[i] != b'!' {
            i += 1;
            continue;
        }
        let is_method_var: bool = bytes.get(i + 1) == Some(&b'!');
        let digit_start: usize = if is_method_var { i + 2 } else { i + 1 };
        let mut j: usize = digit_start;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        let preceded_by_ident: bool = i
            .checked_sub(1)
            .and_then(|p: usize| bytes.get(p))
            .is_some_and(|&p: &u8| p.is_ascii_alphanumeric() || p == b'_');
        let index: usize = body[digit_start..j].parse::<usize>().unwrap_or(usize::MAX);
        let names: &[String] = if is_method_var {
            method_param_names
        } else {
            type_param_names
        };
        if j > digit_start
            && !preceded_by_ident
            && let Some(name) = names.get(index)
        {
            out.push_str(&body[copy_from..i]);
            out.push_str(name);
            i = j;
            copy_from = j;
        } else {
            i += 1;
        }
    }
    out.push_str(&body[copy_from..]);
    out
}

fn drop_dead_after_transfer(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut after_transfer: bool = false;
    for line in lines {
        let t: &str = line.trim();
        if after_transfer && is_redundant_terminal(t) {
            continue;
        }
        after_transfer = is_unconditional_transfer(t);
        out.push(line.clone());
    }
    out
}

fn is_unconditional_transfer(t: &str) -> bool {
    (t.starts_with("return ") && t.ends_with(';'))
        || (t.starts_with("throw ") && t.ends_with(';'))
        || t == "yield break;"
}

fn is_redundant_terminal(t: &str) -> bool {
    matches!(t, "return;" | "return 0;" | "return false;")
}

fn result_register(lines: &[String]) -> Option<String> {
    let mut idx: usize = 0;
    while idx + 1 < lines.len() {
        if let Some(name) = result_register_assign(&lines[idx])
            && lines[idx + 1].trim() == format!("return {name};")
        {
            return Some(name);
        }
        idx += 1;
    }
    None
}

fn result_register_assign(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, _rhs): (&str, &str) = inner.split_once(" = ")?;
    let name: &str = lhs.trim();
    is_local_name(name).then(|| name.to_owned())
}

fn register_store_expr(line: &str, register: &str) -> Option<String> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (lhs, rhs): (&str, &str) = inner.split_once(" = ")?;
    let rhs: &str = rhs.trim();
    (lhs.trim() == register && rhs != register).then(|| rhs.to_owned())
}

fn next_meaningful_index(lines: &[String], after: usize) -> Option<usize> {
    (after + 1..lines.len()).find(|&i: &usize| !lines[i].trim().is_empty())
}

fn closes_block(line: &str) -> bool {
    matches!(line.trim(), "}")
}

fn falls_off_method_end(lines: &[String], close_idx: usize) -> bool {
    (close_idx + 1..lines.len()).all(|i: usize| {
        let t: &str = lines[i].trim();
        t.is_empty() || t == "}" || t == "{" || t == "finally" || t == "try"
    })
}

fn block_opener_is_branch(lines: &[String], assign_idx: usize) -> bool {
    let mut depth: i32 = 0;
    let mut i: usize = assign_idx;
    loop {
        let line: &str = lines[i].trim();
        depth += i32::try_from(line.matches('}').count()).unwrap_or(0);
        depth -= i32::try_from(line.matches('{').count()).unwrap_or(0);
        if depth < 0 {
            let opener: &str = if line == "{" {
                i.checked_sub(1).map_or("", |p: usize| lines[p].trim())
            } else {
                line
            };
            return opener == "else" || opener.starts_with("catch");
        }
        let Some(prev): Option<usize> = i.checked_sub(1) else {
            return false;
        };
        i = prev;
    }
}

fn hoist_result_register_returns(lines: &[String]) -> Vec<String> {
    let Some(register): Option<String> = result_register(lines) else {
        return lines.to_vec();
    };
    let mut out: Vec<String> = lines.to_vec();
    for idx in 0..out.len() {
        let Some(expr): Option<String> = register_store_expr(&out[idx], &register) else {
            continue;
        };
        let Some(close_idx): Option<usize> = next_meaningful_index(&out, idx) else {
            continue;
        };
        if !closes_block(&out[close_idx])
            || !block_opener_is_branch(&out, idx)
            || !falls_off_method_end(&out, close_idx)
        {
            continue;
        }
        let indent: &str = &out[idx][..out[idx].len() - out[idx].trim_start().len()];
        out[idx] = format!("{indent}return {expr};");
    }
    out
}

fn drop_bare_value_statements(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line: &&String| !is_bare_value_statement(line))
        .cloned()
        .collect()
}

fn is_bare_value_statement(line: &str) -> bool {
    let t: &str = line.trim();
    let Some(inner): Option<&str> = t.strip_suffix(';') else {
        return false;
    };
    let inner: &str = inner.trim();
    if inner.is_empty() {
        return false;
    }
    if inner.contains('=')
        || inner.contains('(')
        || inner.contains(')')
        || inner.contains("++")
        || inner.contains("--")
        || inner.contains(' ')
        || local_decl_name(line).is_some()
    {
        return false;
    }
    inner
        .bytes()
        .next()
        .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && inner
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

fn drop_unreferenced_local_decls(lines: &[String]) -> Vec<String> {
    let unreferenced: std::collections::BTreeSet<&str> = lines
        .iter()
        .filter_map(|l: &String| local_decl_name(l))
        .filter(|name: &&str| {
            !lines.iter().any(|l: &String| {
                local_decl_name(l) != Some(name) && line_references_identifier(l, name)
            })
        })
        .collect();
    if unreferenced.is_empty() {
        return lines.to_vec();
    }
    lines
        .iter()
        .filter(|l: &&String| !local_decl_name(l).is_some_and(|n: &str| unreferenced.contains(n)))
        .cloned()
        .collect()
}

fn state_mirror_local(lines: &[String], sm: &StateMachine) -> Option<String> {
    let needle: String = format!("= this.{};", sm.state_field);
    lines.iter().find_map(|line: &String| {
        let t: &str = line.trim();
        let lhs: &str = t.strip_suffix(&needle)?.trim();
        lhs.starts_with("local").then(|| lhs.to_owned())
    })
}

fn linearize_dispatch(lines: &[String], sm: &StateMachine, mirror: Option<&str>) -> Vec<String> {
    let without_completion: Vec<String> = drop_await_completion_blocks(lines);
    let Some(mirror): Option<&str> = mirror else {
        return without_completion;
    };
    collapse_resume_guards(&without_completion, sm, mirror)
}

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
    let resolved: String = crate::state_machine::hoisted_slot_source_name(name)?;
    let consumed: usize = digits + underscores + name_len;
    Some((resolved, consumed))
}

fn replace_captured_this(line: &str) -> String {
    line.replace("this.<>4__this.", "this.")
        .replace("this.<>4__this", "this")
}

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

fn fold_async(lines: &[String], sm: &StateMachine) -> (Vec<String>, u32) {
    let collapsed: Vec<String> = collapse_await_completion_guard(lines, sm);
    let mut out: Vec<String> = Vec::with_capacity(collapsed.len());
    let mut points: u32 = 0;
    for line in &collapsed {
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
    (collapse_awaiter_deref(&out), points)
}

fn simplify_awaiter_results(lines: &[String]) -> Vec<String> {
    let stripped: Vec<String> = lines
        .iter()
        .map(|l: &String| strip_local_address_of(&normalize_configure_await_bool(l)))
        .collect();
    let awaited: std::collections::BTreeSet<String> = stripped
        .iter()
        .filter_map(|l: &String| await_result_local(l))
        .collect();
    if awaited.is_empty() {
        return stripped;
    }
    stripped
        .iter()
        .map(|l: &String| collapse_get_result_calls(l, &awaited))
        .collect()
}

fn normalize_configure_await_bool(line: &str) -> String {
    const NEEDLE: &str = "ConfigureAwait(";
    let mut out: String = String::with_capacity(line.len());
    let mut rest: &str = line;
    while let Some(pos) = rest.find(NEEDLE) {
        let open: usize = pos + NEEDLE.len();
        out.push_str(&rest[..open]);
        let Some(span): Option<usize> = balanced_arg_span(&rest[open..]) else {
            rest = &rest[open..];
            continue;
        };
        let args: &str = &rest[open..open + span];
        out.push_str(&rewrite_trailing_bool_arg(args));
        out.push(')');
        rest = &rest[open + span + 1..];
    }
    out.push_str(rest);
    out
}

fn balanced_arg_span(s: &str) -> Option<usize> {
    let mut depth: usize = 1;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' if depth == 1 => return Some(idx),
            ')' | ']' | '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn rewrite_trailing_bool_arg(args: &str) -> String {
    let mut depth: usize = 0;
    let mut last_comma: Option<usize> = None;
    for (idx, ch) in args.char_indices() {
        match ch {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => last_comma = Some(idx),
            _ => {}
        }
    }
    let (head, tail): (&str, &str) = last_comma.map_or_else(
        || ("", args.trim()),
        |idx: usize| (&args[..=idx], args[idx + 1..].trim()),
    );
    let replacement: &str = match tail {
        "0" => "false",
        "1" => "true",
        other => other,
    };
    if replacement == tail && last_comma.is_none() {
        return args.to_owned();
    }
    if head.is_empty() {
        replacement.to_owned()
    } else {
        format!("{head} {replacement}")
    }
}

fn strip_local_address_of(line: &str) -> String {
    let mut out: String = String::with_capacity(line.len());
    let bytes: &[u8] = line.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if line[i..].starts_with("(&")
            && let Some((name, consumed)) = parse_address_of_local(&line[i..])
        {
            out.push_str(&name);
            i += consumed;
            continue;
        }
        let ch: char = line[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn parse_address_of_local(s: &str) -> Option<(String, usize)> {
    let rest: &str = s.strip_prefix("(&")?;
    let name_len: usize = rest
        .bytes()
        .take_while(|&b: &u8| b.is_ascii_alphanumeric() || b == b'_')
        .count();
    let name: &str = &rest[..name_len];
    if !is_local_name(name) {
        return None;
    }
    rest[name_len..]
        .strip_prefix(')')
        .map(|_| (name.to_owned(), "(&".len() + name_len + 1))
}

fn await_result_local(line: &str) -> Option<String> {
    let t: &str = line.trim();
    let (lhs, rhs): (&str, &str) = t.strip_suffix(';')?.split_once(" = await ")?;
    let lhs: &str = lhs.trim();
    (is_local_name(lhs) && !rhs.trim_start().is_empty()).then(|| lhs.to_owned())
}

fn collapse_get_result_calls(line: &str, awaited: &std::collections::BTreeSet<String>) -> String {
    let mut out: String = line.to_owned();
    for name in awaited {
        out = out.replace(&format!("{name}.GetResult()"), name);
    }
    out
}

fn collapse_awaiter_deref(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some((indent, target, awaiter_local)) = match_await_of_local(&lines[i])
            && !is_used_after(lines, i + 1, &target)
            && let Some(prev) = out.last()
            && let Some(producer_expr) = local_producer(prev, &awaiter_local)
        {
            out.pop();
            out.push(format!("{indent}await {producer_expr};"));
            i += 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn simplify_local_deref_assign(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|line: &String| {
            let trimmed: &str = line.trim_start();
            let indent: &str = &line[..line.len() - trimmed.len()];
            let Some((lhs, rhs)): Option<(&str, &str)> = trimmed.split_once(" = ") else {
                return line.clone();
            };
            let Some(inner): Option<&str> = lhs
                .strip_prefix("*(&")
                .and_then(|s: &str| s.strip_suffix(')'))
            else {
                return line.clone();
            };
            if is_plain_lvalue(inner) {
                format!("{indent}{inner} = {rhs}")
            } else {
                line.clone()
            }
        })
        .collect()
}

fn is_plain_lvalue(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_used_after(lines: &[String], from: usize, name: &str) -> bool {
    lines[from..]
        .iter()
        .any(|l: &String| line_references_identifier(l, name))
}

fn line_references_identifier(line: &str, name: &str) -> bool {
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

fn match_await_of_local(line: &str) -> Option<(String, String, String)> {
    let trimmed: &str = line.trim_start();
    let indent: String = line[..line.len() - trimmed.len()].to_owned();
    let (target, rhs): (&str, &str) = trimmed.split_once(" = await ")?;
    let inner: &str = rhs.strip_suffix(';')?;
    let awaiter: &str = inner
        .strip_prefix("(&")
        .and_then(|s: &str| s.strip_suffix(')'))
        .unwrap_or(inner);
    is_local_name(awaiter).then(|| (indent, target.to_owned(), awaiter.to_owned()))
}

fn local_producer(prev_line: &str, awaiter_local: &str) -> Option<String> {
    let t: &str = prev_line.trim();
    let needle: String = format!("{awaiter_local} = ");
    let rhs: &str = t.strip_prefix(&needle)?.strip_suffix(';')?;
    (!rhs.starts_with("await ")).then(|| rhs.to_owned())
}

fn is_local_name(s: &str) -> bool {
    s.starts_with("local") && s[5..].bytes().all(|b: u8| b.is_ascii_digit()) && s.len() > 5
}

fn collapse_await_completion_guard(lines: &[String], sm: &StateMachine) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some((open_idx, close_idx)) = completion_guard_span(lines, i)
            && let Some(suspend_end) = suspend_run_end(lines, close_idx + 1, sm)
        {
            for body_line in &lines[open_idx + 1..close_idx] {
                if is_get_result_line(body_line) {
                    continue;
                }
                out.push(dedent_one_level(body_line));
            }
            i = suspend_end + 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn suspend_run_end(lines: &[String], start: usize, sm: &StateMachine) -> Option<usize> {
    let mut i: usize = start;
    while i < lines.len() {
        let t: &str = lines[i].trim();
        if t == "return;" {
            return Some(i);
        }
        if t.is_empty() || is_plumbing_line(&lines[i], sm) || is_suspend_local_set(t) {
            i += 1;
            continue;
        }
        return None;
    }
    None
}

fn is_suspend_local_set(t: &str) -> bool {
    let Some((lhs, rhs)): Option<(&str, &str)> =
        t.strip_suffix(';').and_then(|s: &str| s.split_once(" = "))
    else {
        return false;
    };
    lhs.starts_with("local") && rhs.bytes().all(|b: u8| b.is_ascii_digit() || b == b'-')
}

fn completion_guard_span(lines: &[String], idx: usize) -> Option<(usize, usize)> {
    let trimmed: &str = lines.get(idx)?.trim_start();
    let is_completed_guard: bool = trimmed.starts_with("if (")
        && (trimmed.contains(".IsCompleted)") || trimmed.contains(".get_IsCompleted())"))
        && !trimmed.contains("!(");
    if !is_completed_guard {
        return None;
    }
    let open_idx: usize = brace_open_index(lines, idx)?;
    let close_idx: usize = block_extent(lines, idx)?;
    (close_idx > open_idx).then_some((open_idx, close_idx))
}

fn is_get_result_line(line: &str) -> bool {
    let t: &str = line.trim();
    t.ends_with(".GetResult();") && !t.contains(" = ")
}

fn dedent_one_level(line: &str) -> String {
    line.strip_prefix("    ").unwrap_or(line).to_owned()
}

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

fn brace_open_index(lines: &[String], header_idx: usize) -> Option<usize> {
    if lines.get(header_idx)?.trim_end().ends_with('{') {
        return Some(header_idx);
    }
    (lines.get(header_idx + 1)?.trim() == "{").then_some(header_idx + 1)
}

fn block_extent(lines: &[String], header_idx: usize) -> Option<usize> {
    let open_idx: usize = brace_open_index(lines, header_idx)?;
    let mut depth: i32 = 0;
    for (offset, line) in lines[open_idx..].iter().enumerate() {
        depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
        depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
        if depth == 0 {
            return Some(open_idx + offset);
        }
    }
    None
}

fn drop_await_completion_blocks(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        let trimmed: &str = lines[i].trim_start();
        if trimmed.starts_with("if (!(")
            && trimmed.contains("get_IsCompleted()")
            && let Some(close) = block_extent(lines, i)
        {
            i = close + 1;
            if lines.get(i).map(|l: &String| l.trim()) == Some("return;") {
                i += 1;
            }
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn collapse_resume_guards(lines: &[String], sm: &StateMachine, mirror: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some(extent) = resume_guard_extent(lines, i, mirror) {
            splice_resume_body(&mut out, lines, &extent, sm);
            i = extent.end + 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

struct ResumeGuard {
    body_start: usize,
    body_end: usize,
    has_else: bool,
    else_start: usize,
    else_end: usize,
    end: usize,
}

fn resume_guard_extent(lines: &[String], idx: usize, mirror: &str) -> Option<ResumeGuard> {
    let trimmed: &str = lines.get(idx)?.trim_start();
    let is_dispatch: bool =
        trimmed == format!("if (!{mirror})") || trimmed.starts_with(&format!("if ({mirror} == "));
    if !is_dispatch {
        return None;
    }
    let then_open: usize = idx + 1;
    if lines.get(then_open).map(|l: &String| l.trim()) != Some("{") {
        return None;
    }
    let then_close: usize = block_extent(lines, then_open)?;
    let mut guard: ResumeGuard = ResumeGuard {
        body_start: then_open + 1,
        body_end: then_close.saturating_sub(1),
        has_else: false,
        else_start: 0,
        else_end: 0,
        end: then_close,
    };
    if lines.get(then_close + 1).map(|l: &String| l.trim()) == Some("else") {
        let else_open: usize = then_close + 2;
        if lines.get(else_open).map(|l: &String| l.trim()) == Some("{") {
            let else_close: usize = block_extent(lines, else_open)?;
            guard.has_else = true;
            guard.else_start = else_open + 1;
            guard.else_end = else_close.saturating_sub(1);
            guard.end = else_close;
        }
    }
    Some(guard)
}

fn splice_resume_body(
    out: &mut Vec<String>,
    lines: &[String],
    guard: &ResumeGuard,
    sm: &StateMachine,
) {
    let then_is_restore: bool = block_is_restore_only(lines, guard.body_start, guard.body_end, sm);
    let (keep_start, keep_end): (usize, usize) = if guard.has_else {
        if then_is_restore {
            (guard.else_start, guard.else_end)
        } else {
            (guard.body_start, guard.body_end)
        }
    } else if then_is_restore {
        return;
    } else {
        (guard.body_start, guard.body_end)
    };
    for line in &lines[keep_start..=keep_end.min(lines.len().saturating_sub(1))] {
        out.push(dedent_once(line));
    }
}

fn block_is_restore_only(lines: &[String], start: usize, end: usize, sm: &StateMachine) -> bool {
    if start > end {
        return true;
    }
    lines[start..=end.min(lines.len().saturating_sub(1))]
        .iter()
        .all(|line: &String| {
            let t: &str = line.trim();
            t.is_empty() || is_resume_restore_line(t, sm)
        })
}

fn is_resume_restore_line(t: &str, sm: &StateMachine) -> bool {
    t.contains(".<>u__")
        || t.starts_with("*(&this.<>u__")
        || t.ends_with("= -1;")
        || t == format!("this.{} = -1;", sm.state_field)
        || matches!(t, "{" | "}")
}

fn dedent_once(line: &str) -> String {
    line.strip_prefix("    ")
        .map_or_else(|| line.to_owned(), str::to_owned)
}

fn drop_dead_awaiter_locals(lines: &[String]) -> Vec<String> {
    let write_only: std::collections::BTreeSet<String> = dead_local_names(lines);
    if write_only.is_empty() {
        return lines.to_vec();
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        if is_decl_of_any(line, &write_only) {
            continue;
        }
        match strip_dead_assign(line, &write_only) {
            DeadAssign::Drop => {}
            DeadAssign::Keep(text) => out.push(text),
        }
    }
    out
}

enum DeadAssign {
    Drop,
    Keep(String),
}

fn strip_dead_assign(line: &str, names: &std::collections::BTreeSet<String>) -> DeadAssign {
    let t: &str = line.trim();
    let Some((lhs, rhs)): Option<(&str, &str)> = t.split_once(" = ") else {
        return DeadAssign::Keep(line.to_owned());
    };
    if !names.contains(lhs) {
        return DeadAssign::Keep(line.to_owned());
    }
    let body: &str = rhs.trim_end_matches(';').trim();
    let has_side_effect: bool = body.contains('(') || body.starts_with("await ");
    if !has_side_effect {
        return DeadAssign::Drop;
    }
    let indent: &str = &line[..line.len() - line.trim_start().len()];
    DeadAssign::Keep(format!("{indent}{body};"))
}

fn dead_local_names(lines: &[String]) -> std::collections::BTreeSet<String> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in lines {
        let Some(name): Option<&str> = local_decl_name(line) else {
            continue;
        };
        let read_count: usize = lines
            .iter()
            .filter(|l: &&String| line_reads_local(l, name))
            .count();
        let write_count: usize = lines
            .iter()
            .filter(|l: &&String| line_assigns_local(l, name))
            .count();
        if read_count == 0 && write_count > 0 {
            out.insert(name.to_owned());
        }
    }
    out
}

fn line_assigns_local(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    t.split_once(" = ")
        .is_some_and(|(lhs, _rhs): (&str, &str)| lhs == name)
}

fn local_decl_name(line: &str) -> Option<&str> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
    let valid_name: bool = name.starts_with("local")
        && name[5..].bytes().all(|b: u8| b.is_ascii_digit())
        && name.len() > 5;
    let keyword_lead: bool = matches!(
        ty.split_whitespace().next(),
        Some("return" | "throw" | "yield" | "await" | "continue" | "break" | "goto")
    );
    (valid_name && !ty.is_empty() && !ty.contains('=') && !ty.contains('(') && !keyword_lead)
        .then_some(name)
}

fn line_reads_local(line: &str, name: &str) -> bool {
    let t: &str = line.trim();
    if let Some((lhs, _rhs)) = t.split_once(" = ")
        && lhs == name
    {
        return false;
    }
    if local_decl_name(line) == Some(name) {
        return false;
    }
    line_references_identifier(line, name)
}

fn is_decl_of_any(line: &str, names: &std::collections::BTreeSet<String>) -> bool {
    local_decl_name(line).is_some_and(|n: &str| names.contains(n))
}

fn collapse_completion_gates(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        let trimmed: &str = lines[i].trim_start();
        if is_completion_gate_header(trimmed)
            && let Some(close) = block_extent(lines, i)
            && let Some(open) = brace_open_index(lines, i)
        {
            let negated: bool = trimmed.contains("if (!(") || trimmed.contains("if(!(");
            let has_else: bool = lines.get(close + 1).map(|l: &String| l.trim()) == Some("else");
            if negated {
                if has_else
                    && let Some(else_close) = block_extent(lines, close + 1)
                    && let Some(else_open) = brace_open_index(lines, close + 1)
                {
                    for body_line in &lines[else_open + 1..else_close] {
                        if !is_completion_residue(body_line) {
                            out.push(dedent_once(body_line));
                        }
                    }
                    i = else_close + 1;
                    continue;
                }
                i = close + 1;
                continue;
            }
            for body_line in &lines[open + 1..close] {
                if !is_completion_residue(body_line) {
                    out.push(dedent_once(body_line));
                }
            }
            if has_else && let Some(else_close) = block_extent(lines, close + 1) {
                i = else_close + 1;
            } else {
                i = close + 1;
            }
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn is_completion_gate_header(trimmed: &str) -> bool {
    trimmed.starts_with("if (")
        && (trimmed.contains(".IsCompleted)") || trimmed.contains(".get_IsCompleted())"))
}

fn is_completion_residue(line: &str) -> bool {
    let t: &str = line.trim();
    is_get_result_line(t) || (t.starts_with("local") && t.ends_with(" = this;"))
}

fn fold_yield_assignments(lines: &[String], sm: &StateMachine) -> Vec<String> {
    let _ = sm;
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        let trimmed: &str = lines[i].trim_start();
        let indent: &str = &lines[i][..lines[i].len() - trimmed.len()];
        if let Some(value) = trimmed
            .strip_prefix("/*current*/ = ")
            .or_else(|| trimmed.strip_prefix("/*current*/="))
            .and_then(|s: &str| s.strip_suffix(';'))
        {
            if value == "0" || value.is_empty() {
                out.push(format!("{indent}yield break;"));
                i += 1;
                while i < lines.len() && is_terminal_movenext_return(&lines[i]) {
                    i += 1;
                }
            } else {
                out.push(format!("{indent}yield return {value};"));
                i += 1;
            }
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn is_terminal_movenext_return(line: &str) -> bool {
    matches!(line.trim(), "return 0;" | "return false;" | "return;")
}

fn fold_iterator_return_register(lines: &[String]) -> Vec<String> {
    let Some(register): Option<String> = iterator_return_register(lines) else {
        return lines.to_vec();
    };
    let bool_assign: String = format!("{register} = true;");
    let bool_clear: String = format!("{register} = false;");
    let ret_register: String = format!("return {register};");
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        let trimmed: &str = line.trim();
        if trimmed == bool_assign || trimmed == bool_clear {
            continue;
        }
        if trimmed == ret_register {
            let indent: &str = &line[..line.len() - line.trim_start().len()];
            out.push(format!("{indent}yield break;"));
            continue;
        }
        out.push(line.clone());
    }
    out
}

fn iterator_return_register(lines: &[String]) -> Option<String> {
    let register: String = lines.iter().find_map(|line: &String| {
        let trimmed: &str = line.trim();
        let inner: &str = trimmed.strip_suffix(';')?;
        let name: &str = inner.strip_prefix("return ")?;
        is_local_name(name).then(|| name.to_owned())
    })?;
    let bool_assign: String = format!("{register} = true;");
    let bool_clear: String = format!("{register} = false;");
    let ret_register: String = format!("return {register};");
    let decl: String = format!("bool {register};");
    let mut assigned_false: bool = false;
    for line in lines {
        let trimmed: &str = line.trim();
        if !line_references_identifier(line, &register) {
            continue;
        }
        if trimmed == bool_clear {
            assigned_false = true;
            continue;
        }
        if trimmed == bool_assign || trimmed == ret_register || trimmed == decl {
            continue;
        }
        return None;
    }
    assigned_false.then_some(register)
}

fn drop_redundant_blank_runs(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut prev_blank: bool = false;
    for line in lines {
        let blank: bool = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        prev_blank = blank;
        out.push(line.clone());
    }
    out
}

fn drop_orphan_labels(lines: &[String]) -> Vec<String> {
    let referenced: std::collections::BTreeSet<&str> = lines
        .iter()
        .filter_map(|l: &String| {
            let t: &str = l.trim();
            t.strip_prefix("goto ")
                .and_then(|r: &str| r.strip_suffix(';'))
        })
        .filter(|t: &&str| t.starts_with("IL_"))
        .collect();
    lines
        .iter()
        .filter(|l: &&String| {
            let t: &str = l.trim();
            t.strip_suffix(":;")
                .filter(|s: &&str| s.starts_with("IL_"))
                .is_none_or(|label: &str| referenced.contains(label))
        })
        .cloned()
        .collect()
}

fn collapse_dispatch_info_rethrow(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some(span) = match_dispatch_info_rethrow(lines, i) {
            let indent: &str = leading_whitespace(&lines[i]);
            out.push(format!("{indent}throw {};", span.captured));
            i = span.end + 1;
            continue;
        }
        if let Some((indent, captured)) = match_bare_dispatch_info_throw(&lines[i]) {
            out.push(format!("{indent}throw {captured};"));
            i += 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

struct RethrowSpan {
    captured: String,
    end: usize,
}

fn match_dispatch_info_rethrow(lines: &[String], idx: usize) -> Option<RethrowSpan> {
    let guard: &str = lines.get(idx)?.trim();
    let captured: &str = guard
        .strip_prefix("if (!(")?
        .strip_suffix(" as Exception))")?
        .trim();
    if captured.is_empty() {
        return None;
    }
    let open: usize = idx + 1;
    if lines.get(open)?.trim() != "{" {
        return None;
    }
    let throw_line: &str = lines.get(idx + 2)?.trim();
    let thrown: &str = throw_line.strip_prefix("throw ")?.strip_suffix(';')?.trim();
    if thrown != captured {
        return None;
    }
    if lines.get(idx + 3)?.trim() != "}" {
        return None;
    }
    let rethrow: &str = lines.get(idx + 4)?.trim();
    if !is_dispatch_info_throw(rethrow) {
        return None;
    }
    Some(RethrowSpan {
        captured: captured.to_owned(),
        end: idx + 4,
    })
}

fn match_bare_dispatch_info_throw(line: &str) -> Option<(String, String)> {
    let t: &str = line.trim();
    let after_capture: &str = dispatch_info_capture_body(t)?;
    let captured: &str = after_capture.split(").Throw()").next()?.trim();
    if captured.is_empty() || captured == "__stack_underflow" {
        return None;
    }
    Some((leading_whitespace(line).to_owned(), captured.to_owned()))
}

fn dispatch_info_capture_body(t: &str) -> Option<&str> {
    let stripped: &str = t
        .strip_prefix("ExceptionDispatchInfo.")
        .or_else(|| t.strip_prefix("System.Runtime.ExceptionServices.ExceptionDispatchInfo."))
        .unwrap_or(t);
    stripped.strip_prefix("Capture(")
}

fn is_dispatch_info_throw(t: &str) -> bool {
    dispatch_info_capture_body(t).is_some() && t.contains(").Throw()") && t.ends_with(';')
}

fn leading_whitespace(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

fn thrown_local_name(line: &str) -> Option<&str> {
    let thrown: &str = line
        .trim()
        .strip_prefix("throw ")?
        .strip_suffix(';')?
        .trim();
    let is_ident: bool = !thrown.is_empty()
        && thrown
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && thrown
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    is_ident.then_some(thrown)
}

fn object_decl_name(line: &str) -> Option<&str> {
    let t: &str = line.trim();
    let inner: &str = t.strip_suffix(';')?;
    let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
    let is_object: bool = matches!(ty.trim(), "object" | "Object" | "System.Object");
    let valid_name: bool = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    (is_object && valid_name).then_some(name)
}

fn retype_object_catch_head(line: &str) -> Option<String> {
    let indent: &str = leading_whitespace(line);
    let t: &str = line.trim();
    let after: &str = t.strip_prefix("catch (")?;
    let (ty, rest): (&str, &str) = after.split_once(' ')?;
    if !matches!(ty, "Object" | "System.Object") {
        return None;
    }
    Some(format!("{indent}catch (Exception {rest}"))
}

fn is_enumerator_disposal_clear(line: &str) -> bool {
    let t: &str = line.trim();
    let Some(inner): Option<&str> = t.strip_suffix(';') else {
        return false;
    };
    let Some((lhs, rhs)): Option<(&str, &str)> = inner.split_once(" = ") else {
        return false;
    };
    let lhs_simple: bool = !lhs.is_empty()
        && lhs
            .bytes()
            .next()
            .is_some_and(|b: u8| b.is_ascii_alphabetic() || b == b'_')
        && lhs
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_');
    if !lhs_simple {
        return false;
    }
    let Some(ty): Option<&str> = rhs
        .trim()
        .strip_prefix("default(")
        .and_then(|s: &str| s.strip_suffix(')'))
    else {
        return false;
    };
    let leaf: &str = ty.rsplit('.').next().unwrap_or(ty);
    let head: &str = leaf.split('<').next().unwrap_or(leaf);
    head.ends_with("Enumerator")
}

fn drop_enumerator_disposal_clears(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line: &&String| !is_enumerator_disposal_clear(line))
        .cloned()
        .collect()
}

fn retype_thrown_object_locals(lines: &[String]) -> Vec<String> {
    let thrown: std::collections::BTreeSet<String> = lines
        .iter()
        .filter_map(|line: &String| thrown_local_name(line).map(str::to_owned))
        .collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        if let Some(head) = retype_object_catch_head(line) {
            out.push(head);
            continue;
        }
        if let Some(name) = object_decl_name(line)
            && thrown.contains(name)
        {
            let indent: &str = leading_whitespace(line);
            out.push(format!("{indent}Exception {name};"));
            continue;
        }
        out.push(line.clone());
    }
    out
}

fn unwrap_async_exception_wrapper(lines: &[String]) -> Vec<String> {
    let mut idx: usize = 0;
    while idx < lines.len() {
        if lines[idx].trim() == "try"
            && let Some(span) = async_wrapper_span(lines, idx)
        {
            let mut out: Vec<String> = lines[..idx].to_vec();
            out.extend(
                lines[span.body_start..=span.body_end]
                    .iter()
                    .map(|line: &String| dedent_once(line)),
            );
            out.extend_from_slice(&lines[span.end + 1..]);
            return out;
        }
        idx += 1;
    }
    lines.to_vec()
}

struct AsyncWrapperSpan {
    body_start: usize,
    body_end: usize,
    end: usize,
}

fn async_wrapper_span(lines: &[String], try_idx: usize) -> Option<AsyncWrapperSpan> {
    let try_close: usize = block_extent(lines, try_idx)?;
    let catch_header: usize = try_close + 1;
    if !is_catch_exception_header(lines.get(catch_header)?.trim()) {
        return None;
    }
    let catch_close: usize = block_extent(lines, catch_header)?;
    let catch_open: usize = brace_open_index(lines, catch_header)?;
    if !catch_body_is_plumbing_only(&lines[catch_open + 1..catch_close]) {
        return None;
    }
    let body_open: usize = brace_open_index(lines, try_idx)?;
    if body_open + 1 > try_close.saturating_sub(1) {
        return None;
    }
    Some(AsyncWrapperSpan {
        body_start: body_open + 1,
        body_end: try_close - 1,
        end: catch_close,
    })
}

fn is_catch_exception_header(t: &str) -> bool {
    t == "catch"
        || t.starts_with("catch (Exception")
        || t.starts_with("catch(Exception")
        || t.starts_with("catch (System.Exception")
        || t.starts_with("catch (Object")
        || t.starts_with("catch(Object")
        || t.starts_with("catch (System.Object")
}

fn catch_body_is_plumbing_only(lines: &[String]) -> bool {
    lines.iter().all(|line: &String| {
        let t: &str = line.trim();
        t.is_empty()
            || t == "{"
            || t == "}"
            || t.contains("SetException(")
            || t.contains("__builder")
            || t.ends_with("= -2;")
            || t == "return;"
    })
}

fn strip_state_plumbing(lines: &[String], sm: &StateMachine, mirror: Option<&str>) -> Vec<String> {
    lines
        .iter()
        .filter(|line: &&String| !is_plumbing_line(line, sm) && !is_mirror_reset(line, mirror))
        .cloned()
        .collect()
}

fn is_mirror_reset(line: &str, mirror: Option<&str>) -> bool {
    let Some(mirror): Option<&str> = mirror else {
        return false;
    };
    let t: &str = line.trim();
    let Some(rhs): Option<&str> = t
        .strip_prefix(mirror)
        .and_then(|s: &str| s.trim_start().strip_prefix('='))
        .and_then(|s: &str| s.trim().strip_suffix(';'))
    else {
        return false;
    };
    let rhs: &str = rhs.trim();
    !rhs.is_empty() && rhs.bytes().all(|b: u8| b.is_ascii_digit() || b == b'-')
}

fn is_plumbing_line(line: &str, sm: &StateMachine) -> bool {
    let t: &str = line.trim();
    let state: &str = &sm.state_field;
    t == format!("this.{state} = -1;")
        || t == format!("this.{state} = -2;")
        || t.starts_with(&format!("this.{state} = "))
        || t.starts_with(&format!("this.{state};"))
        || t.ends_with(&format!("= this.{state};"))
        || is_builder_plumbing_call(t, "Start")
        || is_builder_plumbing_call(t, "get_Task")
        || is_builder_plumbing_call(t, "Complete")
        || t.contains("AwaitUnsafeOnCompleted")
        || t.contains("SetStateMachine(")
        || is_awaiter_save_line(t)
}

fn is_builder_plumbing_call(t: &str, method: &str) -> bool {
    t.contains(&format!("__builder).{method}(")) || t.contains(&format!("__builder.{method}("))
}

fn is_awaiter_save_line(t: &str) -> bool {
    (t.starts_with("this.<>u__") && t.contains(" = "))
        || (t.contains("= this.<>u__") && t.ends_with(';'))
        || t.starts_with("*(&this.<>u__")
}

fn is_state_assignment(line: &str) -> bool {
    let t: &str = line.trim();
    t.contains("__state = ") || t.contains("1__state =")
}

fn declared_locals_of_type(lines: &[String], types: &[&str]) -> std::collections::BTreeSet<String> {
    lines
        .iter()
        .filter_map(|line: &String| {
            let t: &str = line.trim();
            let inner: &str = t.strip_suffix(';')?;
            let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
            (types.contains(&ty) && is_local_name(name)).then(|| name.to_owned())
        })
        .collect()
}

fn normalize_int_mirror_conditions(lines: &[String]) -> Vec<String> {
    let ints: std::collections::BTreeSet<String> = declared_locals_of_type(
        lines,
        &[
            "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "nint", "nuint",
        ],
    );
    if ints.is_empty() {
        return lines.to_vec();
    }
    lines
        .iter()
        .map(|line: &String| rewrite_int_truthiness(line, &ints))
        .collect()
}

fn rewrite_int_truthiness(line: &str, ints: &std::collections::BTreeSet<String>) -> String {
    let Some(cond_span): Option<(usize, usize)> = condition_span(line) else {
        return line.to_owned();
    };
    let prefix: &str = &line[..cond_span.0];
    let cond: &str = &line[cond_span.0..cond_span.1];
    let suffix: &str = &line[cond_span.1..];
    let Some(rewritten): Option<String> = int_condition_rewrite(cond, ints) else {
        return line.to_owned();
    };
    format!("{prefix}{rewritten}{suffix}")
}

fn condition_span(line: &str) -> Option<(usize, usize)> {
    let trimmed_start: usize = line.len() - line.trim_start().len();
    let head: &str = line[trimmed_start..].trim_end();
    let open_rel: usize = ["if (", "while (", "else if ("]
        .iter()
        .find_map(|kw: &&str| head.starts_with(kw).then_some(kw.len()))?;
    let open: usize = trimmed_start + open_rel;
    let close: usize = matching_paren(line.as_bytes(), open - 1)?;
    (close > open).then_some((open, close))
}

fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: usize = 0;
    for (idx, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn int_condition_rewrite(cond: &str, ints: &std::collections::BTreeSet<String>) -> Option<String> {
    let trimmed: &str = cond.trim();
    if let Some(inner) = trimmed
        .strip_prefix("!(!")
        .and_then(|s: &str| s.strip_suffix(')'))
        && is_int_operand(inner, ints)
    {
        return Some(format!("{inner} != 0"));
    }
    if let Some(inner) = trimmed.strip_prefix('!')
        && is_int_operand(inner, ints)
    {
        return Some(format!("{inner} == 0"));
    }
    is_int_operand(trimmed, ints).then(|| format!("{trimmed} != 0"))
}

fn is_int_operand(operand: &str, ints: &std::collections::BTreeSet<String>) -> bool {
    let name: &str = operand.trim();
    ints.contains(name)
}

fn reconstruct_resume_goto_dispatch(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some(span) = match_convergent_goto_dispatch(lines, i) {
            splice_convergent_goto_body(&mut out, lines, &span);
            i = span.end + 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

struct ConvergentGotoDispatch {
    header_idx: usize,
    then_start: usize,
    label_idx: usize,
    then_close: usize,
    else_start: usize,
    else_end: usize,
    drop_guard: bool,
    end: usize,
}

fn match_convergent_goto_dispatch(lines: &[String], idx: usize) -> Option<ConvergentGotoDispatch> {
    let header: &str = lines.get(idx)?.trim();
    let drop_guard: bool = is_state_mirror_header(header);
    if !drop_guard && !is_plain_condition_header(header) {
        return None;
    }
    let then_open: usize = brace_open_index(lines, idx)?;
    let then_close: usize = block_extent(lines, idx)?;
    if then_close <= then_open {
        return None;
    }
    if lines.get(then_close + 1).map(|l: &String| l.trim()) != Some("else") {
        return None;
    }
    let else_open: usize = brace_open_index(lines, then_close + 1)?;
    let else_close: usize = block_extent(lines, then_close + 1)?;
    let label: &str = trailing_goto_label(&lines[else_open + 1..else_close])?;
    let label_marker: String = format!("{label}:;");
    let label_idx: usize = lines[then_open + 1..then_close]
        .iter()
        .position(|l: &String| l.trim() == label_marker)
        .map(|p: usize| then_open + 1 + p)?;
    if branch_balance(&lines[then_open + 1..label_idx]) != 0
        || branch_balance(&lines[label_idx + 1..then_close]) != 0
    {
        return None;
    }
    Some(ConvergentGotoDispatch {
        header_idx: idx,
        then_start: then_open + 1,
        label_idx,
        then_close,
        else_start: else_open + 1,
        else_end: else_close.saturating_sub(1),
        drop_guard,
        end: else_close,
    })
}

fn branch_balance(lines: &[String]) -> i32 {
    lines.iter().fold(0_i32, |acc: i32, line: &String| {
        let opens: i32 = i32::try_from(line.matches('{').count()).unwrap_or(0);
        let closes: i32 = i32::try_from(line.matches('}').count()).unwrap_or(0);
        acc + opens - closes
    })
}

fn is_state_mirror_header(header: &str) -> bool {
    let Some(cond): Option<&str> = header
        .strip_prefix("if (")
        .and_then(|s: &str| s.strip_suffix(')'))
    else {
        return false;
    };
    let cond: &str = cond.trim();
    let Some((lhs, rhs)): Option<(&str, &str)> =
        cond.split_once(" == ").or_else(|| cond.split_once(" != "))
    else {
        return false;
    };
    let rhs: &str = rhs.trim();
    is_plain_lvalue(lhs.trim())
        && !rhs.is_empty()
        && rhs.bytes().all(|b: u8| b.is_ascii_digit() || b == b'-')
}

fn is_plain_condition_header(header: &str) -> bool {
    header
        .strip_prefix("if (")
        .and_then(|s: &str| s.strip_suffix(')'))
        .is_some_and(|cond: &str| !cond.trim().is_empty())
}

fn trailing_goto_label(else_body: &[String]) -> Option<&str> {
    let mut label: Option<&str> = None;
    for line in else_body {
        let t: &str = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(target) = t
            .strip_prefix("goto ")
            .and_then(|r: &str| r.strip_suffix(';'))
        {
            if !target.starts_with("IL_") || label.is_some() {
                return None;
            }
            label = Some(target);
            continue;
        }
        if label.is_some() {
            return None;
        }
    }
    label
}

fn splice_convergent_goto_body(
    out: &mut Vec<String>,
    lines: &[String],
    span: &ConvergentGotoDispatch,
) {
    let then_prefix: &[String] = &lines[span.then_start..span.label_idx];
    let tail_end: usize = span
        .then_close
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let tail: &[String] = &lines[span.label_idx + 1..=tail_end];
    if span.drop_guard {
        for line in then_prefix {
            out.push(dedent_once(line));
        }
        for line in tail {
            out.push(dedent_once(line));
        }
        return;
    }
    let else_body: &[String] =
        &lines[span.else_start..=span.else_end.min(lines.len().saturating_sub(1))];
    let indent: String = leading_whitespace(&lines[span.header_idx]).to_owned();
    out.push(lines[span.header_idx].clone());
    out.push(format!("{indent}{{"));
    for line in then_prefix {
        out.push(line.clone());
    }
    out.push(format!("{indent}}}"));
    out.push(format!("{indent}else"));
    out.push(format!("{indent}{{"));
    for line in else_body {
        let t: &str = line.trim();
        if t.starts_with("goto ") && t.ends_with(';') {
            continue;
        }
        out.push(line.clone());
    }
    out.push(format!("{indent}}}"));
    for line in tail {
        out.push(dedent_once(line));
    }
}

fn collapse_entry_state_dispatch(lines: &[String]) -> Vec<String> {
    let mirrors: std::collections::BTreeSet<String> = unassigned_int_mirrors(lines);
    if mirrors.is_empty() {
        return lines.to_vec();
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i: usize = 0;
    while i < lines.len() {
        if let Some((mirror, taken)) = entry_dispatch_condition(&lines[i], &mirrors)
            && let Some(open) = brace_open_index(lines, i)
            && let Some(close) = block_extent(lines, i)
            && close > open
        {
            let _ = mirror;
            if taken {
                for body_line in &lines[open + 1..close] {
                    out.push(dedent_once(body_line));
                }
            }
            i = close + 1;
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    out
}

fn unassigned_int_mirrors(lines: &[String]) -> std::collections::BTreeSet<String> {
    let declared: std::collections::BTreeSet<String> = declared_locals_of_type(
        lines,
        &[
            "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "nint", "nuint",
        ],
    );
    declared
        .into_iter()
        .filter(|name: &String| !lines.iter().any(|l: &String| line_assigns_local(l, name)))
        .collect()
}

fn entry_dispatch_condition(
    line: &str,
    mirrors: &std::collections::BTreeSet<String>,
) -> Option<(String, bool)> {
    let cond_span: (usize, usize) = condition_span(line)?;
    let cond: &str = line[cond_span.0..cond_span.1].trim();
    let (name, taken): (&str, bool) = cond
        .strip_suffix(" != 0")
        .map(|n: &str| (n, true))
        .or_else(|| cond.strip_suffix(" == 0").map(|n: &str| (n, false)))?;
    let name: &str = name.trim();
    mirrors.contains(name).then(|| (name.to_owned(), taken))
}

fn normalize_reference_null_conditions(lines: &[String]) -> Vec<String> {
    let refs: std::collections::BTreeSet<String> = reference_typed_locals(lines);
    if refs.is_empty() {
        return lines.to_vec();
    }
    lines
        .iter()
        .map(|line: &String| rewrite_reference_truthiness(line, &refs))
        .collect()
}

fn reference_typed_locals(lines: &[String]) -> std::collections::BTreeSet<String> {
    lines
        .iter()
        .filter_map(|line: &String| {
            let t: &str = line.trim();
            let inner: &str = t.strip_suffix(';')?;
            let (ty, name): (&str, &str) = inner.rsplit_once(' ')?;
            (is_local_name(name) && is_reference_type(ty)).then(|| name.to_owned())
        })
        .collect()
}

fn is_reference_type(ty: &str) -> bool {
    if ty == "object" || ty == "string" {
        return true;
    }
    if matches!(
        ty,
        "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "byte"
            | "sbyte"
            | "bool"
            | "char"
            | "float"
            | "double"
            | "decimal"
            | "nint"
            | "nuint"
            | "void"
    ) || ty.starts_with('!')
    {
        return false;
    }
    let leaf: &str = ty.rsplit('.').next().unwrap_or(ty);
    let head: &str = leaf.split('<').next().unwrap_or(leaf);
    if head.starts_with("Configured")
        || head.ends_with("Awaiter")
        || head.ends_with("Awaitable")
        || head.ends_with("Enumerator")
    {
        return false;
    }
    matches!(
        head,
        "List"
            | "Dictionary"
            | "HashSet"
            | "Queue"
            | "Stack"
            | "IReadOnlyList"
            | "IEnumerable"
            | "IEnumerator"
            | "ICollection"
            | "IList"
            | "Exception"
            | "Task"
            | "MethodInfo"
            | "Type"
    ) || (head
        .bytes()
        .next()
        .is_some_and(|b: u8| b.is_ascii_uppercase())
        && !is_value_type_head(head))
}

fn is_value_type_head(head: &str) -> bool {
    matches!(
        head,
        "ValueTuple"
            | "ValueTask"
            | "KeyValuePair"
            | "TimeSpan"
            | "DateTime"
            | "Guid"
            | "CancellationToken"
            | "Span"
            | "ReadOnlySpan"
            | "Memory"
            | "ReadOnlyMemory"
            | "Nullable"
    )
}

fn rewrite_reference_truthiness(line: &str, refs: &std::collections::BTreeSet<String>) -> String {
    let Some(cond_span): Option<(usize, usize)> = condition_span(line) else {
        return line.to_owned();
    };
    let prefix: &str = &line[..cond_span.0];
    let cond: &str = &line[cond_span.0..cond_span.1];
    let suffix: &str = &line[cond_span.1..];
    let Some(rewritten): Option<String> = reference_condition_rewrite(cond, refs) else {
        return line.to_owned();
    };
    format!("{prefix}{rewritten}{suffix}")
}

fn reference_condition_rewrite(
    cond: &str,
    refs: &std::collections::BTreeSet<String>,
) -> Option<String> {
    let trimmed: &str = cond.trim();
    if let Some(inner) = trimmed
        .strip_prefix("!(!")
        .and_then(|s: &str| s.strip_suffix(')'))
        && refs.contains(inner.trim())
    {
        return Some(format!("{} != null", inner.trim()));
    }
    if let Some(inner) = trimmed.strip_prefix('!')
        && refs.contains(inner.trim())
    {
        return Some(format!("{} == null", inner.trim()));
    }
    refs.contains(trimmed).then(|| format!("{trimmed} != null"))
}

fn normalize_bool_literal_residue(lines: &[String]) -> Vec<String> {
    let bools: std::collections::BTreeSet<String> = declared_locals_of_type(lines, &["bool"]);
    if bools.is_empty() {
        return lines.to_vec();
    }
    lines
        .iter()
        .map(|line: &String| rewrite_bool_literal_assign(line, &bools))
        .collect()
}

fn rewrite_bool_literal_assign(line: &str, bools: &std::collections::BTreeSet<String>) -> String {
    let trimmed: &str = line.trim_start();
    let indent: &str = &line[..line.len() - trimmed.len()];
    let Some((lhs, rhs)): Option<(&str, &str)> = trimmed
        .strip_suffix(';')
        .and_then(|s: &str| s.split_once(" = "))
    else {
        return line.to_owned();
    };
    if !bools.contains(lhs.trim()) {
        return line.to_owned();
    }
    let replacement: &str = match rhs.trim() {
        "0" => "false",
        "1" => "true",
        _ => return line.to_owned(),
    };
    format!("{indent}{lhs} = {replacement};")
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
    fn numeric_hoisted_closure_field_becomes_valid_identifier() {
        assert_eq!(
            parse_param_field("8__1.count = 0;"),
            Some(("__hoisted1".to_owned(), 4))
        );
        assert_eq!(
            replace_param_fields("    this.<>8__1 = new C();"),
            "    __hoisted1 = new C();"
        );
    }

    #[test]
    fn bare_value_statement_is_dropped_but_calls_and_labels_survive() {
        let lines: Vec<String> = vec![
            "    local2;".to_owned(),
            "    local3.GetResult();".to_owned(),
            "    IL_0079:;".to_owned(),
            "    total = local2;".to_owned(),
        ];
        let out: Vec<String> = drop_bare_value_statements(&lines);
        let joined: String = out.join("\n");
        assert!(
            !out.iter().any(|l: &String| l.trim() == "local2;"),
            "a bare value statement is dropped:\n{joined}"
        );
        assert!(
            joined.contains("local3.GetResult();"),
            "a side-effecting call statement survives:\n{joined}"
        );
        assert!(joined.contains("IL_0079:;"), "a label survives:\n{joined}");
        assert!(
            joined.contains("total = local2;"),
            "an assignment survives:\n{joined}"
        );
    }

    #[test]
    fn sanitize_residue_fixes_display_class_and_lambda_keeps_real_generics() {
        assert_eq!(
            sanitize_generated_residue("    x = new <>c__DisplayClass1_0();"),
            "    x = new __c__DisplayClass1_0();\n"
        );
        assert_eq!(
            sanitize_generated_residue("    f = x.<ParallelForAsync>b__0;"),
            "    f = x._ParallelForAsync_b__0;\n"
        );
        assert_eq!(
            sanitize_generated_residue("    y = new <>c__DisplayClass2_0<T>();"),
            "    y = new __c__DisplayClass2_0<T>();\n"
        );
    }

    #[test]
    fn sanitize_residue_leaves_comment_signature_line_untouched() {
        assert_eq!(
            sanitize_generated_residue(
                "// <Evens>d__0 [iterator state machine]\n    x = new <>c__DisplayClass0_0();\n"
            ),
            "// <Evens>d__0 [iterator state machine]\n    x = new __c__DisplayClass0_0();\n"
        );
    }

    #[test]
    fn sanitize_residue_leaves_real_generics_and_comparisons_alone() {
        assert_eq!(
            sanitize_generated_residue("    a = new List<int>();\n    if (i < count)\n"),
            "    a = new List<int>();\n    if (i < count)\n"
        );
    }

    #[test]
    fn builder_plumbing_recognized_without_address_of_receiver() {
        let sm: StateMachine = async_sm();
        assert!(is_plumbing_line("    this.<>t__builder.Complete();", &sm));
        assert!(is_plumbing_line(
            "    this.<>t__builder.Start(ref local0);",
            &sm
        ));
        assert!(is_plumbing_line(
            "    local1 = (&this.<>t__builder).get_Task();",
            &sm
        ));
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

    #[test]
    fn linearizes_single_await_dispatch() {
        let body: &str = concat!(
            "    local0 = this.<>1__state;\n",
            "    if (!local0)\n",
            "    {\n",
            "        local1 = this.<>u__1;\n",
            "        *(&this.<>u__1) = default(TaskAwaiter<int>);\n",
            "        local0 = -1;\n",
            "    }\n",
            "    else\n",
            "    {\n",
            "        local2 = Compute().GetAwaiter();\n",
            "        if (!((&local2).get_IsCompleted()))\n",
            "        {\n",
            "            local0 = 0;\n",
            "            this.<>u__1 = local2;\n",
            "        }\n",
            "        return;\n",
            "    }\n",
            "    local1 = (&local2).GetResult();\n",
            "    (&this.<>t__builder).SetResult(local1);\n",
        );
        let (out, points): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(
            out.contains("local2 = await Compute();"),
            "await recovered:\n{out}"
        );
        assert!(
            out.contains("return local1;"),
            "SetResult folded to return:\n{out}"
        );
        assert!(
            !out.contains("get_IsCompleted"),
            "completion scaffolding removed:\n{out}"
        );
        assert!(!out.contains("<>u__"), "awaiter plumbing removed:\n{out}");
        assert!(
            !out.contains("= this.<>1__state"),
            "state mirror load removed:\n{out}"
        );
        assert!(
            !out.contains("if (!local0)"),
            "resume dispatch guard collapsed:\n{out}"
        );
        assert_eq!(points, 1);
    }

    #[test]
    fn unwraps_async_exception_capture_wrapper() {
        let body: &str = concat!(
            "int local0;\n",
            "local0 = 1;\n",
            "try\n",
            "{\n",
            "    total = total + local0;\n",
            "    (&this.<>t__builder).SetResult(total);\n",
            "}\n",
            "catch (Exception ex)\n",
            "{\n",
            "    this.<>1__state = -2;\n",
            "    (&this.<>t__builder).SetException(ex);\n",
            "}\n",
        );
        let (out, _): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(
            out.contains("total = total + local0;"),
            "try body kept:\n{out}"
        );
        assert!(out.contains("return total;"), "SetResult folded:\n{out}");
        assert!(
            !out.contains("catch"),
            "compiler catch wrapper removed:\n{out}"
        );
        assert!(
            !out.contains("SetException"),
            "SetException removed:\n{out}"
        );
        assert!(
            out.contains("int local0;"),
            "a live pre-try local declaration is preserved:\n{out}"
        );
    }

    #[test]
    fn hoists_result_register_store_in_terminal_else_to_return() {
        let lines: Vec<String> = vec![
            "int local1;".to_owned(),
            "if (cond)".to_owned(),
            "{".to_owned(),
            "    local1 = total;".to_owned(),
            "    return local1;".to_owned(),
            "}".to_owned(),
            "else".to_owned(),
            "{".to_owned(),
            "    local1 = 0;".to_owned(),
            "}".to_owned(),
        ];
        let out: Vec<String> = hoist_result_register_returns(&lines);
        assert!(
            out.iter().any(|l: &String| l.trim() == "return 0;"),
            "terminal else result-register store becomes an early return:\n{}",
            out.join("\n")
        );
        assert!(
            out.iter().any(|l: &String| l.trim() == "return local1;"),
            "the staged success return is left intact:\n{}",
            out.join("\n")
        );
    }

    #[test]
    fn does_not_hoist_when_a_later_return_consumes_the_register() {
        let lines: Vec<String> = vec![
            "int local1;".to_owned(),
            "if (first)".to_owned(),
            "{".to_owned(),
            "    local1 = wrap5;".to_owned(),
            "    return local1;".to_owned(),
            "}".to_owned(),
            "if (cond)".to_owned(),
            "{".to_owned(),
            "    local1 = a;".to_owned(),
            "}".to_owned(),
            "else".to_owned(),
            "{".to_owned(),
            "    local1 = b;".to_owned(),
            "}".to_owned(),
            "scope = null;".to_owned(),
            "return local1;".to_owned(),
        ];
        let out: Vec<String> = hoist_result_register_returns(&lines);
        assert!(
            out.iter().any(|l: &String| l.trim() == "local1 = b;"),
            "a merge-prep store feeding a later return is not turned into an early return:\n{}",
            out.join("\n")
        );
        assert!(
            !out.iter().any(|l: &String| l.trim() == "return b;"),
            "no fabricated early return when a shared return follows the branch:\n{}",
            out.join("\n")
        );
    }

    #[test]
    fn iterator_keeps_real_try_catch_untouched() {
        let body: &str = concat!(
            "try\n",
            "{\n",
            "    DoWork();\n",
            "}\n",
            "catch (Exception ex)\n",
            "{\n",
            "    Log(ex);\n",
            "}\n",
        );
        let (out, _): (String, u32) = reverse_move_next(body, &iterator_sm());
        assert!(
            out.contains("catch") && out.contains("Log(ex);"),
            "a real user try/catch with work in the catch must NOT be unwrapped:\n{out}"
        );
    }

    #[test]
    fn keeps_dispatch_branch_with_real_work() {
        let body: &str = concat!(
            "    local0 = this.<>1__state;\n",
            "    if (!local0)\n",
            "    {\n",
            "        DoRealWork();\n",
            "    }\n",
        );
        let (out, _): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(
            out.contains("DoRealWork();"),
            "a dispatch branch holding real work is preserved, not dropped:\n{out}"
        );
    }

    #[test]
    fn collapses_post_await_completion_gate() {
        let lines: Vec<String> = vec![
            "    local2 = await (&local3);".to_owned(),
            "    if ((&local2).IsCompleted)".to_owned(),
            "    {".to_owned(),
            "        (&local2).GetResult();".to_owned(),
            "        DoWork();".to_owned(),
            "    }".to_owned(),
            "    else".to_owned(),
            "    {".to_owned(),
            "        local0 = 0;".to_owned(),
            "        return;".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = collapse_completion_gates(&lines);
        let joined: String = out.join("\n");
        assert!(joined.contains("DoWork();"), "then-body kept:\n{joined}");
        assert!(!joined.contains("IsCompleted"), "gate removed:\n{joined}");
        assert!(
            !joined.contains("GetResult"),
            "GetResult dropped:\n{joined}"
        );
        assert!(!joined.contains("else"), "else suspend dropped:\n{joined}");
    }

    #[test]
    fn drops_empty_negated_completion_gate() {
        let lines: Vec<String> = vec![
            "    local2 = await (&local3);".to_owned(),
            "    if (!((&local2).IsCompleted))".to_owned(),
            "    {".to_owned(),
            "    }".to_owned(),
            "    DoWork();".to_owned(),
        ];
        let out: Vec<String> = collapse_completion_gates(&lines);
        let joined: String = out.join("\n");
        assert!(
            !joined.contains("IsCompleted"),
            "empty gate removed:\n{joined}"
        );
        assert!(
            joined.contains("DoWork();"),
            "following code kept:\n{joined}"
        );
    }

    #[test]
    fn prunes_write_only_awaiter_local_but_keeps_returned_local() {
        let lines: Vec<String> = vec![
            "    int local1;".to_owned(),
            "    YieldAwaiter local2;".to_owned(),
            "    local2 = X();".to_owned(),
            "    local1 = total;".to_owned(),
            "    return local1;".to_owned(),
        ];
        let out: Vec<String> = drop_dead_awaiter_locals(&lines);
        let joined: String = out.join("\n");
        assert!(
            !joined.contains("local2"),
            "write-only awaiter dropped:\n{joined}"
        );
        assert!(
            joined.contains("X();"),
            "side-effecting call preserved:\n{joined}"
        );
        assert!(
            joined.contains("int local1;"),
            "read local decl kept:\n{joined}"
        );
        assert!(
            joined.contains("return local1;"),
            "read use kept:\n{joined}"
        );
    }

    #[test]
    fn return_local_counts_as_read_not_a_declaration() {
        assert_eq!(local_decl_name("    return local1;"), None);
        assert_eq!(local_decl_name("    int local1;"), Some("local1"));
        assert!(line_reads_local("    return local1;", "local1"));
    }

    #[test]
    fn folds_async_iterator_current_to_yield() {
        let lines: Vec<String> = vec![
            "    /*current*/ = i + 1;".to_owned(),
            "    /*current*/ = 0;".to_owned(),
        ];
        let out: Vec<String> = fold_yield_assignments(&lines, &async_sm());
        let joined: String = out.join("\n");
        assert!(
            joined.contains("yield return i + 1;"),
            "yield return:\n{joined}"
        );
        assert!(joined.contains("yield break;"), "yield break:\n{joined}");
    }

    #[test]
    fn folds_async_iterator_terminal_contract_after_yield_break() {
        let lines: Vec<String> = vec![
            "    /*current*/ = 0;".to_owned(),
            "    return 0;".to_owned(),
            "    return;".to_owned(),
        ];
        let out: Vec<String> = fold_yield_assignments(&lines, &async_sm());
        let joined: String = out.join("\n");
        assert_eq!(joined, "    yield break;");
    }

    #[test]
    fn dispatch_info_rethrow_recovers_captured_exception() {
        let lines: Vec<String> = vec![
            "    if (!(local6 as Exception))".to_owned(),
            "    {".to_owned(),
            "        throw local6;".to_owned(),
            "    }".to_owned(),
            "    Capture(__stack_underflow).Throw();".to_owned(),
        ];
        let out: Vec<String> = collapse_dispatch_info_rethrow(&lines);
        let joined: String = out.join("\n");
        assert_eq!(joined, "    throw local6;");
        assert!(
            !joined.contains("__stack_underflow"),
            "underflow eliminated:\n{joined}"
        );
    }

    #[test]
    fn dispatch_info_rethrow_keeps_unrelated_lines() {
        let lines: Vec<String> = vec![
            "    if (!(value as Exception))".to_owned(),
            "    {".to_owned(),
            "        Log(value);".to_owned(),
            "    }".to_owned(),
            "    DoWork();".to_owned(),
        ];
        let out: Vec<String> = collapse_dispatch_info_rethrow(&lines);
        assert_eq!(out, lines, "a non-rethrow guard must be left untouched");
    }

    #[test]
    fn orphan_label_dropped_when_its_goto_was_folded_away() {
        let lines: Vec<String> = vec!["    IL_0079:;".to_owned(), "    yield return x;".to_owned()];
        let out: Vec<String> = drop_orphan_labels(&lines);
        assert_eq!(out, vec!["    yield return x;".to_owned()]);
    }

    #[test]
    fn referenced_label_is_kept() {
        let lines: Vec<String> = vec![
            "    IL_0079:;".to_owned(),
            "    work();".to_owned(),
            "    goto IL_0079;".to_owned(),
        ];
        let out: Vec<String> = drop_orphan_labels(&lines);
        assert_eq!(out, lines, "a label with a live goto must survive");
    }

    #[test]
    fn simplify_awaiter_strips_address_of_and_collapses_get_result() {
        let lines: Vec<String> = vec![
            "    local4 = await (&local5);".to_owned(),
            "    local6 = (&local4).GetResult().GetEnumerator();".to_owned(),
        ];
        let out: Vec<String> = simplify_awaiter_results(&lines);
        let joined: String = out.join("\n");
        assert!(
            joined.contains("local4 = await local5;"),
            "address-of on the awaitable is stripped:\n{joined}"
        );
        assert!(
            joined.contains("local6 = local4.GetEnumerator();"),
            "GetResult on the awaited local collapses to the awaited value:\n{joined}"
        );
        assert!(!joined.contains("(&"), "no address-of residue:\n{joined}");
    }

    #[test]
    fn simplify_awaiter_normalizes_configure_await_bool() {
        let lines: Vec<String> = vec!["    local0 = await foo.ConfigureAwait(0);".to_owned()];
        let out: Vec<String> = simplify_awaiter_results(&lines);
        assert_eq!(out[0].trim(), "local0 = await foo.ConfigureAwait(false);");
    }

    #[test]
    fn drop_dead_after_transfer_removes_trailing_void_return() {
        let lines: Vec<String> = vec![
            "    return local2;".to_owned(),
            "    return;".to_owned(),
            "    DoWork();".to_owned(),
        ];
        let out: Vec<String> = drop_dead_after_transfer(&lines);
        let joined: String = out.join("\n");
        assert!(
            joined.contains("return local2;") && joined.contains("DoWork();"),
            "the value-return and the next live statement survive:\n{joined}"
        );
        assert_eq!(
            out.iter()
                .filter(|l: &&String| l.trim() == "return;")
                .count(),
            0,
            "the dead void-return after a value-return is dropped:\n{joined}"
        );
    }

    #[test]
    fn drop_unreferenced_local_decls_prunes_dead_awaiter_decl() {
        let lines: Vec<String> = vec![
            "    ConfiguredTaskAwaiter<int> local4;".to_owned(),
            "    int local1;".to_owned(),
            "    local1 = total;".to_owned(),
            "    return local1;".to_owned(),
        ];
        let out: Vec<String> = drop_unreferenced_local_decls(&lines);
        let joined: String = out.join("\n");
        assert!(
            !joined.contains("local4"),
            "an awaiter local with no remaining reference is pruned:\n{joined}"
        );
        assert!(
            joined.contains("int local1;") && joined.contains("return local1;"),
            "a referenced local declaration survives:\n{joined}"
        );
    }

    #[test]
    fn int_mirror_double_negation_becomes_not_equal_zero() {
        let lines: Vec<String> = vec![
            "    int local0;".to_owned(),
            "    if (!(!local0))".to_owned(),
        ];
        let out: Vec<String> = normalize_int_mirror_conditions(&lines);
        assert_eq!(out[1], "    if (local0 != 0)", "got:\n{}", out.join("\n"));
    }

    #[test]
    fn int_mirror_single_negation_becomes_equal_zero() {
        let lines: Vec<String> = vec!["int local2;".to_owned(), "if (!local2)".to_owned()];
        let out: Vec<String> = normalize_int_mirror_conditions(&lines);
        assert_eq!(out[1], "if (local2 == 0)", "got:\n{}", out.join("\n"));
    }

    #[test]
    fn int_truthiness_rewrite_does_not_touch_method_call_conditions() {
        let lines: Vec<String> = vec![
            "    int local0;".to_owned(),
            "    if (!(wrap2.MoveNext()))".to_owned(),
        ];
        let out: Vec<String> = normalize_int_mirror_conditions(&lines);
        assert_eq!(
            out[1],
            "    if (!(wrap2.MoveNext()))",
            "a bool method-call condition is preserved:\n{}",
            out.join("\n")
        );
    }

    #[test]
    fn bool_local_integer_literal_assignment_becomes_keyword() {
        let lines: Vec<String> = vec![
            "    bool local0;".to_owned(),
            "    local0 = 0;".to_owned(),
            "    local0 = 1;".to_owned(),
        ];
        let out: Vec<String> = normalize_bool_literal_residue(&lines);
        assert_eq!(out[1], "    local0 = false;", "got:\n{}", out.join("\n"));
        assert_eq!(out[2], "    local0 = true;", "got:\n{}", out.join("\n"));
    }

    #[test]
    fn bool_literal_rewrite_leaves_int_assignment_alone() {
        let lines: Vec<String> = vec!["int local1;".to_owned(), "local1 = 0;".to_owned()];
        let out: Vec<String> = normalize_bool_literal_residue(&lines);
        assert_eq!(out[1], "local1 = 0;", "an int local keeps its literal");
    }

    #[test]
    fn reference_local_truthiness_becomes_null_check() {
        let lines: Vec<String> = vec![
            "    object local6;".to_owned(),
            "    if (!(!local6))".to_owned(),
        ];
        let out: Vec<String> = normalize_reference_null_conditions(&lines);
        assert_eq!(
            out[1],
            "    if (local6 != null)",
            "got:\n{}",
            out.join("\n")
        );
    }

    #[test]
    fn reference_null_rewrite_skips_value_typed_locals() {
        let lines: Vec<String> = vec![
            "    System.ValueTuple<int, string> local3;".to_owned(),
            "    if (!(!local3))".to_owned(),
        ];
        let out: Vec<String> = normalize_reference_null_conditions(&lines);
        assert_eq!(
            out[1],
            "    if (!(!local3))",
            "a value-tuple local is not null-compared:\n{}",
            out.join("\n")
        );
    }

    #[test]
    fn entry_state_dispatch_inlines_fresh_body_for_unassigned_int_mirror() {
        let lines: Vec<String> = vec![
            "    int local0;".to_owned(),
            "    if (local0 != 0)".to_owned(),
            "    {".to_owned(),
            "        total = 0;".to_owned(),
            "        wrap2 = this.source.GetEnumerator();".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = collapse_entry_state_dispatch(&lines);
        let joined: String = out.join("\n");
        assert!(
            joined.contains("total = 0;")
                && joined.contains("wrap2 = this.source.GetEnumerator();"),
            "the fresh-entry body is inlined:\n{joined}"
        );
        assert!(
            !joined.contains("local0 != 0"),
            "the unassigned-mirror entry guard is collapsed:\n{joined}"
        );
    }

    #[test]
    fn entry_state_dispatch_keeps_guard_when_mirror_is_assigned() {
        let lines: Vec<String> = vec![
            "    int local0;".to_owned(),
            "    local0 = ComputeFlag();".to_owned(),
            "    if (local0 != 0)".to_owned(),
            "    {".to_owned(),
            "        DoWork();".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = collapse_entry_state_dispatch(&lines);
        let joined: String = out.join("\n");
        assert!(
            joined.contains("if (local0 != 0)"),
            "a genuinely-assigned int local keeps its conditional:\n{joined}"
        );
    }

    #[test]
    fn end_to_end_int_mirror_async_dispatch_is_recompile_clean_shape() {
        let body: &str = concat!(
            "    int local0;\n",
            "    int local1;\n",
            "    if (!(!local0))\n",
            "    {\n",
            "        local1 = Compute();\n",
            "    }\n",
            "    return local1;\n",
        );
        let (out, _): (String, u32) = reverse_move_next(body, &async_sm());
        assert!(
            !out.contains("!local0") && !out.contains("local0 != 0"),
            "the int-mirror dispatch is gone, not left as an invalid bang-on-int:\n{out}"
        );
        assert!(
            out.contains("local1 = Compute();"),
            "the fresh-entry work survives:\n{out}"
        );
    }

    #[test]
    fn lowers_type_var_placeholder_to_declared_param_name() {
        let body: &str =
            "    System.Collections.Generic.IEnumerator<!0> local2;\n    local3 = default(!0);\n";
        let names: Vec<String> = vec!["T".to_owned()];
        let out: String = lower_generic_placeholders(body, &names, &[]);
        assert!(out.contains("IEnumerator<T>"), "type var lowered:\n{out}");
        assert!(out.contains("default(T)"), "default lowered:\n{out}");
        assert!(!out.contains("!0"), "no placeholder residue:\n{out}");
    }

    #[test]
    fn lowers_multiple_method_and_type_vars_by_index() {
        let body: &str =
            "    if (!(local1.handlers.TryGetValue(typeof(!0), &local3)))\n    !1 local2;\n";
        let names: Vec<String> = vec!["TRequest".to_owned(), "TResponse".to_owned()];
        let out: String = lower_generic_placeholders(body, &names, &names);
        assert!(
            out.contains("typeof(TRequest)"),
            "index 0 -> TRequest:\n{out}"
        );
        assert!(
            out.contains("TResponse local2"),
            "index 1 -> TResponse:\n{out}"
        );
    }

    #[test]
    fn lowers_method_var_against_method_param_list() {
        let body: &str = "    !!0 local0;\n    local0 = default(!!1);\n    !0 local1;\n";
        let type_names: Vec<String> = vec!["TClass".to_owned()];
        let method_names: Vec<String> = vec!["TMethod".to_owned(), "UMethod".to_owned()];
        let out: String = lower_generic_placeholders(body, &type_names, &method_names);
        assert!(out.contains("TMethod local0"), "!!0 -> TMethod:\n{out}");
        assert!(out.contains("default(UMethod)"), "!!1 -> UMethod:\n{out}");
        assert!(out.contains("TClass local1"), "!0 -> TClass:\n{out}");
        assert!(!out.contains('!'), "no placeholder residue:\n{out}");
    }

    #[test]
    fn placeholder_lowering_keeps_logical_not_intact() {
        let body: &str = "    if (!visited.Add(node))\n";
        let names: Vec<String> = vec!["T".to_owned()];
        let out: String = lower_generic_placeholders(body, &names, &[]);
        assert_eq!(
            out, body,
            "a logical-not on an identifier must be untouched"
        );
    }

    #[test]
    fn placeholder_lowering_ignores_unmapped_index() {
        let body: &str = "    !5 local0;\n";
        let names: Vec<String> = vec!["T".to_owned()];
        let out: String = lower_generic_placeholders(body, &names, &[]);
        assert_eq!(out, body, "an out-of-range placeholder stays literal");
    }

    #[test]
    fn simplifies_local_address_deref_assignment() {
        let lines: Vec<String> = vec!["    *(&node) = default(T);".to_owned()];
        let out: Vec<String> = simplify_local_deref_assign(&lines);
        assert_eq!(out, vec!["    node = default(T);".to_owned()]);
    }

    #[test]
    fn deref_simplify_leaves_field_paths_alone() {
        let lines: Vec<String> =
            vec!["    *(&this.<>u__1) = default(TaskAwaiter<int>);".to_owned()];
        let out: Vec<String> = simplify_local_deref_assign(&lines);
        assert_eq!(out, lines, "a field-path deref clear must not be rewritten");
    }

    #[test]
    fn qualified_dispatch_info_rethrow_still_collapses() {
        let lines: Vec<String> = vec![
            "    if (!(local6 as Exception))".to_owned(),
            "    {".to_owned(),
            "        throw local6;".to_owned(),
            "    }".to_owned(),
            "    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(local6).Throw();"
                .to_owned(),
        ];
        let out: Vec<String> = collapse_dispatch_info_rethrow(&lines);
        assert_eq!(out.join("\n"), "    throw local6;");
    }

    #[test]
    fn resume_dispatch_with_goto_into_then_reconstructs_unconditional_body() {
        let lines: Vec<String> = vec![
            "    if (local0 == 0)".to_owned(),
            "    {".to_owned(),
            "        local2.GetResult();".to_owned(),
            "        running.Add(work);".to_owned(),
            "IL_0127:;".to_owned(),
            "        if (wrap2.MoveNext())".to_owned(),
            "        {".to_owned(),
            "        }".to_owned(),
            "        return result;".to_owned(),
            "    }".to_owned(),
            "    else".to_owned(),
            "    {".to_owned(),
            "        goto IL_0127;".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = reconstruct_resume_goto_dispatch(&lines);
        let joined: String = out.join("\n");
        assert!(
            !joined.contains("local0 == 0") && !joined.contains("goto IL_0127"),
            "the unassigned state-mirror resume guard and its back-goto are reconstructed away:\n{joined}"
        );
        assert!(
            joined.contains("local2.GetResult();") && joined.contains("running.Add(work);"),
            "the resume-prefix body work survives the reconstruction, it is not deleted:\n{joined}"
        );
        assert!(
            joined.contains("if (wrap2.MoveNext())") && joined.contains("return result;"),
            "the shared loop tail after the label is preserved:\n{joined}"
        );
    }

    #[test]
    fn convergent_user_if_else_with_back_goto_hoists_the_shared_tail() {
        let lines: Vec<String> = vec![
            "    if (!n.IsTerminal)".to_owned(),
            "    {".to_owned(),
            "IL_00A7:;".to_owned(),
            "        local4 = n.Children.GetEnumerator();".to_owned(),
            "    }".to_owned(),
            "    else".to_owned(),
            "    {".to_owned(),
            "        yield return p;".to_owned(),
            "        goto IL_00A7;".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = reconstruct_resume_goto_dispatch(&lines);
        let joined: String = out.join("\n");
        assert!(
            joined.contains("if (!n.IsTerminal)") && joined.contains("else"),
            "a genuine user condition is preserved, not dropped:\n{joined}"
        );
        assert!(
            joined.contains("yield return p;"),
            "the else-branch work survives:\n{joined}"
        );
        assert!(
            !joined.contains("goto IL_00A7"),
            "the back-goto into the then-branch is reconstructed into fall-through:\n{joined}"
        );
        let yield_idx: usize = out
            .iter()
            .position(|l: &String| l.trim() == "yield return p;")
            .expect("yield present");
        let tail_idx: usize = out
            .iter()
            .position(|l: &String| l.contains("n.Children.GetEnumerator()"))
            .expect("tail present");
        assert!(
            tail_idx > yield_idx,
            "the shared tail is hoisted after the if/else so both arms converge into it:\n{joined}"
        );
    }

    #[test]
    fn convergent_dispatch_leaves_an_if_else_without_a_back_goto_alone() {
        let lines: Vec<String> = vec![
            "    if (flag)".to_owned(),
            "    {".to_owned(),
            "        DoA();".to_owned(),
            "    }".to_owned(),
            "    else".to_owned(),
            "    {".to_owned(),
            "        DoB();".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = reconstruct_resume_goto_dispatch(&lines);
        assert_eq!(
            out, lines,
            "an ordinary if/else with no back-goto must be untouched"
        );
    }

    #[test]
    fn iterator_bool_return_register_becomes_yield_break() {
        let lines: Vec<String> = vec![
            "    bool local0;".to_owned(),
            "    while (e.MoveNext())".to_owned(),
            "    {".to_owned(),
            "        yield return e.Current;".to_owned(),
            "        local0 = true;".to_owned(),
            "    }".to_owned(),
            "    local0 = false;".to_owned(),
            "    return local0;".to_owned(),
        ];
        let out: Vec<String> = fold_iterator_return_register(&lines);
        let joined: String = out.join("\n");
        assert!(joined.contains("yield break;"), "got:\n{joined}");
        assert!(
            !joined.contains("return local0;"),
            "bool return removed:\n{joined}"
        );
        assert!(
            !joined.contains("local0 = true;"),
            "dead set removed:\n{joined}"
        );
        assert!(
            !joined.contains("local0 = false;"),
            "dead clear removed:\n{joined}"
        );
    }

    #[test]
    fn fold_register_leaves_real_value_return_alone() {
        let lines: Vec<String> = vec![
            "    int local1;".to_owned(),
            "    local1 = total;".to_owned(),
            "    return local1;".to_owned(),
        ];
        let out: Vec<String> = fold_iterator_return_register(&lines);
        assert_eq!(
            out, lines,
            "a non-bool value return must not be turned into yield break"
        );
    }

    #[test]
    fn dollar_in_generated_name_is_sanitized() {
        let body: &str = "    h.CS$<>8__locals1 = outer;\n";
        let out: String = sanitize_generated_residue(body);
        assert!(!out.contains('$'), "dollar removed:\n{out}");
        assert!(!out.contains("<>"), "angle residue removed:\n{out}");
        assert!(out.contains("CS___8__locals1"), "consistent name:\n{out}");
    }

    #[test]
    fn dollar_sanitization_is_consistent_across_sites() {
        let body: &str = "    h.CS$<>8__locals1 = outer;\n    use(h.CS$<>8__locals1.field);\n";
        let out: String = sanitize_generated_residue(body);
        let count: usize = out.matches("CS___8__locals1").count();
        assert_eq!(count, 2, "both sites rewritten identically:\n{out}");
    }

    #[test]
    fn thrown_object_local_retypes_to_exception() {
        let lines: Vec<String> = vec![
            "    object local6;".to_owned(),
            "    local6 = wrap3;".to_owned(),
            "    if (local6 != null)".to_owned(),
            "    {".to_owned(),
            "        throw local6;".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = retype_thrown_object_locals(&lines);
        assert!(
            out.contains(&"    Exception local6;".to_owned()),
            "thrown object local must be retyped to Exception:\n{out:?}"
        );
    }

    #[test]
    fn object_catch_head_retypes_to_exception() {
        let lines: Vec<String> = vec![
            "    catch (Object ex)".to_owned(),
            "    {".to_owned(),
            "    }".to_owned(),
        ];
        let out: Vec<String> = retype_thrown_object_locals(&lines);
        assert_eq!(out[0], "    catch (Exception ex)");
    }

    #[test]
    fn unthrown_object_local_is_left_alone() {
        let lines: Vec<String> = vec![
            "    object local6;".to_owned(),
            "    local6 = wrap3;".to_owned(),
        ];
        let out: Vec<String> = retype_thrown_object_locals(&lines);
        assert_eq!(
            out, lines,
            "an object local that is never thrown keeps its type"
        );
    }

    #[test]
    fn enumerator_disposal_clear_is_dropped() {
        let lines: Vec<String> = vec![
            "    wrap2 = default(Enumerator<int>);".to_owned(),
            "    wrap2 = default(ConfiguredCancelableAsyncEnumerable<int>.Enumerator);".to_owned(),
            "    local1 = sink;".to_owned(),
        ];
        let out: Vec<String> = drop_enumerator_disposal_clears(&lines);
        assert_eq!(out, vec!["    local1 = sink;".to_owned()]);
    }

    #[test]
    fn non_enumerator_default_clear_is_kept() {
        let lines: Vec<String> = vec!["    local2 = default(ValueTask<bool>);".to_owned()];
        let out: Vec<String> = drop_enumerator_disposal_clears(&lines);
        assert_eq!(
            out, lines,
            "a non-enumerator default clear must be preserved"
        );
    }

    #[test]
    fn object_catch_header_counts_as_async_wrapper() {
        assert!(is_catch_exception_header("catch (Object ex)"));
        assert!(is_catch_exception_header("catch (System.Object ex)"));
        assert!(is_catch_exception_header("catch (Exception ex)"));
        assert!(!is_catch_exception_header(
            "catch (OperationCanceledException ex)"
        ));
    }
}
