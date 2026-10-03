const HANDLER_TYPE: &str = "System.Runtime.CompilerServices.DefaultInterpolatedStringHandler";

#[must_use]
pub(crate) fn lower_interpolated_strings(body: &str) -> String {
    let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
    let mut changed: bool = false;
    let mut index: usize = 0;
    while index < lines.len() {
        if let Some(next) = lower_at(&mut lines, index) {
            changed = true;
            index = next;
        } else {
            index += 1;
        }
    }
    if !changed {
        return body.to_owned();
    }
    let mut out: String = lines.join("\n");
    if body.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn lower_at(lines: &mut Vec<String>, start: usize) -> Option<usize> {
    let opening: &str = lines.get(start)?.trim();
    let (handler, rest): (&str, &str) = opening.split_once(" = new ")?;
    if !is_local_name(handler) {
        return None;
    }
    let arguments: &str = rest
        .strip_prefix(HANDLER_TYPE)?
        .strip_prefix('(')?
        .strip_suffix(");")?;
    if split_top_level(arguments).len() != 2 {
        return None;
    }
    let handler: String = handler.to_owned();
    let mut text: String = String::new();
    let mut cursor: usize = start + 1;
    let prefix: String = format!("{handler}.");
    loop {
        let line: &str = lines.get(cursor)?.trim();
        let Some(call) = line.strip_prefix(&prefix) else {
            break;
        };
        if let Some(literal) = call
            .strip_prefix("AppendLiteral(")
            .and_then(|c: &str| c.strip_suffix(");"))
        {
            text.push_str(&literal_part(literal)?);
        } else if let Some(arguments) = call
            .strip_prefix("AppendFormatted(")
            .and_then(|c: &str| c.strip_suffix(");"))
        {
            text.push_str(&hole(arguments)?);
        } else {
            break;
        }
        cursor += 1;
    }
    let consumer: String = lines.get(cursor)?.clone();
    let finish: String = format!("{handler}.ToStringAndClear()");
    if consumer.matches(&finish).count() != 1 {
        return None;
    }
    let restart: String = format!("{handler} = new {HANDLER_TYPE}(");
    let reused_without_restart: bool = lines
        .iter()
        .skip(cursor + 1)
        .find(|l: &&String| mentions(l, &handler))
        .is_some_and(|l: &String| !l.trim().starts_with(&restart));
    if reused_without_restart {
        return None;
    }
    let lowered: String = consumer.replacen(&finish, &format!("$\"{text}\""), 1);
    lines.splice(start..=cursor, std::iter::once(lowered));
    let declaration: String = format!("{HANDLER_TYPE} {handler};");
    let declared_at: Option<usize> = lines.iter().position(|l: &String| l.trim() == declaration);
    let remaining: usize = lines
        .iter()
        .filter(|l: &&String| mentions(l, &handler))
        .count();
    if let Some(at) = declared_at
        && remaining == 1
    {
        lines.remove(at);
        return Some(start.saturating_sub(1));
    }
    Some(start)
}

fn is_local_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn mentions(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(at, _): (usize, &str)| {
        let before: bool = line[..at]
            .chars()
            .next_back()
            .is_none_or(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        let after: bool = line[at + name.len()..]
            .chars()
            .next()
            .is_none_or(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        before && after
    })
}

fn literal_part(literal: &str) -> Option<String> {
    let inner: &str = literal.strip_prefix('"')?.strip_suffix('"')?;
    let mut escaped: bool = false;
    for c in inner.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return None;
        }
    }
    if escaped {
        return None;
    }
    Some(inner.replace('{', "{{").replace('}', "}}"))
}

fn hole(arguments: &str) -> Option<String> {
    let parts: Vec<String> = split_top_level(arguments);
    let value: &str = parts.first()?.trim();
    if value.is_empty() {
        return None;
    }
    let simple: bool = value
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    let mut out: String = if simple {
        format!("{{{value}")
    } else {
        format!("{{({value})")
    };
    match parts.len() {
        1 => {}
        2 => out.push_str(&qualifier(parts[1].trim())?),
        3 => {
            out.push_str(&alignment(parts[1].trim())?);
            out.push_str(&format_part(parts[2].trim())?);
        }
        _ => return None,
    }
    out.push('}');
    Some(out)
}

fn qualifier(part: &str) -> Option<String> {
    if part.starts_with('"') {
        format_part(part)
    } else {
        alignment(part)
    }
}

fn alignment(part: &str) -> Option<String> {
    let digits: &str = part.strip_prefix('-').unwrap_or(part);
    (!digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit()))
        .then(|| format!(",{part}"))
}

fn format_part(part: &str) -> Option<String> {
    if part == "null" {
        return Some(String::new());
    }
    let inner: &str = part.strip_prefix('"')?.strip_suffix('"')?;
    if inner.is_empty() || inner.contains(['"', '\\', '{', '}']) {
        return None;
    }
    Some(format!(":{inner}"))
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut current: String = String::new();
    let mut quote: Option<char> = None;
    let mut escaped: bool = false;
    for c in text.chars() {
        if let Some(open) = quote {
            current.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(current);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handler_sequence_becomes_one_interpolated_string() {
        let body: &str = concat!(
            "{\n",
            "    System.Runtime.CompilerServices.DefaultInterpolatedStringHandler local7;\n",
            "\n",
            "    local7 = new System.Runtime.CompilerServices.DefaultInterpolatedStringHandler(1, 2);\n",
            "    local7.AppendFormatted(local3);\n",
            "    local7.AppendLiteral(\"-{\");\n",
            "    local7.AppendFormatted(local1 % 5, \"D2\");\n",
            "    local8 = local7.ToStringAndClear();\n",
            "}\n"
        );
        let lowered: String = lower_interpolated_strings(body);
        assert_eq!(
            lowered,
            "{\n\n    local8 = $\"{local3}-{{{(local1 % 5):D2}\";\n}\n"
        );
    }

    #[test]
    fn a_handler_used_elsewhere_is_left_alone() {
        let body: &str = concat!(
            "    local7 = new System.Runtime.CompilerServices.DefaultInterpolatedStringHandler(1, 1);\n",
            "    local7.AppendFormatted(local3);\n",
            "    local8 = local7.ToStringAndClear();\n",
            "    local9 = local7.ToStringAndClear();\n"
        );
        assert_eq!(lower_interpolated_strings(body), body);
    }
}
