use std::fmt::Write as _;

pub(super) const ACC_ENUM: u32 = 0x4000;

pub(super) struct EnumShape<'a> {
    pub(super) simple: &'a str,
    pub(super) qualified: &'a str,
    pub(super) constants: &'a [String],
}

pub(super) fn enum_body(shape: &EnumShape<'_>, fields: &str, members: &[String]) -> Option<String> {
    let EnumShape {
        simple,
        qualified,
        constants,
    } = shape;
    if constants.is_empty() {
        return None;
    }
    let mut initialisers: Vec<(String, String)> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    let mut saw_static_block: bool = false;
    for member in members {
        let first: &str = member.lines().next().unwrap_or("").trim();
        if first == "static {" {
            if saw_static_block {
                return None;
            }
            saw_static_block = true;
            initialisers = constant_initialisers(qualified, member)?;
            continue;
        }
        if is_enum_synthetic(simple, qualified, first) {
            continue;
        }
        if first.starts_with(&format!("public {simple}(String arg0, int arg1"))
            || first.starts_with(&format!("private {simple}(String arg0, int arg1"))
            || first.starts_with(&format!("{simple}(String arg0, int arg1"))
        {
            kept.push(enum_constructor(simple, member)?);
            continue;
        }
        kept.push(member.clone());
    }
    if !saw_static_block {
        return None;
    }
    let mut declared: Vec<&str> = initialisers
        .iter()
        .map(|(name, _): &(String, String)| name.as_str())
        .collect();
    declared.sort_unstable();
    let mut expected: Vec<&str> = constants.iter().map(String::as_str).collect();
    expected.sort_unstable();
    if declared != expected {
        return None;
    }
    let mut out: String = String::new();
    let rendered: Vec<String> = initialisers
        .iter()
        .map(|(name, args): &(String, String)| {
            if args.is_empty() {
                name.clone()
            } else {
                format!("{name}({args})")
            }
        })
        .collect();
    let _ = writeln!(out, "    {};", rendered.join(",\n    "));
    for line in fields.lines() {
        if is_constant_field(qualified, constants, line) {
            continue;
        }
        let _ = writeln!(out, "{line}");
    }
    for member in kept {
        let _ = writeln!(out, "{member}");
    }
    Some(out)
}

fn constant_initialisers(qualified: &str, block: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in block.lines() {
        let line: &str = raw.trim();
        if line.is_empty() || line == "static {" || line == "}" {
            continue;
        }
        let rest: &str = line.strip_prefix(&format!("{qualified}."))?;
        let (field, value): (&str, &str) = rest.split_once(" = ")?;
        if field == "$VALUES" {
            let values_call: bool = value == format!("{qualified}.$values();")
                || value.starts_with(&format!("new {qualified}[]"));
            if values_call {
                continue;
            }
            return None;
        }
        let allocation: &str = value
            .strip_prefix(&format!("new {qualified}(\"{field}\", "))?
            .strip_suffix(");")?;
        let (ordinal, args): (&str, &str) = match allocation.split_once(", ") {
            Some((ordinal, args)) => (ordinal, args),
            None => (allocation, ""),
        };
        if ordinal.parse::<usize>().ok()? != out.len() {
            return None;
        }
        out.push((field.to_owned(), args.to_owned()));
    }
    Some(out)
}

fn is_enum_synthetic(simple: &str, qualified: &str, first: &str) -> bool {
    let values: String = format!("public static {qualified}[] values()");
    let value_of: String = format!("public static {qualified} valueOf(String arg0)");
    let synthetic_values: String = format!("static {qualified}[] $values()");
    first.starts_with(&values)
        || first.starts_with(&value_of)
        || first.contains(&synthetic_values)
        || first.starts_with(&format!("public static {qualified}[] $values()"))
        || first == format!("{simple}() {{")
}

fn enum_constructor(simple: &str, member: &str) -> Option<String> {
    let mut lines = member.lines();
    let first: &str = lines.next()?;
    let open: usize = first.find('(')?;
    let close: usize = first.rfind(')')?;
    let params: &str = &first[open + 1..close];
    let rest: &str = params
        .strip_prefix("String arg0, int arg1")
        .map(|rest: &str| rest.strip_prefix(", ").unwrap_or(rest))?;
    let mut out: String = format!("    {simple}({rest}){}", &first[close + 1..]);
    out.push('\n');
    for line in lines {
        if line.trim() == "super(arg0, arg1);" {
            continue;
        }
        let _ = writeln!(out, "{line}");
    }
    Some(out.trim_end_matches('\n').to_owned())
}

fn is_constant_field(qualified: &str, constants: &[String], line: &str) -> bool {
    let trimmed: &str = line.trim();
    if !trimmed.contains("static ") {
        return false;
    }
    if trimmed.ends_with(" $VALUES;") && trimmed.contains(&format!("{qualified}[]")) {
        return true;
    }
    constants
        .iter()
        .any(|name: &String| trimmed.ends_with(&format!("{qualified} {name};")))
}
