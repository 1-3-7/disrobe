use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::RenderedClass;

pub(super) const ACC_ENUM: u32 = 0x4000;

pub(super) struct EnumShape<'a> {
    pub(super) simple: &'a str,
    pub(super) qualified: &'a str,
    pub(super) constants: &'a [String],
}

pub(super) struct EnumParts {
    pub(super) prefix: String,
    pub(super) declaration: String,
    pub(super) simple: String,
    pub(super) qualified: String,
    pub(super) supertypes: String,
    pub(super) annotation_text: String,
    pub(super) fields_text: String,
    pub(super) member_texts: Vec<String>,
    pub(super) constants: Vec<String>,
}

struct ConstantInit {
    name: String,
    args: String,
    body_class: Option<String>,
}

pub(super) fn enum_keyword(declaration: &str) -> String {
    declaration
        .replace("abstract ", "")
        .replace("final ", "")
        .replace("class", "enum")
}

pub(super) fn enum_body(
    shape: &EnumShape<'_>,
    fields: &str,
    members: &[String],
    bodies: &BTreeMap<String, String>,
) -> Option<String> {
    let EnumShape {
        simple,
        qualified,
        constants,
    } = shape;
    if constants.is_empty() {
        return None;
    }
    let mut initialisers: Vec<ConstantInit> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    let mut saw_static_block: bool = false;
    let mut constructor_arity: Option<usize> = None;
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
            if is_accessor_constructor(first) {
                continue;
            }
            let rendered: String = enum_constructor(simple, member)?;
            constructor_arity = Some(parameter_count(first).saturating_sub(2));
            kept.push(rendered);
            continue;
        }
        kept.push(member.clone());
    }
    if !saw_static_block {
        return None;
    }
    let mut declared: Vec<&str> = initialisers
        .iter()
        .map(|init: &ConstantInit| init.name.as_str())
        .collect();
    declared.sort_unstable();
    let mut expected: Vec<&str> = constants.iter().map(String::as_str).collect();
    expected.sort_unstable();
    if declared != expected {
        return None;
    }
    let mut rendered: Vec<String> = Vec::with_capacity(initialisers.len());
    for init in &initialisers {
        let args: &str = trim_accessor_argument(&init.args, constructor_arity);
        let head: String = if args.is_empty() {
            init.name.clone()
        } else {
            format!("{}({args})", init.name)
        };
        match &init.body_class {
            None => rendered.push(head),
            Some(body_class) => {
                let body: &String = bodies.get(body_class)?;
                rendered.push(format!("{head} {{\n{body}    }}"));
            }
        }
    }
    let mut out: String = String::new();
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

pub(super) fn fold_constant_bodies(rendered: &mut BTreeMap<String, RenderedClass>) {
    let pending: Vec<String> = rendered
        .iter()
        .filter(|(_, class): &(&String, &RenderedClass)| class.enum_parts.is_some())
        .map(|(descriptor, _): (&String, &RenderedClass)| descriptor.clone())
        .collect();
    for descriptor in pending {
        let Some(parts): Option<&EnumParts> = rendered
            .get(&descriptor)
            .and_then(|class: &RenderedClass| class.enum_parts.as_ref())
        else {
            continue;
        };
        let Some(static_block): Option<&String> = parts
            .member_texts
            .iter()
            .find(|member: &&String| member.lines().next().unwrap_or("").trim() == "static {")
        else {
            continue;
        };
        let Some(initialisers): Option<Vec<ConstantInit>> =
            constant_initialisers(&parts.qualified, static_block)
        else {
            continue;
        };
        let body_classes: Vec<String> = initialisers
            .iter()
            .filter_map(|init: &ConstantInit| init.body_class.clone())
            .collect();
        if body_classes.is_empty() {
            continue;
        }
        let mut bodies: BTreeMap<String, String> = BTreeMap::new();
        let mut consumed: Vec<String> = Vec::new();
        for body_class in &body_classes {
            let Some((key, body)): Option<(String, String)> =
                constant_body(rendered, &parts.qualified, body_class)
            else {
                break;
            };
            bodies.insert(body_class.clone(), body);
            consumed.push(key);
        }
        if bodies.len() != body_classes.len() {
            continue;
        }
        let Some(body): Option<String> = enum_body(
            &EnumShape {
                simple: &parts.simple,
                qualified: &parts.qualified,
                constants: &parts.constants,
            },
            &parts.fields_text,
            &parts.member_texts,
            &bodies,
        ) else {
            continue;
        };
        let mut text: String = parts.prefix.clone();
        let _ = writeln!(
            text,
            "{} {}{} {{",
            enum_keyword(&parts.declaration),
            parts.simple,
            parts.supertypes
        );
        text.push_str(&parts.annotation_text);
        text.push_str(&body);
        text.push_str("}\n");
        let mut method_count: usize = 0;
        let mut fully_lifted: usize = 0;
        let mut fallback: usize = 0;
        for key in consumed {
            if let Some(folded) = rendered.remove(&key) {
                method_count += folded.method_count;
                fully_lifted += folded.fully_lifted;
                fallback += folded.fallback;
            }
        }
        if let Some(class) = rendered.get_mut(&descriptor) {
            class.text = text;
            class.enum_parts = None;
            class.method_count += method_count;
            class.fully_lifted += fully_lifted;
            class.fallback += fallback;
        }
    }
}

fn constant_body(
    rendered: &BTreeMap<String, RenderedClass>,
    qualified: &str,
    body_class: &str,
) -> Option<(String, String)> {
    let body_simple: &str = body_class.rsplit('.').next()?;
    let header_tail: String = format!("class {body_simple} extends {qualified} {{");
    let (key, class): (&String, &RenderedClass) =
        rendered
            .iter()
            .find(|(_, class): &(&String, &RenderedClass)| {
                class.enum_parts.is_none()
                    && class
                        .text
                        .lines()
                        .find(|line: &&str| line.contains(" class "))
                        .is_some_and(|line: &str| line.trim().ends_with(&header_tail))
            })?;
    let lines: Vec<&str> = class.text.lines().collect();
    let header: usize = lines
        .iter()
        .position(|line: &&str| line.trim().ends_with(&header_tail))?;
    let closing: usize = lines.iter().rposition(|line: &&str| *line == "}")?;
    if closing <= header {
        return None;
    }
    let ctor_prefixes: [String; 3] = [
        format!("public {body_simple}("),
        format!("private {body_simple}("),
        format!("{body_simple}("),
    ];
    let own_prefix: String = format!("{body_class}.");
    let base_prefix: String = format!("{qualified}.");
    let mut body: String = String::new();
    let mut skipping_constructor: bool = false;
    for line in &lines[header + 1..closing] {
        let is_member_start: bool = line.starts_with("    ") && !line.starts_with("     ");
        if is_member_start {
            let trimmed: &str = line.trim();
            if trimmed == "}" {
                if skipping_constructor {
                    skipping_constructor = false;
                    continue;
                }
            } else {
                skipping_constructor = ctor_prefixes
                    .iter()
                    .any(|prefix: &String| trimmed.starts_with(prefix.as_str()));
            }
        }
        if skipping_constructor {
            continue;
        }
        let _ = writeln!(body, "    {}", line.replace(&own_prefix, &base_prefix));
    }
    Some((key.clone(), body))
}

fn constant_initialisers(qualified: &str, block: &str) -> Option<Vec<ConstantInit>> {
    let mut out: Vec<ConstantInit> = Vec::new();
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
        let allocated: &str = value.strip_prefix("new ")?.strip_suffix(");")?;
        let (class, tail): (&str, &str) = allocated.split_once("(\"")?;
        let body_class: Option<String> = if class == qualified {
            None
        } else {
            let suffix: &str = class.strip_prefix(qualified)?.strip_prefix("$_")?;
            if suffix.is_empty() || !suffix.bytes().all(|b: u8| b.is_ascii_digit()) {
                return None;
            }
            Some(class.to_owned())
        };
        let allocation: &str = tail.strip_prefix(&format!("{field}\", "))?;
        let (ordinal, args): (&str, &str) = match allocation.split_once(", ") {
            Some((ordinal, args)) => (ordinal, args),
            None => (allocation, ""),
        };
        if ordinal.parse::<usize>().ok()? != out.len() {
            return None;
        }
        out.push(ConstantInit {
            name: field.to_owned(),
            args: args.to_owned(),
            body_class,
        });
    }
    Some(out)
}

fn trim_accessor_argument(args: &str, constructor_arity: Option<usize>) -> &str {
    let Some(arity) = constructor_arity else {
        return args;
    };
    if args.is_empty() {
        return args;
    }
    let count: usize = args.split(", ").count();
    if count == arity + 1
        && let Some(trimmed) = args.strip_suffix(", null")
    {
        return trimmed;
    }
    if arity == 0 && args == "null" {
        return "";
    }
    args
}

fn parameter_count(first: &str) -> usize {
    let Some(open) = first.find('(') else {
        return 0;
    };
    let Some(close) = first.rfind(')') else {
        return 0;
    };
    let params: &str = first[open + 1..close].trim();
    if params.is_empty() {
        0
    } else {
        params.split(", ").count()
    }
}

fn is_accessor_constructor(first: &str) -> bool {
    let Some(open) = first.find('(') else {
        return false;
    };
    let Some(close) = first.rfind(')') else {
        return false;
    };
    first[open + 1..close]
        .rsplit(", ")
        .next()
        .and_then(|param: &str| param.split_whitespace().next())
        .is_some_and(|ty: &str| ty.contains("$_") || ty.ends_with("_u002D_IA"))
}

fn is_enum_synthetic(simple: &str, qualified: &str, first: &str) -> bool {
    let values: String = format!("public static {qualified}[] values()");
    let value_of: String = format!("public static {qualified} valueOf(String ");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> String {
        let mut out: String = text.join("\n");
        out.push('\n');
        out
    }

    fn member(text: &[&str]) -> String {
        text.join("\n")
    }

    fn rendered(text: &str) -> RenderedClass {
        RenderedClass {
            text: text.to_owned(),
            source_path: "X.java".to_owned(),
            method_count: 1,
            fully_lifted: 1,
            fallback: 0,
            enum_parts: None,
        }
    }

    #[test]
    fn constant_subclasses_fold_into_constant_bodies() {
        let parts: EnumParts = EnumParts {
            prefix: String::new(),
            declaration: "public static abstract class".to_owned(),
            simple: "Op".to_owned(),
            qualified: "Outer.Op".to_owned(),
            supertypes: String::new(),
            annotation_text: String::new(),
            fields_text: lines(&[
                "    public static Outer.Op[] $VALUES;",
                "    public static Outer.Op ADD;",
                "    public static Outer.Op SUB;",
                "    public String sign;",
            ]),
            member_texts: vec![
                member(&[
                    "    static {",
                    "        Outer.Op.ADD = new Outer.Op$_1(\"ADD\", 0, \"+\");",
                    "        Outer.Op.SUB = new Outer.Op(\"SUB\", 1, \"-\", null);",
                    "        Outer.Op.$VALUES = Outer.Op.$values();",
                    "    }",
                ]),
                member(&[
                    "    public Op(String arg0, int arg1, String arg2) {",
                    "        super(arg0, arg1);",
                    "        this.sign = arg2;",
                    "    }",
                ]),
                member(&[
                    "    public Op(String arg0, int arg1, String arg2, Outer$_1 arg3) {",
                    "        this(arg0, arg1, arg2);",
                    "    }",
                ]),
                "    public abstract int apply(int arg0, int arg1);".to_owned(),
            ],
            constants: vec!["ADD".to_owned(), "SUB".to_owned()],
        };
        let mut classes: BTreeMap<String, RenderedClass> = BTreeMap::new();
        let mut op: RenderedClass = rendered("public static abstract class Op {\n}\n");
        op.enum_parts = Some(parts);
        classes.insert("LOuter$Op;".to_owned(), op);
        classes.insert(
            "LOuter$Op$1;".to_owned(),
            rendered(&lines(&[
                "static final class Op$_1 extends Outer.Op {",
                "    public Op$_1(String arg0, int arg1, String arg2) {",
                "        super(arg0, arg1, arg2, null);",
                "    }",
                "    public int apply(int arg0, int arg1) {",
                "        return Outer.Op$_1.SUB.apply(arg0, arg1) + 1;",
                "    }",
                "}",
            ])),
        );
        fold_constant_bodies(&mut classes);
        assert!(!classes.contains_key("LOuter$Op$1;"));
        let folded: &RenderedClass = &classes["LOuter$Op;"];
        assert_eq!(folded.method_count, 2);
        assert_eq!(
            folded.text,
            lines(&[
                "public static enum Op {",
                "    ADD(\"+\") {",
                "        public int apply(int arg0, int arg1) {",
                "            return Outer.Op.SUB.apply(arg0, arg1) + 1;",
                "        }",
                "    },",
                "    SUB(\"-\");",
                "    public String sign;",
                "    Op(String arg2) {",
                "        this.sign = arg2;",
                "    }",
                "    public abstract int apply(int arg0, int arg1);",
                "}",
            ])
        );
    }

    #[test]
    fn a_missing_constant_subclass_keeps_the_class_form() {
        let parts: EnumParts = EnumParts {
            prefix: String::new(),
            declaration: "public static class".to_owned(),
            simple: "Mode".to_owned(),
            qualified: "Outer.Mode".to_owned(),
            supertypes: String::new(),
            annotation_text: String::new(),
            fields_text: lines(&["    public static Outer.Mode FAST;"]),
            member_texts: vec![member(&[
                "    static {",
                "        Outer.Mode.FAST = new Outer.Mode$_1(\"FAST\", 0);",
                "    }",
            ])],
            constants: vec!["FAST".to_owned()],
        };
        let mut classes: BTreeMap<String, RenderedClass> = BTreeMap::new();
        let mut mode: RenderedClass = rendered("public static class Mode {\n}\n");
        mode.enum_parts = Some(parts);
        classes.insert("LOuter$Mode;".to_owned(), mode);
        fold_constant_bodies(&mut classes);
        assert_eq!(
            classes["LOuter$Mode;"].text,
            "public static class Mode {\n}\n"
        );
    }
}
