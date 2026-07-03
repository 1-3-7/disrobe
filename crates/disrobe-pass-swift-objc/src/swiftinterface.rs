use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::swift_reflect::{SwiftField, SwiftTypeReflection};

const FORMAT_MARKER: &str = "swift-interface-format-version";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceDeclKind {
    Class,
    Struct,
    Enum,
    Protocol,
    Extension,
    Actor,
}

impl InterfaceDeclKind {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Protocol => "protocol",
            Self::Extension => "extension",
            Self::Actor => "actor",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceProperty {
    pub name: String,
    pub type_name: Option<String>,
    pub is_let: bool,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceMethod {
    pub name: String,
    pub signature: String,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceCase {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceDecl {
    pub kind: InterfaceDeclKind,
    pub name: String,
    pub conformances: Vec<String>,
    pub properties: Vec<InterfaceProperty>,
    pub methods: Vec<InterfaceMethod>,
    pub cases: Vec<InterfaceCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedInterface {
    pub format_version: Option<String>,
    pub module_name: Option<String>,
    pub decls: Vec<InterfaceDecl>,
}

impl ParsedInterface {
    #[must_use]
    pub fn resilient_field_names(&self) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for decl in &self.decls {
            let mut names: Vec<String> = Vec::new();
            names.extend(
                decl.properties
                    .iter()
                    .map(|p: &InterfaceProperty| p.name.clone()),
            );
            names.extend(decl.cases.iter().map(|c: &InterfaceCase| c.name.clone()));
            if !names.is_empty() {
                out.insert(decl.name.clone(), names);
            }
        }
        out
    }
}

#[must_use]
pub fn merge_elided_field_names(
    reflected: Vec<SwiftTypeReflection>,
    interface: &ParsedInterface,
) -> (Vec<SwiftTypeReflection>, usize) {
    let index: BTreeMap<String, Vec<String>> = interface.resilient_field_names();
    let mut filled: usize = 0;
    let mut out: Vec<SwiftTypeReflection> = Vec::with_capacity(reflected.len());
    for mut ty in reflected {
        let short_name: Option<&str> = ty.demangled_type_name.as_deref().map(short_type_name);
        if let Some(name) = short_name
            && let Some(source_names) = index.get(name)
        {
            for (slot, recovered) in ty.fields.iter_mut().zip(source_names.iter()) {
                if slot.name.is_empty() {
                    recovered.clone_into(&mut slot.name);
                    filled += 1;
                }
            }
            for recovered in source_names.iter().skip(ty.fields.len()) {
                ty.fields.push(SwiftField {
                    name: recovered.clone(),
                    mangled_type: None,
                    demangled_type: None,
                    is_indirect_enum_case: false,
                    is_var: false,
                });
                filled += 1;
            }
        }
        out.push(ty);
    }
    (out, filled)
}

fn short_type_name(full: &str) -> &str {
    full.rsplit('.').next().unwrap_or(full)
}

#[must_use]
pub fn looks_like_swiftinterface(text: &str) -> bool {
    text.lines()
        .take(8)
        .any(|l: &str| l.contains(FORMAT_MARKER))
}

#[must_use]
pub fn parse(text: &str) -> ParsedInterface {
    crate::debug::dbg_section("swiftinterface parse");
    crate::debug::dbg_kv("input", || {
        format!(
            "bytes={} lines={} is_swiftinterface={}",
            text.len(),
            text.lines().count(),
            looks_like_swiftinterface(text)
        )
    });
    let mut format_version: Option<String> = None;
    let mut module_name: Option<String> = None;
    let mut decls: Vec<InterfaceDecl> = Vec::new();
    let mut current: Option<InterfaceDecl> = None;
    let mut depth_after_open: usize = 0;

    for raw_line in text.lines() {
        let line: &str = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("// ") {
            scan_directive(rest, &mut format_version, &mut module_name);
            continue;
        }
        if line.starts_with("//") {
            continue;
        }

        let opens: usize = line.matches('{').count();
        let closes: usize = line.matches('}').count();

        if let Some(decl) = &mut current {
            if line.starts_with('}') {
                if depth_after_open == 0 {
                    if let Some(finished) = current.take() {
                        decls.push(finished);
                    }
                    continue;
                }
                depth_after_open -= 1;
                continue;
            }
            depth_after_open += opens.saturating_sub(closes);
            consume_member(line, decl);
            continue;
        }

        if let Some(kind) = decl_kind_of(line) {
            let parsed: InterfaceDecl = parse_decl_header(line, kind);
            if opens > 0 && opens == closes {
                decls.push(parsed);
            } else if opens > 0 {
                current = Some(parsed);
                depth_after_open = opens - 1;
            } else {
                current = Some(parsed);
                depth_after_open = 0;
            }
        }
    }
    if let Some(finished) = current.take() {
        decls.push(finished);
    }

    crate::debug::dbg_kv("parsed", || {
        let methods: usize = decls.iter().map(|d: &InterfaceDecl| d.methods.len()).sum();
        let props: usize = decls
            .iter()
            .map(|d: &InterfaceDecl| d.properties.len())
            .sum();
        format!(
            "format_version={format_version:?} module={module_name:?} decls={} methods={methods} properties={props}",
            decls.len()
        )
    });
    ParsedInterface {
        format_version,
        module_name,
        decls,
    }
}

fn scan_directive(
    rest: &str,
    format_version: &mut Option<String>,
    module_name: &mut Option<String>,
) {
    if let Some(value) = rest.strip_prefix(FORMAT_MARKER) {
        let trimmed: &str = value.trim_start_matches([':', ' ']);
        if !trimmed.is_empty() {
            *format_version = Some(trimmed.to_owned());
        }
    } else if let Some(value) = rest.strip_prefix("swift-module-flags:")
        && let Some(name) = extract_module_name_flag(value)
    {
        *module_name = Some(name);
    }
}

fn extract_module_name_flag(flags: &str) -> Option<String> {
    let mut tokens: std::str::SplitWhitespace<'_> = flags.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "-module-name" {
            return tokens.next().map(str::to_owned);
        }
    }
    None
}

fn decl_kind_of(line: &str) -> Option<InterfaceDeclKind> {
    let without_attrs: &str = strip_leading_modifiers(line);
    let first: &str = without_attrs.split_whitespace().next()?;
    match first {
        "class" => Some(InterfaceDeclKind::Class),
        "struct" => Some(InterfaceDeclKind::Struct),
        "enum" => Some(InterfaceDeclKind::Enum),
        "protocol" => Some(InterfaceDeclKind::Protocol),
        "extension" => Some(InterfaceDeclKind::Extension),
        "actor" => Some(InterfaceDeclKind::Actor),
        _ => None,
    }
}

fn strip_leading_modifiers(line: &str) -> &str {
    let mut rest: &str = line;
    loop {
        let trimmed: &str = rest.trim_start();
        let word: Option<&str> = trimmed.split_whitespace().next();
        match word {
            Some(w)
                if w.starts_with('@')
                    || matches!(
                        w,
                        "public"
                            | "open"
                            | "internal"
                            | "final"
                            | "indirect"
                            | "fileprivate"
                            | "private"
                    ) =>
            {
                rest = &trimmed[w.len()..];
            }
            _ => return trimmed,
        }
    }
}

fn parse_decl_header(line: &str, kind: InterfaceDeclKind) -> InterfaceDecl {
    let body: &str = strip_leading_modifiers(line);
    let after_keyword: &str = body
        .strip_prefix(kind.keyword())
        .map_or(body, |s: &str| s.trim_start());
    let head: &str = after_keyword.split('{').next().unwrap_or(after_keyword);
    let (name_part, conformance_part): (&str, &str) = match head.split_once(':') {
        Some((n, c)) => (n.trim(), c),
        None => (head.trim(), ""),
    };
    let name: String = name_part
        .split(['<', ' '])
        .next()
        .unwrap_or(name_part)
        .trim()
        .to_owned();
    let conformances: Vec<String> = conformance_part
        .split([',', '&'])
        .map(str::trim)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
        .collect();
    InterfaceDecl {
        kind,
        name,
        conformances,
        properties: Vec::new(),
        methods: Vec::new(),
        cases: Vec::new(),
    }
}

fn consume_member(line: &str, decl: &mut InterfaceDecl) {
    let body: &str = strip_leading_modifiers(line);
    let is_static: bool = line.contains("static ") || line.contains("class var ");
    if let Some(rest) = body
        .strip_prefix("let ")
        .or_else(|| body.strip_prefix("var "))
    {
        let is_let: bool = body.starts_with("let ");
        if let Some(prop) = parse_property(rest, is_let, is_static) {
            decl.properties.push(prop);
        }
        return;
    }
    if let Some(rest) = body.strip_prefix("func ") {
        if let Some(method) = parse_method(rest, is_static) {
            decl.methods.push(method);
        }
        return;
    }
    if let Some(rest) = body.strip_prefix("case ") {
        for case in parse_cases(rest) {
            decl.cases.push(case);
        }
    }
}

fn parse_property(rest: &str, is_let: bool, is_static: bool) -> Option<InterfaceProperty> {
    let head: &str = rest.split('{').next().unwrap_or(rest).trim();
    let (name_raw, type_raw): (&str, Option<&str>) = match head.split_once(':') {
        Some((n, t)) => (n.trim(), Some(t.trim())),
        None => (head.trim(), None),
    };
    let name: String = name_raw
        .split_whitespace()
        .next()
        .unwrap_or(name_raw)
        .to_owned();
    if name.is_empty() {
        return None;
    }
    let type_name: Option<String> = type_raw
        .map(|t: &str| t.trim_end_matches(['=', ' ']).trim())
        .filter(|t: &&str| !t.is_empty())
        .map(str::to_owned);
    Some(InterfaceProperty {
        name,
        type_name,
        is_let,
        is_static,
    })
}

fn parse_method(rest: &str, is_static: bool) -> Option<InterfaceMethod> {
    let trimmed: &str = rest.trim();
    let name: String = trimmed
        .split(['(', '<', ' '])
        .next()
        .unwrap_or(trimmed)
        .to_owned();
    if name.is_empty() {
        return None;
    }
    let signature: String = trimmed.trim_end_matches('{').trim().to_owned();
    Some(InterfaceMethod {
        name,
        signature,
        is_static,
    })
}

fn parse_cases(rest: &str) -> Vec<InterfaceCase> {
    rest.split(',')
        .map(|chunk: &str| {
            chunk
                .trim()
                .split(['(', ' ', '='])
                .next()
                .unwrap_or("")
                .trim()
                .to_owned()
        })
        .filter(|name: &String| !name.is_empty())
        .map(|name: String| InterfaceCase { name })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = "// swift-interface-format-version: 1.0\n\
// swift-compiler-version: Apple Swift version 5.10\n\
// swift-module-flags: -target arm64-apple-ios15.0 -module-name SwiftHello\n\
import Swift\n\
@_hasMissingDesignatedInitializers public class LoginViewController {\n\
  public var displayedUserName: Swift.String\n\
  public let sessionToken: Swift.String\n\
  public func greetWithBanner() -> Swift.String\n\
}\n\
public struct Credentials : Swift.Equatable {\n\
  public let user: Swift.String\n\
  public let secret: Swift.String\n\
}\n\
public enum AuthState {\n\
  case loggedOut\n\
  case loggedIn(token: Swift.String)\n\
}\n";

    #[test]
    fn detects_swiftinterface_header() {
        assert!(looks_like_swiftinterface(SAMPLE));
        assert!(!looks_like_swiftinterface("class Foo {}\n"));
    }

    #[test]
    fn parses_module_metadata() {
        let parsed: ParsedInterface = parse(SAMPLE);
        assert_eq!(parsed.format_version.as_deref(), Some("1.0"));
        assert_eq!(parsed.module_name.as_deref(), Some("SwiftHello"));
        assert_eq!(parsed.decls.len(), 3);
    }

    #[test]
    fn recovers_class_property_names() {
        let parsed: ParsedInterface = parse(SAMPLE);
        let class: &InterfaceDecl = parsed
            .decls
            .iter()
            .find(|d: &&InterfaceDecl| d.name == "LoginViewController")
            .expect("class decl");
        let names: Vec<&str> = class
            .properties
            .iter()
            .map(|p: &InterfaceProperty| p.name.as_str())
            .collect();
        assert!(names.contains(&"displayedUserName"));
        assert!(names.contains(&"sessionToken"));
        assert_eq!(class.methods.len(), 1);
        assert_eq!(class.methods[0].name, "greetWithBanner");
    }

    #[test]
    fn recovers_struct_conformances_and_fields() {
        let parsed: ParsedInterface = parse(SAMPLE);
        let s: &InterfaceDecl = parsed
            .decls
            .iter()
            .find(|d: &&InterfaceDecl| d.name == "Credentials")
            .expect("struct decl");
        assert_eq!(s.kind, InterfaceDeclKind::Struct);
        assert!(
            s.conformances
                .iter()
                .any(|c: &String| c == "Swift.Equatable")
        );
        assert_eq!(s.properties.len(), 2);
        assert!(s.properties.iter().all(|p: &InterfaceProperty| p.is_let));
    }

    #[test]
    fn recovers_enum_case_names() {
        let parsed: ParsedInterface = parse(SAMPLE);
        let e: &InterfaceDecl = parsed
            .decls
            .iter()
            .find(|d: &&InterfaceDecl| d.name == "AuthState")
            .expect("enum decl");
        let cases: Vec<&str> = e
            .cases
            .iter()
            .map(|c: &InterfaceCase| c.name.as_str())
            .collect();
        assert_eq!(cases, vec!["loggedOut", "loggedIn"]);
    }

    #[test]
    fn resilient_field_names_index_covers_all_named_decls() {
        let parsed: ParsedInterface = parse(SAMPLE);
        let index: BTreeMap<String, Vec<String>> = parsed.resilient_field_names();
        assert_eq!(
            index.get("LoginViewController").map(Vec::as_slice),
            Some(
                ["displayedUserName", "sessionToken"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
        assert!(index.contains_key("AuthState"));
    }

    #[test]
    fn merge_fills_elided_reflection_field_names() {
        use crate::swift_reflect::FieldDescriptorKind;

        let elided: Vec<SwiftTypeReflection> = vec![SwiftTypeReflection {
            mangled_type_name: Some("$s10SwiftHello11CredentialsV".to_owned()),
            demangled_type_name: Some("SwiftHello.Credentials".to_owned()),
            superclass: None,
            kind: FieldDescriptorKind::Struct,
            fields: vec![
                SwiftField {
                    name: String::new(),
                    mangled_type: Some("SS".to_owned()),
                    demangled_type: Some("Swift.String".to_owned()),
                    is_indirect_enum_case: false,
                    is_var: false,
                },
                SwiftField {
                    name: String::new(),
                    mangled_type: Some("SS".to_owned()),
                    demangled_type: Some("Swift.String".to_owned()),
                    is_indirect_enum_case: false,
                    is_var: false,
                },
            ],
        }];
        let interface: ParsedInterface = parse(SAMPLE);
        let (merged, filled): (Vec<SwiftTypeReflection>, usize) =
            merge_elided_field_names(elided, &interface);
        assert_eq!(filled, 2);
        let names: Vec<&str> = merged[0]
            .fields
            .iter()
            .map(|f: &SwiftField| f.name.as_str())
            .collect();
        assert_eq!(names, vec!["user", "secret"]);
    }

    #[test]
    fn merge_leaves_present_names_untouched() {
        use crate::swift_reflect::FieldDescriptorKind;

        let present: Vec<SwiftTypeReflection> = vec![SwiftTypeReflection {
            mangled_type_name: None,
            demangled_type_name: Some("SwiftHello.Credentials".to_owned()),
            superclass: None,
            kind: FieldDescriptorKind::Struct,
            fields: vec![SwiftField {
                name: "alreadyKnown".to_owned(),
                mangled_type: None,
                demangled_type: None,
                is_indirect_enum_case: false,
                is_var: false,
            }],
        }];
        let interface: ParsedInterface = parse(SAMPLE);
        let (merged, filled): (Vec<SwiftTypeReflection>, usize) =
            merge_elided_field_names(present, &interface);
        assert_eq!(
            filled, 1,
            "the unfilled second slot is appended from the interface"
        );
        assert_eq!(merged[0].fields[0].name, "alreadyKnown");
    }
}
