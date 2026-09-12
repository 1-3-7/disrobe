#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::native_bodies::{
    FunctionBody, NativeBodyReport, recover_native_bodies,
};
use disrobe_pass_swift_objc::objc_dispatch::{
    DispatchArch, DispatchMaps, ObjcMessageSend, build_dispatch_maps,
};

const SOURCE_FILE: &str = "dispatch_sends.m";

const FIXTURES: [(&str, DispatchArch, &str); 4] = [
    (
        "dispatch_sends_arm64.macho",
        DispatchArch::Arm64,
        "arm64 -O0",
    ),
    (
        "dispatch_sends_x86_64.macho",
        DispatchArch::X86_64,
        "x86_64 -O0",
    ),
    (
        "dispatch_sends_arm64_opt.macho",
        DispatchArch::Arm64,
        "arm64 -O2",
    ),
    (
        "dispatch_sends_x86_64_opt.macho",
        DispatchArch::X86_64,
        "x86_64 -O2",
    ),
];

const ARM64_DYNAMIC_RECEIVER: &str = "x0";
const X86_64_DYNAMIC_RECEIVER: &str = "rdi";
const X86_64_STRET_DYNAMIC_RECEIVER: &str = "rsi";
const ARM64_ARGUMENT_REGISTERS: [&str; 6] = ["x2", "x3", "x4", "x5", "x6", "x7"];
const X86_64_ARGUMENT_REGISTERS: [&str; 4] = ["rdx", "rcx", "r8", "r9"];
const X86_64_STRET_ARGUMENT_REGISTERS: [&str; 3] = ["rcx", "r8", "r9"];

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("objc_dispatch")
}

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn source_text() -> String {
    String::from_utf8(fixture(SOURCE_FILE)).expect("objective-c source is utf-8")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceReceiver {
    Class(String),
    Super,
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceSend {
    selector: String,
    receiver: SourceReceiver,
    alloc_init_fold: bool,
    uses_stret: bool,
}

#[derive(Debug, Clone)]
struct SourceFunction {
    native_name: String,
    sends: Vec<SourceSend>,
}

fn class_names(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line: &str| line.trim().strip_prefix("@interface "))
        .filter_map(|rest: &str| rest.split([' ', ':']).next())
        .map(str::trim)
        .filter(|name: &&str| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

fn matching_delimiter(text: &str, open: usize, opener: u8, closer: u8) -> Option<usize> {
    let bytes: &[u8] = text.as_bytes();
    let mut depth: usize = 0;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        if *byte == opener {
            depth += 1;
        } else if *byte == closer {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn split_top_level(text: &str) -> Vec<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut depth: usize = 0;
    let mut quoted: bool = false;
    let mut start: Option<usize> = None;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b'[' | b'(' if !quoted => depth += 1,
            b']' | b')' if !quoted => depth = depth.saturating_sub(1),
            _ => {}
        }
        let separator: bool = !quoted && depth == 0 && byte.is_ascii_whitespace();
        match (separator, start) {
            (true, Some(begin)) => {
                out.push(&text[begin..index]);
                start = None;
            }
            (false, None) => start = Some(index),
            _ => {}
        }
    }
    if let Some(begin) = start {
        out.push(&text[begin..]);
    }
    out
}

fn assemble_selector(parts: &str) -> String {
    let tokens: Vec<&str> = split_top_level(parts);
    let mut selector: String = String::new();
    let mut index: usize = 0;
    while index < tokens.len() {
        let token: &str = tokens[index];
        match token.find(':') {
            Some(colon) => {
                selector.push_str(&token[..colon]);
                selector.push(':');
                if colon + 1 == token.len() {
                    index += 1;
                }
            }
            None => {
                if selector.is_empty() {
                    selector.push_str(token);
                }
            }
        }
        index += 1;
    }
    selector
}

fn split_receiver(inner: &str) -> (&str, &str) {
    let trimmed: &str = inner.trim();
    if trimmed.starts_with('[') {
        let close: usize = matching_delimiter(trimmed, 0, b'[', b']')
            .unwrap_or_else(|| panic!("unbalanced nested message in {trimmed:?}"));
        return (&trimmed[..=close], trimmed[close + 1..].trim());
    }
    let mut cursor: usize = 0;
    loop {
        let rest: &str = trimmed[cursor..].trim_start();
        cursor = trimmed.len() - rest.len();
        if !rest.starts_with('(') {
            break;
        }
        let close: usize = matching_delimiter(trimmed, cursor, b'(', b')')
            .unwrap_or_else(|| panic!("unbalanced cast in {trimmed:?}"));
        cursor = close + 1;
    }
    let rest: &str = &trimmed[cursor..];
    let end: usize = rest.find(char::is_whitespace).unwrap_or(rest.len());
    (&rest[..end], rest[end..].trim())
}

fn emit_message(
    inner: &str,
    classes: &BTreeSet<String>,
    stret_selectors: &BTreeSet<String>,
    out: &mut Vec<SourceSend>,
) {
    let (receiver_text, parts): (&str, &str) = split_receiver(inner);
    let selector: String = assemble_selector(parts);
    let uses_stret: bool = stret_selectors.contains(&selector);

    if let Some(nested_inner) = receiver_text
        .strip_prefix('[')
        .and_then(|s: &str| s.strip_suffix(']'))
    {
        let mut nested: Vec<SourceSend> = Vec::new();
        emit_message(nested_inner, classes, stret_selectors, &mut nested);
        if selector == "init"
            && nested.len() == 1
            && nested[0].selector == "alloc"
            && let SourceReceiver::Class(class) = &nested[0].receiver
        {
            out.push(SourceSend {
                selector,
                receiver: SourceReceiver::Class(class.clone()),
                alloc_init_fold: true,
                uses_stret,
            });
            return;
        }
        out.extend(nested);
        out.push(SourceSend {
            selector,
            receiver: SourceReceiver::Dynamic,
            alloc_init_fold: false,
            uses_stret,
        });
        return;
    }

    let receiver: SourceReceiver = if receiver_text == "super" {
        SourceReceiver::Super
    } else if classes.contains(receiver_text) {
        SourceReceiver::Class(receiver_text.to_owned())
    } else {
        SourceReceiver::Dynamic
    };
    out.push(SourceSend {
        selector,
        receiver,
        alloc_init_fold: false,
        uses_stret,
    });
}

fn extract_sends(
    body: &str,
    classes: &BTreeSet<String>,
    stret_selectors: &BTreeSet<String>,
) -> Vec<SourceSend> {
    let mut out: Vec<SourceSend> = Vec::new();
    let mut cursor: usize = 0;
    while let Some(open) = body[cursor..].find('[') {
        let start: usize = cursor + open;
        let close: usize = matching_delimiter(body, start, b'[', b']')
            .unwrap_or_else(|| panic!("unbalanced message expression in {body:?}"));
        emit_message(&body[start + 1..close], classes, stret_selectors, &mut out);
        cursor = close + 1;
    }
    out
}

fn struct_return_selectors(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line: &&str| line.starts_with("- (struct ") || line.starts_with("+ (struct "))
        .map(method_selector)
        .collect()
}

fn method_selector(header: &str) -> String {
    let mut rest: &str = header[1..].trim_start();
    if rest.starts_with('(') {
        let close: usize = matching_delimiter(rest, 0, b'(', b')').expect("return type parens");
        rest = rest[close + 1..].trim_start();
    }
    let declaration: &str = rest.trim_end_matches('{').trim();
    if !declaration.contains(':') {
        return declaration
            .split_whitespace()
            .next()
            .unwrap_or(declaration)
            .to_owned();
    }
    let mut selector: String = String::new();
    let mut keyword: String = String::new();
    let mut depth: usize = 0;
    for ch in declaration.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                if let Some(part) = keyword.split_whitespace().last() {
                    selector.push_str(part);
                }
                selector.push(':');
                keyword.clear();
            }
            _ if depth == 0 => keyword.push(ch),
            _ => {}
        }
    }
    selector
}

fn function_native_name(header: &str, implementation: Option<&str>) -> Option<String> {
    if let Some(class) = implementation
        && (header.starts_with('-') || header.starts_with('+'))
    {
        let sign: char = header.chars().next()?;
        return Some(format!("{sign}[{class} {}]", method_selector(header)));
    }
    let signature: &str = header.split('(').next()?;
    let name: &str = signature.split_whitespace().last()?.trim_start_matches('*');
    (!name.is_empty()).then(|| format!("_{name}"))
}

fn parse_source(text: &str) -> Vec<SourceFunction> {
    let classes: BTreeSet<String> = class_names(text);
    let stret_selectors: BTreeSet<String> = struct_return_selectors(text);
    let mut out: Vec<SourceFunction> = Vec::new();
    let mut in_interface: bool = false;
    let mut implementation: Option<String> = None;
    let mut pending: Option<(String, String, usize)> = None;

    for raw in text.lines() {
        let line: &str = raw.trim();
        if let Some((native_name, body, depth)) = pending.as_mut() {
            *depth += line.matches('{').count();
            *depth = depth.saturating_sub(line.matches('}').count());
            if *depth == 0 {
                out.push(SourceFunction {
                    native_name: std::mem::take(native_name),
                    sends: extract_sends(body, &classes, &stret_selectors),
                });
                pending = None;
            } else {
                body.push_str(line);
                body.push(' ');
            }
            continue;
        }
        if line.starts_with("@interface") {
            in_interface = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("@implementation ") {
            implementation = rest.split_whitespace().next().map(str::to_owned);
            continue;
        }
        if line == "@end" {
            in_interface = false;
            implementation = None;
            continue;
        }
        if in_interface
            || !line.ends_with('{')
            || (line.starts_with("struct ") && !line.contains('('))
        {
            continue;
        }
        if let Some(native_name) = function_native_name(line, implementation.as_deref()) {
            pending = Some((native_name, String::new(), 1));
        }
    }
    out
}

const fn dynamic_receiver_token(arch: DispatchArch, uses_stret: bool) -> &'static str {
    match (arch, uses_stret) {
        (DispatchArch::X86_64, true) => X86_64_STRET_DYNAMIC_RECEIVER,
        (DispatchArch::Arm64, _) => ARM64_DYNAMIC_RECEIVER,
        (DispatchArch::X86_64, false) => X86_64_DYNAMIC_RECEIVER,
    }
}

const fn argument_registers(arch: DispatchArch, uses_stret: bool) -> &'static [&'static str] {
    match (arch, uses_stret) {
        (DispatchArch::X86_64, true) => &X86_64_STRET_ARGUMENT_REGISTERS,
        (DispatchArch::Arm64, _) => &ARM64_ARGUMENT_REGISTERS,
        (DispatchArch::X86_64, false) => &X86_64_ARGUMENT_REGISTERS,
    }
}

const fn expected_receiver_class(send: &SourceSend) -> Option<&str> {
    match &send.receiver {
        SourceReceiver::Class(name) => Some(name.as_str()),
        SourceReceiver::Super | SourceReceiver::Dynamic => None,
    }
}

fn expected_receiver_token(send: &SourceSend, arch: DispatchArch) -> String {
    match &send.receiver {
        SourceReceiver::Class(name) => name.clone(),
        SourceReceiver::Super => "super".to_owned(),
        SourceReceiver::Dynamic => dynamic_receiver_token(arch, send.uses_stret).to_owned(),
    }
}

fn expected_rendering(send: &SourceSend, arch: DispatchArch) -> String {
    let receiver: String = expected_receiver_token(send, arch);
    if send.alloc_init_fold {
        return format!("[[{receiver} alloc] {}]", send.selector);
    }
    if !send.selector.contains(':') {
        return format!("[{receiver} {}]", send.selector);
    }
    let registers: &[&str] = argument_registers(arch, send.uses_stret);
    let mut rendered: String = format!("[{receiver}");
    for (position, keyword) in send
        .selector
        .split(':')
        .filter(|k: &&str| !k.is_empty())
        .enumerate()
    {
        let register: &str = registers.get(position).copied().unwrap_or("?");
        rendered.push(' ');
        rendered.push_str(keyword);
        rendered.push(':');
        rendered.push_str(register);
    }
    rendered.push(']');
    rendered
}

fn recovered(name: &str) -> (Vec<u8>, ParsedSlice, NativeBodyReport) {
    let bytes: Vec<u8> = fixture(name);
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse mach-o fixture");
    let report: NativeBodyReport = recover_native_bodies(&bytes, &parsed);
    (bytes, parsed, report)
}

#[test]
fn source_model_describes_every_adversarial_case() {
    let functions: Vec<SourceFunction> = parse_source(&source_text());
    let names: Vec<&str> = functions
        .iter()
        .map(|f: &SourceFunction| f.native_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "_make_greeting",
            "_first_element",
            "_store",
            "_text_length",
            "_fresh_object",
            "_clobbered_receiver",
            "_chained_receiver",
            "_instance_then_class",
            "_branch_shared_classref",
            "_class_summary",
            "_dynamic_summary",
            "-[FastCourier describe]",
            "-[FastCourier superSummaryFirst:second:third:fourth:]",
        ],
        "the source parser must recover every definition in {SOURCE_FILE}"
    );

    let total: usize = functions
        .iter()
        .map(|f: &SourceFunction| f.sends.len())
        .sum();
    assert_eq!(total, 17, "the source declares 17 message sends");

    let all: Vec<&SourceSend> = functions
        .iter()
        .flat_map(|f: &SourceFunction| f.sends.iter())
        .collect();
    assert_eq!(
        all.iter()
            .filter(|s: &&&SourceSend| matches!(s.receiver, SourceReceiver::Class(_)))
            .count(),
        7,
        "seven sends name a class receiver in the source"
    );
    assert_eq!(
        all.iter()
            .filter(|s: &&&SourceSend| matches!(s.receiver, SourceReceiver::Super))
            .count(),
        2,
        "two sends go through super"
    );
    assert_eq!(
        all.iter()
            .filter(|s: &&&SourceSend| s.alloc_init_fold)
            .count(),
        1,
        "exactly one [[C alloc] init] pair folds into a single objc_alloc_init call"
    );

    for function in &functions {
        let distinct: BTreeSet<(&str, Option<&str>)> = function
            .sends
            .iter()
            .map(|s: &SourceSend| (s.selector.as_str(), expected_receiver_class(s)))
            .collect();
        assert_eq!(
            distinct.len(),
            function.sends.len(),
            "{}: every send in a function must be distinct, otherwise a dropped or duplicated \
             annotation could hide",
            function.native_name
        );
    }
}

#[test]
fn every_fixture_recovers_exactly_the_sends_the_source_declares() {
    let functions: Vec<SourceFunction> = parse_source(&source_text());
    for (name, arch, label) in FIXTURES {
        let (_, _, report): (Vec<u8>, ParsedSlice, NativeBodyReport) = recovered(name);
        let by_name: BTreeMap<&str, &FunctionBody> = report
            .functions
            .iter()
            .map(|f: &FunctionBody| (f.native_name.as_str(), f))
            .collect();

        let recovered_names: BTreeSet<&str> = by_name.keys().copied().collect();
        let source_names: BTreeSet<&str> = functions
            .iter()
            .map(|f: &SourceFunction| f.native_name.as_str())
            .collect();
        assert_eq!(
            recovered_names, source_names,
            "{label}: recovered function set must equal the source's definitions"
        );

        for function in &functions {
            let body: &FunctionBody = by_name[function.native_name.as_str()];
            let sends: &Vec<ObjcMessageSend> = &body.objc_sends;
            let observed: Vec<(&str, Option<&str>)> = sends
                .iter()
                .map(|s: &ObjcMessageSend| {
                    (s.send.selector.as_str(), s.send.receiver_class.as_deref())
                })
                .collect();
            let expected: Vec<(&str, Option<&str>)> = function
                .sends
                .iter()
                .map(|s: &SourceSend| (s.selector.as_str(), expected_receiver_class(s)))
                .collect();
            assert_eq!(
                observed, expected,
                "{label}: {} must recover the source's sends in order",
                function.native_name
            );

            for (send, source) in sends.iter().zip(function.sends.iter()) {
                assert!(
                    send.call_site >= body.start && send.call_site < body.end,
                    "{label}: {} call site {:#x} must fall inside [{:#x}, {:#x})",
                    function.native_name,
                    send.call_site,
                    body.start,
                    body.end
                );
                assert_eq!(
                    send.send.rendered,
                    expected_rendering(source, arch),
                    "{label}: {} rendering must match the source expression",
                    function.native_name
                );
            }
            let ascending: bool = sends
                .windows(2)
                .all(|w: &[ObjcMessageSend]| w[0].call_site < w[1].call_site);
            assert!(
                ascending,
                "{label}: {} call sites must be strictly ascending",
                function.native_name
            );
        }

        let total_recovered: usize = report
            .functions
            .iter()
            .map(|f: &FunctionBody| f.objc_sends.len())
            .sum();
        let total_expected: usize = functions
            .iter()
            .map(|f: &SourceFunction| f.sends.len())
            .sum();
        assert_eq!(
            total_recovered, total_expected,
            "{label}: a send annotated outside the source's call sites is a soundness violation"
        );
    }
}

#[test]
fn real_fixtures_exercise_target_specific_struct_return_dispatch() {
    let functions: Vec<SourceFunction> = parse_source(&source_text());
    let stret_send_count: usize = functions
        .iter()
        .flat_map(|function: &SourceFunction| function.sends.iter())
        .filter(|send: &&SourceSend| send.uses_stret)
        .count();
    assert_eq!(
        stret_send_count, 3,
        "the source must independently declare class, dynamic, and super struct-return sends"
    );

    for (name, arch, label) in FIXTURES {
        let bytes: Vec<u8> = fixture(name);
        let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse mach-o fixture");
        let maps: DispatchMaps = build_dispatch_maps(&bytes, &parsed, arch);
        let imports: BTreeSet<&str> = maps.imports_by_addr.values().map(String::as_str).collect();
        match arch {
            DispatchArch::X86_64 => {
                assert!(
                    imports.contains("_objc_msgSend_stret"),
                    "{label}: class and dynamic struct-return sends must use objc_msgSend_stret"
                );
                assert!(
                    imports.contains("_objc_msgSendSuper2_stret"),
                    "{label}: the struct-return super send must use objc_msgSendSuper2_stret"
                );
            }
            DispatchArch::Arm64 => {
                assert!(
                    !imports
                        .iter()
                        .any(|symbol: &&str| symbol.ends_with("_stret")),
                    "{label}: arm64 passes indirect result storage in x8 without a stret entry point"
                );
                assert!(imports.contains("_objc_msgSend"));
                assert!(imports.contains("_objc_msgSendSuper2"));
            }
        }
    }
}

#[test]
fn a_dynamic_receiver_is_never_rendered_as_a_class() {
    let source: String = source_text();
    let classes: BTreeSet<String> = class_names(&source);
    let functions: Vec<SourceFunction> = parse_source(&source);
    let mut checked: usize = 0;
    for (name, _, label) in FIXTURES {
        let (_, _, report): (Vec<u8>, ParsedSlice, NativeBodyReport) = recovered(name);
        let by_name: BTreeMap<&str, &FunctionBody> = report
            .functions
            .iter()
            .map(|f: &FunctionBody| (f.native_name.as_str(), f))
            .collect();
        for function in &functions {
            let body: &FunctionBody = by_name[function.native_name.as_str()];
            for (send, source_send) in body.objc_sends.iter().zip(function.sends.iter()) {
                if !matches!(source_send.receiver, SourceReceiver::Dynamic) {
                    continue;
                }
                for class in &classes {
                    assert!(
                        !send.send.rendered.contains(class.as_str()),
                        "{label}: {} renders {:?} for a receiver the source cannot pin to a class",
                        function.native_name,
                        send.send.rendered
                    );
                }
                checked += 1;
            }
        }
    }
    assert_eq!(
        checked,
        8 * FIXTURES.len(),
        "every dynamic-receiver send in every fixture must be checked"
    );
}

#[test]
fn super_sends_are_distinguishable_from_unresolved_receivers() {
    let functions: Vec<SourceFunction> = parse_source(&source_text());
    let super_functions: Vec<&SourceFunction> = functions
        .iter()
        .filter(|f: &&SourceFunction| {
            f.sends
                .iter()
                .any(|s: &SourceSend| matches!(s.receiver, SourceReceiver::Super))
        })
        .collect();
    assert_eq!(super_functions.len(), 2, "two methods dispatch to super");

    for (name, arch, label) in FIXTURES {
        let (_, _, report): (Vec<u8>, ParsedSlice, NativeBodyReport) = recovered(name);
        let body: &FunctionBody = report
            .functions
            .iter()
            .find(|f: &&FunctionBody| f.native_name == super_functions[0].native_name)
            .unwrap_or_else(|| panic!("{label}: super-dispatching method absent"));
        let send: &ObjcMessageSend = body
            .objc_sends
            .first()
            .unwrap_or_else(|| panic!("{label}: super send not recovered"));
        assert_eq!(send.send.selector, "describe");
        assert_eq!(send.send.receiver_class, None);
        assert!(
            send.send.rendered.starts_with("[super "),
            "{label}: a super send must render as super, not as the unresolved token {:?}",
            dynamic_receiver_token(arch, false)
        );
        assert!(
            !send
                .send
                .rendered
                .contains(dynamic_receiver_token(arch, false)),
            "{label}: a super send must not fall back to the raw receiver register"
        );
    }
}

#[test]
fn dispatch_maps_resolve_every_selector_and_class_the_source_names() {
    let source: String = source_text();
    let functions: Vec<SourceFunction> = parse_source(&source);
    let selectors: BTreeSet<&str> = functions
        .iter()
        .flat_map(|f: &SourceFunction| f.sends.iter())
        .filter(|s: &&SourceSend| !s.alloc_init_fold)
        .map(|s: &SourceSend| s.selector.as_str())
        .collect();
    let classes: BTreeSet<&str> = functions
        .iter()
        .flat_map(|f: &SourceFunction| f.sends.iter())
        .filter_map(expected_receiver_class)
        .collect();
    assert_eq!(
        selectors.len(),
        9,
        "the source names nine distinct selectors"
    );
    assert_eq!(classes.len(), 3, "the source names three receiver classes");

    for (name, arch, label) in FIXTURES {
        let bytes: Vec<u8> = fixture(name);
        let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse mach-o fixture");
        let maps: DispatchMaps = build_dispatch_maps(&bytes, &parsed, arch);

        let resolved_selectors: BTreeSet<&str> =
            maps.selref_by_va.values().map(String::as_str).collect();
        for selector in &selectors {
            assert!(
                resolved_selectors.contains(selector),
                "{label}: __objc_selrefs must resolve {selector}"
            );
        }
        let resolved_classes: BTreeSet<&str> =
            maps.classref_by_va.values().map(String::as_str).collect();
        for class in &classes {
            assert!(
                resolved_classes.contains(class),
                "{label}: __objc_classrefs must resolve {class}"
            );
        }
        assert!(
            maps.imports_by_addr
                .values()
                .any(|s: &String| s == "_objc_msgSend"),
            "{label}: the bind table must expose the dispatch entry point"
        );
    }
}

#[test]
fn malformed_input_never_panics() {
    for junk in [
        vec![],
        vec![0u8; 3],
        vec![0xFFu8; 64],
        b"\xcf\xfa\xed\xfe garbage header bytes that are not a real mach-o".to_vec(),
    ] {
        let _ = macho::parse_slice(&junk).map(|parsed: ParsedSlice| {
            let _ = recover_native_bodies(&junk, &parsed);
            let _ = build_dispatch_maps(&junk, &parsed, DispatchArch::Arm64);
        });
    }
}
