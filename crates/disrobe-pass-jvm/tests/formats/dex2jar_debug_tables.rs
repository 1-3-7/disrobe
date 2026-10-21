#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::dex::CodeItem;
use disrobe_pass_jvm::{
    Dex2JarResult, DexFile, assemble_jar, parse_code_items, parse_dex, translate_dex_bytes,
};

use crate::common::find_on_path;

const DEBUG_DEX: &[u8] = include_bytes!("../fixtures/d8_enum_plain/EnumProbe-min21-debug.dex");
const RELEASE_DEX: &[u8] = include_bytes!("../fixtures/d8_enum_plain/EnumProbe-min21.dex");

struct JavapMethod {
    lines: BTreeSet<u32>,
    locals: BTreeMap<String, String>,
}

fn javap_methods(dex_bytes: &[u8], class: &str) -> BTreeMap<String, JavapMethod> {
    let javap: PathBuf = find_on_path("javap").expect("javap (JDK) on PATH");
    let result: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate");
    let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
    let scratch: ScratchDir = ScratchDir::create("dex2jar-debug-tables").expect("scratch");
    let jar_path: PathBuf = scratch.path().join("translated.jar");
    std::fs::write(&jar_path, &jar).expect("write jar");
    let output: std::process::Output = std::process::Command::new(javap)
        .arg("-p")
        .arg("-c")
        .arg("-l")
        .arg("-cp")
        .arg(&jar_path)
        .arg(class)
        .output()
        .expect("run javap");
    assert!(
        output.status.success(),
        "javap -l rejected {class}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut methods: BTreeMap<String, JavapMethod> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut section: &str = "";
    for raw in text.lines() {
        let line: &str = raw.trim();
        if line.ends_with(");")
            && !line.starts_with("line ")
            && !line.contains(" = ")
            && !line.contains("//")
            && line
                .split(':')
                .next()
                .is_none_or(|head: &str| head.trim().parse::<u32>().is_err())
        {
            let name: String = line
                .split('(')
                .next()
                .and_then(|head: &str| head.rsplit(' ').next())
                .expect("method name")
                .to_owned();
            current = Some(name.clone());
            methods.insert(
                name,
                JavapMethod {
                    lines: BTreeSet::new(),
                    locals: BTreeMap::new(),
                },
            );
            section = "";
            continue;
        }
        if line == "LineNumberTable:" || line == "LocalVariableTable:" {
            section = if line.starts_with("Line") {
                "lines"
            } else {
                "locals"
            };
            continue;
        }
        let Some(name) = current.as_ref() else {
            continue;
        };
        let method: &mut JavapMethod = methods.get_mut(name).expect("current method");
        if section == "lines"
            && let Some(rest) = line.strip_prefix("line ")
            && let Some((number, _)) = rest.split_once(':')
        {
            method
                .lines
                .insert(number.trim().parse().expect("line number"));
        } else if section == "locals" {
            let columns: Vec<&str> = line.split_whitespace().collect();
            if columns.len() == 5 && columns[0].parse::<u32>().is_ok() {
                method
                    .locals
                    .insert(columns[3].to_owned(), columns[4].to_owned());
            }
        }
    }
    methods
}

fn dex_method<'a>(items: &'a [CodeItem], class: &str, name: &str) -> &'a CodeItem {
    items
        .iter()
        .find(|item: &&CodeItem| item.class == class && item.method_name == name)
        .unwrap_or_else(|| panic!("code item {class}->{name}"))
}

#[test]
fn translated_classes_carry_the_dex_line_and_local_tables() {
    let dex: DexFile = parse_dex(DEBUG_DEX).expect("parse debug dex");
    let report = parse_code_items(&dex, DEBUG_DEX);
    let items: &[CodeItem] = report.decoded();
    let probe: BTreeMap<String, JavapMethod> = javap_methods(DEBUG_DEX, "EnumProbe");
    let main: &CodeItem = dex_method(items, "LEnumProbe;", "main");
    let expected_lines: BTreeSet<u32> = main
        .positions
        .iter()
        .map(|position: &disrobe_pass_jvm::dex::DebugPosition| position.line)
        .collect();
    assert!(expected_lines.len() >= 5, "{expected_lines:?}");
    let javap_main: &JavapMethod = &probe["main"];
    assert_eq!(
        javap_main.lines, expected_lines,
        "javap -l LineNumberTable of main equals the DEX debug positions"
    );
    let expected_locals: BTreeMap<String, String> = main
        .locals
        .iter()
        .map(|local: &disrobe_pass_jvm::dex::DebugLocal| {
            (local.name.clone(), local.descriptor.clone())
        })
        .collect();
    assert!(
        expected_locals.contains_key("out") && expected_locals.contains_key("level"),
        "{expected_locals:?}"
    );
    for (name, descriptor) in &expected_locals {
        assert_eq!(
            javap_main.locals.get(name),
            Some(descriptor),
            "local {name} is in the translated LocalVariableTable with its descriptor: {:?}",
            javap_main.locals
        );
    }
    let level: BTreeMap<String, JavapMethod> = javap_methods(DEBUG_DEX, "EnumProbe$Level");
    let next: &CodeItem = dex_method(items, "LEnumProbe$Level;", "next");
    assert!(
        next.locals.iter().any(|l| l.name == "all"),
        "{:?}",
        next.locals
    );
    assert_eq!(
        level["next"].locals.get("all").map(String::as_str),
        Some("[LEnumProbe$Level;")
    );
}

#[test]
fn a_release_build_keeps_line_numbers_but_has_no_locals() {
    let dex: DexFile = parse_dex(RELEASE_DEX).expect("parse release dex");
    let report = parse_code_items(&dex, RELEASE_DEX);
    let main_item: &CodeItem = dex_method(report.decoded(), "LEnumProbe;", "main");
    assert!(main_item.locals.is_empty(), "{:?}", main_item.locals);
    let expected_lines: BTreeSet<u32> = main_item
        .positions
        .iter()
        .map(|p: &disrobe_pass_jvm::dex::DebugPosition| p.line)
        .collect();
    let probe: BTreeMap<String, JavapMethod> = javap_methods(RELEASE_DEX, "EnumProbe");
    let main: &JavapMethod = &probe["main"];
    assert_eq!(
        main.lines, expected_lines,
        "d8 --release keeps line positions"
    );
    assert!(main.locals.is_empty(), "{:?}", main.locals);
}

#[test]
fn a_dropped_debug_position_turns_the_line_comparison_red() {
    let dex: DexFile = parse_dex(DEBUG_DEX).expect("parse debug dex");
    let report = parse_code_items(&dex, DEBUG_DEX);
    let main: &CodeItem = dex_method(report.decoded(), "LEnumProbe;", "main");
    let full: BTreeSet<u32> = main
        .positions
        .iter()
        .map(|p: &disrobe_pass_jvm::dex::DebugPosition| p.line)
        .collect();
    let mut dropped: BTreeSet<u32> = full;
    let first: u32 = *dropped.iter().next().expect("a line");
    dropped.remove(&first);
    let probe: BTreeMap<String, JavapMethod> = javap_methods(DEBUG_DEX, "EnumProbe");
    assert_ne!(probe["main"].lines, dropped);
}
