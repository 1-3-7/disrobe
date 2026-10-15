#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_pass_go::{GoAnalysis, GoTypeRef, analyze};

const USER_TYPES: [&str; 2] = ["main.Parcel", "main.Ledger"];

struct MatrixRow {
    binary: &'static str,
    version: &'static str,
    target: &'static str,
}

const GO117_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go117_linux_amd64",
        version: "go1.17.13",
        target: "linux/amd64",
    },
    MatrixRow {
        binary: "go117_linux_amd64_pie",
        version: "go1.17.13",
        target: "linux/amd64 PIE",
    },
    MatrixRow {
        binary: "go117_linux_arm64",
        version: "go1.17.13",
        target: "linux/arm64",
    },
];

const GO118_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go118_linux_amd64",
        version: "go1.18.10",
        target: "linux/amd64",
    },
    MatrixRow {
        binary: "go118_linux_amd64_pie",
        version: "go1.18.10",
        target: "linux/amd64 PIE",
    },
    MatrixRow {
        binary: "go118_linux_arm64",
        version: "go1.18.10",
        target: "linux/arm64",
    },
];

const GO120_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go120_linux_amd64",
        version: "go1.20.14",
        target: "linux/amd64",
    },
    MatrixRow {
        binary: "go120_linux_amd64_pie",
        version: "go1.20.14",
        target: "linux/amd64 PIE",
    },
    MatrixRow {
        binary: "go120_linux_arm64",
        version: "go1.20.14",
        target: "linux/arm64",
    },
];

const GO126_ROWS: [MatrixRow; 3] = [
    MatrixRow {
        binary: "go126_linux_amd64",
        version: "go1.26.3",
        target: "linux/amd64",
    },
    MatrixRow {
        binary: "go126_linux_amd64_pie",
        version: "go1.26.3",
        target: "linux/amd64 PIE",
    },
    MatrixRow {
        binary: "go126_linux_arm64",
        version: "go1.26.3",
        target: "linux/arm64",
    },
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("go")
        .join("versions")
}

fn objdump_symbols(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line: &str| line.strip_prefix("TEXT "))
        .filter_map(|line: &str| line.split_once("(SB)"))
        .map(|(name, _): (&str, &str)| name.to_owned())
        .collect()
}

fn recovered_type<'a>(analysis: &'a GoAnalysis, name: &str) -> &'a GoTypeRef {
    analysis
        .typemeta
        .types
        .iter()
        .find(|ty: &&GoTypeRef| ty.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} must recover from typelinks"))
}

fn recovered_field_names<'a>(analysis: &'a GoAnalysis, type_name: &str) -> BTreeSet<&'a str> {
    recovered_type(analysis, type_name)
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect()
}

fn type_oracle(symbols: &BTreeSet<String>) -> BTreeSet<String> {
    symbols
        .iter()
        .filter_map(|symbol: &String| symbol.strip_prefix("main.Type"))
        .filter_map(|symbol: &str| symbol.strip_suffix("Equal"))
        .map(|name: &str| format!("main.{name}"))
        .collect()
}

fn field_oracle(
    symbols: &BTreeSet<String>,
    type_names: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    type_names
        .iter()
        .map(|type_name: &String| {
            let short: &str = type_name.strip_prefix("main.").unwrap_or(type_name);
            let prefix: String = format!("main.{short}");
            let fields: BTreeSet<String> = symbols
                .iter()
                .filter_map(|symbol: &String| symbol.strip_prefix(&prefix))
                .filter(|field: &&str| !field.is_empty() && !field.contains('.'))
                .map(str::to_owned)
                .collect();
            (type_name.clone(), fields)
        })
        .collect()
}

fn ledger_method_oracle(symbols: &BTreeSet<String>) -> BTreeSet<String> {
    symbols
        .iter()
        .filter_map(|symbol: &String| {
            symbol
                .strip_prefix("main.Ledger.")
                .or_else(|| symbol.strip_prefix("main.(*Ledger)."))
        })
        .filter(|method: &&str| !method.is_empty() && !method.contains('.'))
        .map(str::to_owned)
        .collect()
}

fn recovered_ledger_methods(analysis: &GoAnalysis) -> BTreeSet<String> {
    analysis
        .typemeta
        .types
        .iter()
        .filter(|ty: &&GoTypeRef| {
            ty.name
                .as_deref()
                .is_some_and(|name: &str| name.trim_start_matches('*').ends_with("Ledger"))
        })
        .flat_map(|ty: &GoTypeRef| ty.methods.iter())
        .filter_map(|method| method.name.clone())
        .collect()
}

fn assert_row(row: &MatrixRow) {
    let root: PathBuf = corpus_root();
    let binary: PathBuf = root.join(row.binary);
    let nm: PathBuf = root.join(format!("{}.nm.txt", row.binary));
    let objdump: PathBuf = root.join(format!("{}.objdump.txt", row.binary));
    let bytes: Vec<u8> = std::fs::read(&binary)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", binary.display()));
    let analysis: GoAnalysis =
        analyze(&bytes).unwrap_or_else(|error| panic!("analyze {}: {error}", binary.display()));
    let nm_text: String = std::fs::read_to_string(&nm)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", nm.display()));
    let objdump_text: String = std::fs::read_to_string(&objdump)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", objdump.display()));
    let nm_functions: BTreeSet<String> = common::parse_nm_text_symbols(&nm_text);
    let objdump_functions: BTreeSet<String> = objdump_symbols(&objdump_text);
    let recovered_functions: BTreeSet<String> = common::recovered_function_names(&analysis);
    let types_from_nm: BTreeSet<String> = type_oracle(&nm_functions);
    let types_from_objdump: BTreeSet<String> = type_oracle(&objdump_functions);

    assert_eq!(
        analysis.image_kind, "elf",
        "{} must remain an ELF",
        row.binary
    );
    assert_eq!(analysis.ptr_size, 8, "{} must remain 64-bit", row.binary);
    assert!(
        !nm_functions.is_empty(),
        "{}: go tool nm reference must name text symbols",
        row.binary
    );
    assert!(
        !objdump_functions.is_empty(),
        "{}: go tool objdump reference must name user functions",
        row.binary
    );
    let user_functions: BTreeSet<String> = objdump_functions
        .iter()
        .filter(|name: &&String| name.starts_with("main."))
        .cloned()
        .collect();
    assert!(
        user_functions.contains("main.main"),
        "{} {}: go tool objdump reference must retain the entrypoint",
        row.version,
        row.target
    );
    for name in &user_functions {
        assert!(
            nm_functions.contains(name.as_str()),
            "{} {}: go tool nm reference lost {name}",
            row.version,
            row.target
        );
        assert!(
            objdump_functions.contains(name),
            "{} {}: go tool objdump reference lost {name}",
            row.version,
            row.target
        );
        assert!(
            recovered_functions.contains(name),
            "{} {}: recovered functions lost {name}",
            row.version,
            row.target
        );
    }
    let methods_from_nm: BTreeSet<String> = ledger_method_oracle(&nm_functions);
    let methods_from_objdump: BTreeSet<String> = ledger_method_oracle(&objdump_functions);
    assert!(
        !methods_from_nm.is_empty(),
        "{} {}: go tool nm reference must retain Ledger methods",
        row.version,
        row.target
    );
    assert_eq!(
        methods_from_objdump, methods_from_nm,
        "{} {}: go tool objdump methods must match go tool nm",
        row.version, row.target
    );
    let recovered_methods: BTreeSet<String> = recovered_ledger_methods(&analysis);
    let ledger_types: Vec<&GoTypeRef> = analysis
        .typemeta
        .types
        .iter()
        .filter(|ty: &&GoTypeRef| {
            ty.name
                .as_deref()
                .is_some_and(|name: &str| name.trim_start_matches('*') == "main.Ledger")
        })
        .collect();
    let type_sample: Vec<&str> = analysis
        .typemeta
        .types
        .iter()
        .filter_map(|ty: &GoTypeRef| ty.name.as_deref())
        .take(20)
        .collect();
    assert_eq!(
        recovered_methods,
        methods_from_nm,
        "{} {}: recovered Ledger method names must match independent symbols; descriptors={ledger_types:?}; type_count={}; sample={type_sample:?}",
        row.version,
        row.target,
        analysis.typemeta.types.len()
    );
    assert_eq!(
        types_from_nm,
        BTreeSet::from(USER_TYPES.map(str::to_owned)),
        "{} {}: go tool nm type markers must name the complete user type set",
        row.version,
        row.target
    );
    assert_eq!(
        types_from_objdump, types_from_nm,
        "{} {}: go tool objdump type markers must match go tool nm",
        row.version, row.target
    );
    for name in &types_from_nm {
        assert!(
            recovered_type(&analysis, name).name.as_deref() == Some(name),
            "{} {}: go tool nm type oracle names {name} but recovery differs",
            row.version,
            row.target
        );
    }
    let fields_from_nm: BTreeMap<String, BTreeSet<String>> =
        field_oracle(&nm_functions, &types_from_nm);
    let fields_from_objdump: BTreeMap<String, BTreeSet<String>> =
        field_oracle(&objdump_functions, &types_from_objdump);
    assert_eq!(
        fields_from_objdump, fields_from_nm,
        "{} {}: go tool objdump field markers must match go tool nm",
        row.version, row.target
    );
    for name in USER_TYPES {
        assert!(
            recovered_type(&analysis, name).name.as_deref() == Some(name),
            "{} {}: recovered type name differs from {name}",
            row.version,
            row.target
        );
    }
    for (type_name, expected_fields) in &fields_from_nm {
        let recovered_fields: BTreeSet<&str> = recovered_field_names(&analysis, type_name);
        assert_eq!(
            recovered_fields,
            expected_fields.iter().map(String::as_str).collect(),
            "{} {}: recovered {type_name} fields must match the independent markers",
            row.version,
            row.target
        );
    }
    eprintln!(
        "{} {}: objdump={}/{} methods={}/{} types={} fields={}/{}",
        row.version,
        row.target,
        user_functions.len(),
        user_functions.len(),
        recovered_methods.len(),
        methods_from_nm.len(),
        USER_TYPES.len(),
        fields_from_nm.values().map(BTreeSet::len).sum::<usize>(),
        fields_from_nm.values().map(BTreeSet::len).sum::<usize>()
    );
}

fn assert_version(rows: &[MatrixRow]) {
    for row in rows {
        assert_row(row);
    }
}

#[test]
fn go117_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO117_ROWS);
}

#[test]
fn go118_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO118_ROWS);
}

#[test]
fn go120_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO120_ROWS);
}

#[test]
fn current_go_matrix_matches_nm_and_objdump_references() {
    assert_version(&GO126_ROWS);
}
