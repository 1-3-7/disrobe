#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_scriptlang::lang::r_rds::{
    RdsAltrep, RdsClosure, RdsComplexVector, RdsContainer, RdsEncoding, RdsEnvironmentInfo,
    RdsObject, RdsRawVector, RdsS4Object,
};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

#[path = "support/r_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod r_toolchain;

use r_toolchain::{RRuntime, require_r, run_bounded, workspace_root};

const GRADED: &str = "the R serialization reader compared against what real R reports";

#[derive(Debug, Default, Clone)]
struct Reference {
    file: String,
    container: String,
    stream_root_type: String,
    value_type: String,
    value_length: Option<usize>,
    bindings: Vec<String>,
    names: Vec<String>,
    classes: Vec<String>,
    raw_bytes: Option<String>,
    complexes: Vec<(String, String)>,
    formals: Vec<(String, String)>,
    body: Option<String>,
    bytecode_expression: Option<String>,
    s4_class: Option<String>,
    s4_slots: Vec<String>,
    env_bindings: Vec<String>,
    env_parents: Vec<String>,
    vector_deparse: Option<String>,
    strings: Vec<String>,
    symbols: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Variant {
    version: u32,
    encoding: RdsEncoding,
    container: RdsContainer,
}

fn unescape(field: &str) -> String {
    let mut out: String = String::with_capacity(field.len());
    let mut chars: std::str::Chars<'_> = field.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn parse_references(report: &str) -> Vec<Reference> {
    let mut all: Vec<Reference> = Vec::new();
    let mut current: Option<Reference> = None;
    for line in report.lines() {
        let mut parts: std::str::Split<'_, char> = line.split('\t');
        let Some(key): Option<&str> = parts.next() else {
            continue;
        };
        let fields: Vec<String> = parts.map(unescape).collect();
        let first: String = fields.first().cloned().unwrap_or_default();
        if key == "begin" {
            if let Some(done) = current.take() {
                all.push(done);
            }
            current = Some(Reference {
                file: first,
                ..Reference::default()
            });
            continue;
        }
        let Some(reference): Option<&mut Reference> = current.as_mut() else {
            continue;
        };
        match key {
            "container" => reference.container = first,
            "streamroottype" => reference.stream_root_type = first,
            "valuetype" => reference.value_type = first,
            "valuelength" => reference.value_length = first.parse::<usize>().ok(),
            "binding" => reference.bindings.push(first),
            "name" => reference.names.push(first),
            "class" => reference.classes.push(first),
            "rawbytes" => reference.raw_bytes = Some(first),
            "complex" => reference
                .complexes
                .push((first, fields.get(1).cloned().unwrap_or_default())),
            "formal" => reference
                .formals
                .push((first, fields.get(1).cloned().unwrap_or_default())),
            "body" => reference.body = Some(first),
            "bytecodeexpr" => reference.bytecode_expression = Some(first),
            "s4class" => reference.s4_class = Some(first),
            "s4slot" => reference.s4_slots.push(first),
            "envbinding" => reference.env_bindings.push(first),
            "envparent" => reference.env_parents.push(first),
            "vectordeparse" => reference.vector_deparse = Some(first),
            "string" => reference.strings.push(first),
            "symbol" => reference.symbols.push(first),
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        all.push(done);
    }
    all
}

fn normalize_expression(text: &str) -> String {
    text.chars()
        .filter(|ch: &char| !ch.is_whitespace() && *ch != ';')
        .collect()
}

fn variant_from_name(name: &str) -> Variant {
    let version: u32 = if name.contains(".v2.") { 2 } else { 3 };
    let encoding: RdsEncoding = if name.contains(".ascii.") {
        RdsEncoding::Ascii
    } else if name.contains(".native.") {
        RdsEncoding::Binary
    } else {
        RdsEncoding::Xdr
    };
    let container: RdsContainer = if Path::new(name)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("rda"))
    {
        RdsContainer::Rda
    } else {
        RdsContainer::Rds
    };
    Variant {
        version,
        encoding,
        container,
    }
}

fn sorted(values: &[String]) -> Vec<String> {
    let unique: BTreeSet<String> = values.iter().cloned().collect();
    unique.into_iter().collect()
}

fn missing(expected: &[String], recovered: &[String]) -> Vec<String> {
    let present: BTreeSet<&String> = recovered.iter().collect();
    expected
        .iter()
        .filter(|value: &&String| !present.contains(*value))
        .cloned()
        .collect()
}

struct Grade {
    checks: usize,
    defects: Vec<String>,
}

impl Grade {
    const fn new() -> Self {
        Self {
            checks: 0usize,
            defects: Vec::new(),
        }
    }

    fn equals<T: PartialEq + std::fmt::Debug>(&mut self, field: &str, expected: &T, found: &T) {
        self.checks += 1usize;
        if expected != found {
            self.defects.push(format!(
                "{field}: R reports {expected:?}, disrobe recovered {found:?}"
            ));
        }
    }

    fn contains(&mut self, field: &str, expected: &[String], recovered: &[String]) {
        if expected.is_empty() {
            return;
        }
        self.checks += 1usize;
        let absent: Vec<String> = missing(expected, recovered);
        if !absent.is_empty() {
            self.defects.push(format!(
                "{field}: R reports {expected:?}, disrobe never recovered {absent:?} (recovered \
                 {recovered:?})"
            ));
        }
    }
}

fn is_sized_vector(type_name: &str) -> bool {
    matches!(
        type_name,
        "logical" | "integer" | "double" | "complex" | "character" | "raw" | "list" | "expression"
    )
}

fn grade_one(reference: &Reference, object: &RdsObject) -> Grade {
    let mut grade: Grade = Grade::new();
    let variant: Variant = variant_from_name(&reference.file);

    grade.equals("container", &variant.container, &object.header.container);
    grade.equals("format version", &variant.version, &object.header.version);
    grade.equals("encoding", &variant.encoding, &object.header.encoding);
    grade.equals(
        "version 3 native encoding string",
        &(variant.version >= 3),
        &object.header.native_encoding.is_some(),
    );
    grade.equals("root type", &reference.stream_root_type, &object.root_type);

    if reference.container == "rds" && is_sized_vector(&reference.stream_root_type) {
        grade.equals("root length", &reference.value_length, &object.root_length);
    }

    grade.contains("names attribute", &reference.names, &object.names);
    grade.contains("class attribute", &reference.classes, &object.class);
    grade.contains("workspace binding", &reference.bindings, &object.symbols);

    if let Some(ref expected_hex) = reference.raw_bytes {
        grade.checks += 1usize;
        let recovered: Option<&RdsRawVector> = object.raw_vectors.first();
        let found: String = recovered.map_or_else(String::new, |vector: &RdsRawVector| {
            vector
                .bytes
                .iter()
                .fold(String::new(), |mut acc: String, byte: &u8| {
                    let _: core::fmt::Result = write!(acc, "{byte:02x}");
                    acc
                })
        });
        if &found != expected_hex {
            grade.defects.push(format!(
                "raw vector bytes: R reports {expected_hex}, disrobe recovered {found}"
            ));
        }
    }

    if !reference.complexes.is_empty() {
        grade.checks += 1usize;
        let recovered: Vec<(String, String)> =
            object
                .complex_vectors
                .first()
                .map_or_else(Vec::new, |vector: &RdsComplexVector| {
                    vector
                        .values
                        .iter()
                        .map(|value| {
                            (
                                normalize_expression(&value.re),
                                normalize_expression(&value.im),
                            )
                        })
                        .collect()
                });
        let expected: Vec<(String, String)> = reference
            .complexes
            .iter()
            .map(|(re, im): &(String, String)| (normalize_expression(re), normalize_expression(im)))
            .collect();
        if recovered != expected {
            grade.defects.push(format!(
                "complex vector: R reports {expected:?}, disrobe recovered {recovered:?}"
            ));
        }
    }

    if !reference.formals.is_empty() || reference.body.is_some() {
        grade.checks += 1usize;
        match object.closures.first() {
            Some(closure) => grade_closure(reference, closure, &mut grade),
            None => grade.defects.push(format!(
                "closure: R reports a closure with formals {:?}, disrobe recovered none",
                reference.formals
            )),
        }
    }

    if let Some(ref expected) = reference.bytecode_expression {
        grade.checks += 1usize;
        let found: Option<&String> = object.bytecode_expressions.first();
        let matched: bool = found.is_some_and(|value: &String| {
            normalize_expression(value) == normalize_expression(expected)
        });
        if !matched {
            grade.defects.push(format!(
                "bytecode expression: R deparses {expected:?}, disrobe recovered {found:?}"
            ));
        }
    }

    if let Some(ref expected) = reference.s4_class {
        grade.checks += 1usize;
        let recovered: Option<&RdsS4Object> = object.s4_objects.first();
        let found: Option<&str> = recovered.and_then(|s4: &RdsS4Object| s4.class.as_deref());
        if found != Some(expected.as_str()) {
            grade.defects.push(format!(
                "S4 class: R reports {expected:?}, disrobe recovered {found:?}"
            ));
        }
        let slots: Vec<String> =
            recovered.map_or_else(Vec::new, |s4: &RdsS4Object| s4.slots.clone());
        grade.contains("S4 slots", &sorted(&reference.s4_slots), &slots);
    }

    if !reference.env_bindings.is_empty() {
        grade.checks += 1usize;
        let recovered: Vec<String> = object
            .environments
            .first()
            .map_or_else(Vec::new, |env: &RdsEnvironmentInfo| env.bindings.clone());
        let expected: Vec<String> = sorted(&reference.env_bindings);
        if sorted(&recovered) != expected {
            grade.defects.push(format!(
                "environment bindings: R reports {expected:?}, disrobe recovered {recovered:?}"
            ));
        }
    }

    if let Some(ref deparse) = reference.vector_deparse
        && let Some(altrep) = object.altrep_objects.first()
        && let Some(ref materialized) = altrep.materialized
    {
        grade.checks += 1usize;
        if normalize_expression(materialized) != normalize_expression(deparse) {
            grade.defects.push(format!(
                "altrep materialization: R deparses {deparse:?}, disrobe recovered {materialized:?}"
            ));
        }
    }

    if variant.version == 2 {
        grade.checks += 1usize;
        if !object.altrep_objects.is_empty() {
            let classes: Vec<Option<String>> = object
                .altrep_objects
                .iter()
                .map(|altrep: &RdsAltrep| altrep.class.clone())
                .collect();
            grade.defects.push(format!(
                "altrep in a version 2 stream: R never writes ALTREP at format version 2, yet \
                 disrobe reported {classes:?}"
            ));
        }
    }

    grade.contains("string values", &reference.strings, &object.string_values);
    grade.contains("symbols", &reference.symbols, &object.symbols);
    grade.contains(
        "symbol print names",
        &reference.symbols,
        &object.string_values,
    );

    grade
}

fn grade_closure(reference: &Reference, closure: &RdsClosure, grade: &mut Grade) {
    let recovered: Vec<(String, String)> = closure
        .formals
        .iter()
        .map(|formal| {
            (
                formal.name.clone(),
                formal.default.as_ref().map_or_else(
                    || "<none>".to_owned(),
                    |value: &String| normalize_expression(value),
                ),
            )
        })
        .collect();
    let expected: Vec<(String, String)> = reference
        .formals
        .iter()
        .map(|(name, default): &(String, String)| (name.clone(), normalize_expression(default)))
        .collect();
    if recovered != expected {
        grade.defects.push(format!(
            "closure formals: R reports {expected:?}, disrobe recovered {recovered:?}"
        ));
    }
    if let Some(ref body) = reference.body
        && normalize_expression(&closure.body) != normalize_expression(body)
    {
        grade.defects.push(format!(
            "closure body: R deparses {body:?}, disrobe recovered {:?}",
            closure.body
        ));
    }
}

fn read_with_disrobe(path: &Path) -> Result<RdsObject, String> {
    let bytes: Vec<u8> = std::fs::read(path).map_err(|error: std::io::Error| error.to_string())?;
    if classify(&bytes) != Some(ScriptLang::R) {
        return Err(format!(
            "classify() did not route {} to the R reader, so `disrobe auto` would never reach it",
            path.display()
        ));
    }
    match analyze(&bytes) {
        Ok(ScriptArtifact::R(object)) => Ok(*object),
        Ok(other) => Err(format!(
            "analyze() produced {other:?} rather than an R object"
        )),
        Err(error) => Err(error.to_string()),
    }
}

const DECLARED_ROOT_TYPES: [&str; 19] = [
    "NULL",
    "symbol",
    "pairlist",
    "closure",
    "environment",
    "language",
    "special",
    "builtin",
    "logical",
    "integer",
    "double",
    "complex",
    "character",
    "...",
    "list",
    "expression",
    "bytecode",
    "raw",
    "S4",
];

const DECLARED_FEATURES: [&str; 7] = [
    "altrep object",
    "external pointer",
    "S4 object",
    "environment frame",
    "closure",
    "bytecode expression",
    "workspace binding",
];

#[derive(Debug, Default)]
struct Coverage {
    root_types: BTreeSet<String>,
    variants: BTreeSet<String>,
    features: BTreeSet<String>,
}

impl Coverage {
    fn record(&mut self, reference: &Reference, object: &RdsObject) {
        self.root_types.insert(reference.stream_root_type.clone());
        let variant: Variant = variant_from_name(&reference.file);
        self.variants.insert(format!(
            "v{} {:?} {:?} {}",
            variant.version,
            variant.encoding,
            variant.container,
            compression_from_name(&reference.file)
        ));
        if !object.altrep_objects.is_empty() {
            self.features.insert("altrep object".to_owned());
        }
        if !object.external_pointers.is_empty() {
            self.features.insert("external pointer".to_owned());
        }
        if !object.s4_objects.is_empty() {
            self.features.insert("S4 object".to_owned());
        }
        if object
            .environments
            .iter()
            .any(|env: &RdsEnvironmentInfo| !env.bindings.is_empty())
        {
            self.features.insert("environment frame".to_owned());
        }
        if !object.closures.is_empty() {
            self.features.insert("closure".to_owned());
        }
        if !object.bytecode_expressions.is_empty() {
            self.features.insert("bytecode expression".to_owned());
        }
        if !reference.bindings.is_empty() {
            self.features.insert("workspace binding".to_owned());
        }
    }
}

fn compression_from_name(name: &str) -> &'static str {
    if name.contains(".gzip.") {
        "gzip"
    } else if name.contains(".bzip2.") {
        "bzip2"
    } else if name.contains(".xz.") {
        "xz"
    } else {
        "uncompressed"
    }
}

fn absent<'a>(declared: &[&'a str], observed: &BTreeSet<String>) -> Vec<&'a str> {
    declared
        .iter()
        .filter(|value: &&&str| !observed.contains(**value))
        .copied()
        .collect()
}

fn describe_corpus(runtime: &RRuntime, describe: &Path, corpus: &Path) -> String {
    let mut command: Command = Command::new(&runtime.rscript);
    command.arg("--vanilla").arg(describe).arg(corpus);
    let Some((success, out, err)): Option<(bool, String, String)> = run_bounded(command) else {
        panic!(
            "Rscript {} {} did not finish within the call timeout, so nothing was graded",
            describe.display(),
            corpus.display()
        );
    };
    assert!(
        success,
        "Rscript could not describe the committed corpus, so there is no reference to grade \
         against. stdout: {}\nstderr: {}",
        out.trim(),
        err.trim()
    );
    out
}

#[test]
fn recovered_objects_match_what_real_r_reports() {
    let Some(runtime): Option<RRuntime> = require_r(GRADED) else {
        return;
    };
    let root: PathBuf = workspace_root();
    let corpus: PathBuf = root.join("corpus").join("r").join("objects");
    let describe: PathBuf = root.join("corpus").join("r").join("describe.R");
    assert!(
        corpus.is_dir(),
        "the committed R corpus is missing at {}, so this run would grade nothing",
        corpus.display()
    );

    let report: String = describe_corpus(&runtime, &describe, &corpus);
    let references: Vec<Reference> = parse_references(&report);
    assert!(
        references.len() >= 200,
        "R described only {} objects, which is fewer than the committed corpus carries, so the \
         reference is incomplete",
        references.len()
    );

    let mut graded: usize = 0usize;
    let mut checks: usize = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut coverage: Coverage = Coverage::default();

    for reference in &references {
        let path: PathBuf = corpus.join(&reference.file);
        match read_with_disrobe(&path) {
            Ok(object) => {
                coverage.record(reference, &object);
                let grade: Grade = grade_one(reference, &object);
                checks += grade.checks;
                graded += 1usize;
                for defect in grade.defects {
                    failures.push(format!("{}: {defect}", reference.file));
                }
            }
            Err(error) => {
                failures.push(format!(
                    "{}: R read this file and reported a {} object, but disrobe could not read it \
                     at all: {error}",
                    reference.file, reference.value_type
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} committed R objects disagree with what R itself reports:\n{}",
        failures.len(),
        references.len(),
        failures.join("\n")
    );
    assert!(
        graded == references.len() && graded > 0usize,
        "graded {graded} of {} objects; a reference R produced but disrobe never compared is a \
         false green",
        references.len()
    );
    assert!(
        checks > graded,
        "only {checks} field comparisons ran across {graded} objects, which is too few to have \
         compared anything of substance"
    );

    let untyped: Vec<&str> = absent(&DECLARED_ROOT_TYPES, &coverage.root_types);
    assert!(
        untyped.is_empty(),
        "the corpus no longer carries a root object of every declared R type; {untyped:?} are \
         claimed but never appear, so the input space is narrower than the claim"
    );
    let unfeatured: Vec<&str> = absent(&DECLARED_FEATURES, &coverage.features);
    assert!(
        unfeatured.is_empty(),
        "these declared recovery features were never exercised by any committed object: \
         {unfeatured:?}"
    );
    assert!(
        coverage.variants.len() >= 14usize,
        "only {} serialization variants appear across the corpus: {:?}",
        coverage.variants.len(),
        coverage.variants
    );

    println!(
        "\nGRADED: {graded} R objects written by R {}, {checks} field comparisons, {} root types, \
         {} serialization variants, every expected value read back out of R itself\n",
        runtime.release,
        coverage.root_types.len(),
        coverage.variants.len()
    );
    for variant in &coverage.variants {
        println!("  variant graded: {variant}");
    }
}
