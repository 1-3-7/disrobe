#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::signature::{TypeSig, element_type, parse_local_sig};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const CORPUS_ROOT_REL: &str = "../../corpus/dotnet";
const UNRECOVERED_EXPRESSION: &str = "__unrecovered_expression";
const STACK_UNDERFLOW: &str = "__stack_underflow";
const STACK_UNDERFLOW_GOLDEN_REL: &str = "golden/dotnet_stack_underflow.tsv";
const STACK_UNDERFLOW_UPDATE_ENV: &str = "DISROBE_UPDATE_STACK_UNDERFLOW_GOLDEN";
const CORPUS_ASSEMBLIES: usize = 46;
const CORPUS_METHOD_FLOOR: usize = 3121;
const BUILD_OUTPUT_DIRS: [&str; 2] = ["bin", "obj"];
const REFRESH_COMMAND: &str = "DISROBE_UPDATE_STACK_UNDERFLOW_GOLDEN=1 cargo test -p disrobe-pass-dotnet --test type_fidelity";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn baseline() -> DecompiledAssembly {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    decompile_assembly(&bytes).expect("decompile baseline")
}

fn method_by_signature<'a>(
    asm: &'a DecompiledAssembly,
    needle: &str,
) -> Option<&'a StructuredMethod> {
    asm.methods.iter().find(|m: &&StructuredMethod| {
        m.signature
            .lines()
            .next_back()
            .is_some_and(|l: &str| l.contains(needle))
    })
}

fn collect_images(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            let is_build_output: bool = path
                .file_name()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .is_some_and(|n: &str| BUILD_OUTPUT_DIRS.contains(&n));
            if !is_build_output {
                collect_images(&path, out);
            }
        } else if path
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str())
            .is_some_and(|e: &str| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe"))
        {
            out.push(path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecoveredBody {
    image: String,
    token: u32,
    signature: String,
}

impl RecoveredBody {
    const fn key(&self) -> (&str, u32) {
        (self.image.as_str(), self.token)
    }

    fn record(&self) -> String {
        format!("{}\t0x{:08x}\t{}", self.image, self.token, self.signature)
    }
}

fn escape_signature(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if c == ' ' || c.is_ascii_graphic() => out.push(c),
            c => write!(out, "\\u{{{:04x}}}", u32::from(c)).expect("format into a string"),
        }
    }
    out
}

fn corpus_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push(CORPUS_ROOT_REL);
    root
}

fn golden_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(STACK_UNDERFLOW_GOLDEN_REL);
    path
}

fn read_golden() -> Vec<RecoveredBody> {
    let path: PathBuf = golden_path();
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "read the recorded stack-underflow bodies at {} ({e}); regenerate it with `{REFRESH_COMMAND}`",
            path.display()
        )
    });
    let mut records: Vec<RecoveredBody> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let (Some(image), Some(token), Some(signature)) =
            (fields.next(), fields.next(), fields.next())
        else {
            panic!(
                "{}:{} is not `image<TAB>token<TAB>signature`: {line}",
                path.display(),
                index + 1
            );
        };
        let Some(digits): Option<&str> = token.strip_prefix("0x") else {
            panic!(
                "{}:{} token must be written `0x` then eight hex digits: {token}",
                path.display(),
                index + 1
            );
        };
        let Ok(token): Result<u32, std::num::ParseIntError> = u32::from_str_radix(digits, 16)
        else {
            panic!(
                "{}:{} token is not hexadecimal: {token}",
                path.display(),
                index + 1
            )
        };
        records.push(RecoveredBody {
            image: image.to_owned(),
            token,
            signature: signature.to_owned(),
        });
    }
    records
}

fn write_golden(bodies: &[RecoveredBody]) {
    let path: PathBuf = golden_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e: std::io::Error| panic!("create {} ({e})", parent.display()));
    }
    let mut text: String = String::new();
    for body in bodies {
        text.push_str(&body.record());
        text.push('\n');
    }
    std::fs::write(&path, text)
        .unwrap_or_else(|e: std::io::Error| panic!("write {} ({e})", path.display()));
}

#[derive(Debug, Default)]
struct PlaceholderSweep {
    assemblies: usize,
    methods: usize,
    depth_capped: Vec<String>,
    underflowed: Vec<RecoveredBody>,
}

fn sweep_placeholders() -> PlaceholderSweep {
    let root: PathBuf = corpus_root();
    let mut images: Vec<PathBuf> = Vec::new();
    collect_images(&root, &mut images);
    images.sort();

    let mut sweep: PlaceholderSweep = PlaceholderSweep::default();
    for image in &images {
        let Ok(bytes) = std::fs::read(image) else {
            continue;
        };
        let Ok(asm) = decompile_assembly(&bytes) else {
            continue;
        };
        sweep.assemblies += 1;
        sweep.methods += asm.methods.len();
        let relative: String = image
            .strip_prefix(&root)
            .unwrap_or(image)
            .to_string_lossy()
            .replace('\\', "/");
        for m in &asm.methods {
            let signature: &str = m.signature.lines().next_back().unwrap_or("").trim();
            if m.body.contains(UNRECOVERED_EXPRESSION) {
                sweep
                    .depth_capped
                    .push(format!("{relative} :: {signature}"));
            }
            if m.body.contains(STACK_UNDERFLOW) {
                sweep.underflowed.push(RecoveredBody {
                    image: relative.clone(),
                    token: m.token,
                    signature: escape_signature(signature),
                });
            }
        }
    }
    sweep.underflowed.sort();
    sweep
}

fn render(bodies: &[&RecoveredBody]) -> String {
    bodies
        .iter()
        .map(|b: &&RecoveredBody| format!("  {}", b.record()))
        .collect::<Vec<String>>()
        .join("\n")
}

#[test]
fn no_recovered_body_falls_back_to_a_placeholder() {
    assert!(
        std::env::var_os(STACK_UNDERFLOW_UPDATE_ENV).is_none(),
        "{STACK_UNDERFLOW_UPDATE_ENV} rewrites the recorded bodies, so this run cannot also \
         check them; re-run without the variable once the rewritten file is reviewed"
    );
    let sweep: PlaceholderSweep = sweep_placeholders();
    assert_eq!(
        sweep.assemblies, CORPUS_ASSEMBLIES,
        "the committed corpus holds exactly {CORPUS_ASSEMBLIES} assemblies this pass can parse, \
         and this run reached {}; a smaller number means the corpus shrank or an assembly stopped \
         parsing, a larger one means new coverage that has to be recorded here",
        sweep.assemblies
    );
    assert!(
        sweep.methods >= CORPUS_METHOD_FLOOR,
        "the sweep recovered {} bodies against a floor of {CORPUS_METHOD_FLOOR}; \
         losing recovered bodies is a regression even when every remaining body is clean",
        sweep.methods
    );
    assert!(
        sweep.depth_capped.is_empty(),
        "{} of {} recovered bodies across {} assemblies emit `{UNRECOVERED_EXPRESSION}`; \
         an expression that exceeded the depth cap is lost output, not recovered source: {:#?}",
        sweep.depth_capped.len(),
        sweep.methods,
        sweep.assemblies,
        sweep.depth_capped
    );
    let untokenized: Vec<&RecoveredBody> = sweep
        .underflowed
        .iter()
        .filter(|b: &&RecoveredBody| b.token == 0)
        .collect();
    assert!(
        untokenized.is_empty(),
        "every recovered body carries the metadata token it was decompiled from, and {} \
         reached this check with token zero; without a token these bodies cannot be told apart \
         from one another:\n{}",
        untokenized.len(),
        render(&untokenized)
    );

    let golden: Vec<RecoveredBody> = read_golden();
    let recorded: BTreeSet<(&str, u32)> = golden.iter().map(|b: &RecoveredBody| b.key()).collect();
    let unrecorded: Vec<&RecoveredBody> = sweep
        .underflowed
        .iter()
        .filter(|b: &&RecoveredBody| !recorded.contains(&b.key()))
        .collect();
    assert!(
        unrecorded.is_empty(),
        "`{STACK_UNDERFLOW}` reached {} recovered bodies that {} does not list, out of {} bodies \
         across {} assemblies. A body that used to reconstruct and now underflows is a regression \
         in the stack model and has to be fixed here, not recorded. A body that is newly reachable \
         because an assembly started parsing is new coverage: record it with `{REFRESH_COMMAND}` \
         and review the added names in the diff.\n{}",
        unrecorded.len(),
        golden_path().display(),
        sweep.methods,
        sweep.assemblies,
        render(&unrecorded)
    );
}

#[test]
fn recorded_stack_underflow_bodies_are_current() {
    let sweep: PlaceholderSweep = sweep_placeholders();
    if std::env::var_os(STACK_UNDERFLOW_UPDATE_ENV).is_some() {
        write_golden(&sweep.underflowed);
        panic!(
            "{STACK_UNDERFLOW_UPDATE_ENV} was set, so {} now holds the {} bodies this run \
             observed. Read the diff before committing it: an added name is a body that stopped \
             reconstructing and a removed name is one that started. Re-run without the variable \
             to check the gate.",
            golden_path().display(),
            sweep.underflowed.len()
        );
    }
    let golden: Vec<RecoveredBody> = read_golden();
    let observed: BTreeSet<(&str, u32)> = sweep
        .underflowed
        .iter()
        .map(|b: &RecoveredBody| b.key())
        .collect();
    let reconstructed: Vec<&RecoveredBody> = golden
        .iter()
        .filter(|b: &&RecoveredBody| !observed.contains(&b.key()))
        .collect();
    assert!(
        reconstructed.is_empty(),
        "{} bodies listed in {} now reconstruct without `{STACK_UNDERFLOW}`. That is an \
         improvement, not a failure, and the only thing left to do is drop them from the record \
         with `{REFRESH_COMMAND}` so the file keeps describing what the pass actually does.\n{}",
        reconstructed.len(),
        golden_path().display(),
        render(&reconstructed)
    );
    let drifted: Vec<String> = golden
        .iter()
        .filter_map(|b: &RecoveredBody| {
            let current: &RecoveredBody = sweep
                .underflowed
                .iter()
                .find(|o: &&RecoveredBody| o.key() == b.key())?;
            (current.signature != b.signature).then(|| {
                format!(
                    "  {}\t0x{:08x}\n    recorded: {}\n    current:  {}",
                    b.image, b.token, b.signature, current.signature
                )
            })
        })
        .collect();
    assert!(
        drifted.is_empty(),
        "{} recorded signatures no longer match how the pass renders those bodies. The bodies \
         themselves are unchanged, so this is a rendering change rather than a regression; \
         refresh the record with `{REFRESH_COMMAND}`.\n{}",
        drifted.len(),
        drifted.join("\n")
    );
}

#[test]
fn local_var_sig_parses_count_and_types() {
    let blob: [u8; 6] = [
        0x07,
        0x03,
        element_type::I4,
        element_type::SZARRAY,
        element_type::STRING,
        element_type::R8,
    ];
    let locals: Vec<TypeSig> = parse_local_sig(&blob).expect("local sig parses");
    assert_eq!(locals.len(), 3, "header declares three locals");
    assert_eq!(locals[0], TypeSig::I4);
    assert_eq!(locals[1], TypeSig::SzArray(Box::new(TypeSig::String)));
    assert_eq!(locals[2], TypeSig::R8);
}

#[test]
fn non_local_calling_convention_rejected() {
    assert!(parse_local_sig(&[0x06, element_type::I4]).is_err());
    assert!(parse_local_sig(&[]).is_err());
}

#[test]
fn recovered_locals_are_never_untyped_var() {
    let asm: DecompiledAssembly = baseline();
    let offenders: Vec<&str> = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains("var local"))
        .map(|m: &StructuredMethod| m.signature.as_str())
        .collect();
    assert!(
        offenders.is_empty(),
        "every recovered local must carry a declared type from the local-var signature; \
         {} method(s) still emit `var local`, first: {:?}",
        offenders.len(),
        offenders.first()
    );
}

#[test]
fn create_range_recovers_param_names_and_local_types() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "CreateRange").expect("CreateRange present in baseline");
    assert!(
        m.signature.contains("CreateRange(int start, int count)"),
        "params must carry recovered names start/count and int types; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("int[] local0"),
        "the int[] array local must be declared with its type; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("int local1"),
        "the loop counter local must be declared int; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("local1 < count") && m.body.contains("start + local1"),
        "body must reference the recovered parameter names start/count, not argN; got:\n{}",
        m.body
    );
    assert!(
        !m.body.contains("arg1") && !m.body.contains("arg2"),
        "no positional argN may remain when names were recovered; got:\n{}",
        m.body
    );
    assert!(m.named_params >= 2, "two params resolved a real name");
    assert!(m.typed_locals >= 2, "at least two locals carry a type");
}

#[test]
fn distance_to_recovers_typed_local_and_named_param() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "DistanceTo").expect("DistanceTo present in baseline");
    assert!(
        m.signature
            .contains("DistanceTo(EdgeCases.Coordinate other)"),
        "the Coordinate parameter must resolve its type token and keep the name `other`; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("double local0"),
        "the dx/dy local must be declared double from the local-var signature; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("other"),
        "body must reference parameter `other`; got:\n{}",
        m.body
    );
}

#[test]
fn shift_resolves_ldarga_to_named_param_not_positional() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "Coordinate Shift(").expect("Shift present in baseline");
    assert!(
        m.signature
            .contains("Shift(EdgeCases.Coordinate c, double dx, double dy)"),
        "all three params resolve names c/dx/dy and the Coordinate type; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("c.Latitude") && !m.body.contains("(&arg0)") && !m.body.contains("arg0."),
        "ldarga on the first static parameter must resolve to the named param `c`, not positional arg0; got:\n{}",
        m.body
    );
    assert!(
        !m.body.contains("(&c)"),
        "an instance access on a struct parameter renders as `c`, not the invalid address-of receiver `(&c)`; got:\n{}",
        m.body
    );
}

#[test]
fn typed_local_rate_is_total_on_clean_baseline() {
    let asm: DecompiledAssembly = baseline();
    let untyped_methods: usize = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains("var local"))
        .count();
    let positional_methods: usize = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| {
            m.body.match_indices("arg").any(|(i, _): (usize, &str)| {
                m.body[i + 3..]
                    .chars()
                    .next()
                    .is_some_and(|c: char| c.is_ascii_digit())
            })
        })
        .count();
    assert_eq!(
        untyped_methods, 0,
        "no method on the clean baseline may carry an untyped `var` local"
    );
    assert!(
        positional_methods <= 8,
        "only genuinely-unnamed compiler-generated params may keep argN; got {positional_methods} methods"
    );
}
