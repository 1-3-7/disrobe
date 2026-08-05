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
use disrobe_pass_dotnet::iterator_reverse::is_mangled_metadata_identifier;
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, ParamModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::signature::{TypeSig, element_type, parse_local_sig};
use disrobe_pass_dotnet::structurize::{StructuredMethod, split_csharp_parameter_declarations};

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const CORPUS_ROOT_REL: &str = "../../corpus/dotnet";
const UNRECOVERED_EXPRESSION: &str = "__unrecovered_expression";
const STACK_UNDERFLOW: &str = "__stack_underflow";
const STACK_UNDERFLOW_GOLDEN_REL: &str = "golden/dotnet_stack_underflow.tsv";
const UNPARSED_GOLDEN_REL: &str = "golden/dotnet_unparsed_images.tsv";
const STACK_UNDERFLOW_UPDATE_ENV: &str = "DISROBE_UPDATE_STACK_UNDERFLOW_GOLDEN";
const CORPUS_IMAGES: usize = 49;
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RefusedImage {
    image: String,
    reason: String,
}

impl RefusedImage {
    fn record(&self) -> String {
        format!("{}\t{}", self.image, self.reason)
    }
}

fn escape_field(raw: &str) -> String {
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

fn golden_path(relative: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(relative);
    path
}

fn read_records(path: &Path) -> Vec<(usize, String)> {
    let text: String = std::fs::read_to_string(path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "read {} ({e}); regenerate it with `{REFRESH_COMMAND}`",
            path.display()
        )
    });
    text.lines()
        .enumerate()
        .filter(|(_, line): &(usize, &str)| !line.is_empty())
        .map(|(index, line): (usize, &str)| (index + 1, line.to_owned()))
        .collect()
}

fn split_record<const N: usize>(line: &str, path: &Path, line_number: usize) -> [String; N] {
    let fields: Vec<String> = line.splitn(N, '\t').map(str::to_owned).collect();
    let Ok(record): Result<[String; N], Vec<String>> = fields.try_into() else {
        panic!(
            "{}:{line_number} needs {N} tab separated fields: {line}",
            path.display()
        )
    };
    record
}

fn parse_token(text: &str, path: &Path, line_number: usize) -> u32 {
    let Some(digits): Option<&str> = text.strip_prefix("0x") else {
        panic!(
            "{}:{line_number} token must be written `0x` then eight hex digits: {text}",
            path.display()
        )
    };
    u32::from_str_radix(digits, 16).unwrap_or_else(|e: std::num::ParseIntError| {
        panic!(
            "{}:{line_number} token is not hexadecimal: {text} ({e})",
            path.display()
        )
    })
}

fn read_underflow_golden() -> Vec<RecoveredBody> {
    let path: PathBuf = golden_path(STACK_UNDERFLOW_GOLDEN_REL);
    read_records(&path)
        .into_iter()
        .map(|(line_number, line): (usize, String)| {
            let [image, token, signature]: [String; 3] = split_record(&line, &path, line_number);
            RecoveredBody {
                image,
                token: parse_token(&token, &path, line_number),
                signature,
            }
        })
        .collect()
}

fn read_refusal_golden() -> Vec<RefusedImage> {
    let path: PathBuf = golden_path(UNPARSED_GOLDEN_REL);
    read_records(&path)
        .into_iter()
        .map(|(line_number, line): (usize, String)| {
            let [image, reason]: [String; 2] = split_record(&line, &path, line_number);
            RefusedImage { image, reason }
        })
        .collect()
}

fn write_golden(relative: &str, records: &[String]) {
    let path: PathBuf = golden_path(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e: std::io::Error| panic!("create {} ({e})", parent.display()));
    }
    let mut text: String = String::new();
    for record in records {
        text.push_str(record);
        text.push('\n');
    }
    std::fs::write(&path, text)
        .unwrap_or_else(|e: std::io::Error| panic!("write {} ({e})", path.display()));
}

#[derive(Debug, Default)]
struct PlaceholderSweep {
    images: usize,
    assemblies: usize,
    methods: usize,
    depth_capped: Vec<String>,
    underflowed: Vec<RecoveredBody>,
    refused: Vec<RefusedImage>,
}

fn sweep_placeholders() -> PlaceholderSweep {
    let root: PathBuf = corpus_root();
    let mut images: Vec<PathBuf> = Vec::new();
    collect_images(&root, &mut images);
    images.sort();

    let mut sweep: PlaceholderSweep = PlaceholderSweep::default();
    for image in &images {
        sweep.images += 1;
        let relative: String = image
            .strip_prefix(&root)
            .unwrap_or(image)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes: Vec<u8> = std::fs::read(image).unwrap_or_else(|e: std::io::Error| {
            panic!(
                "read the committed corpus image {} ({e}); every discovered image has to be \
                 readable or the sweep is scoring itself against a corpus it cannot see",
                image.display()
            )
        });
        let asm: DecompiledAssembly = match decompile_assembly(&bytes) {
            Ok(asm) => asm,
            Err(e) => {
                sweep.refused.push(RefusedImage {
                    image: relative,
                    reason: escape_field(&e.to_string()),
                });
                continue;
            }
        };
        sweep.assemblies += 1;
        sweep.methods += asm.methods.len();
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
                    signature: escape_field(signature),
                });
            }
        }
    }
    sweep.underflowed.sort();
    sweep.refused.sort();
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
        sweep.images, CORPUS_IMAGES,
        "the sweep discovered {} images under the corpus and the committed tree holds \
         {CORPUS_IMAGES}; this count is the denominator every other number here is measured \
         against, so it is pinned rather than floored. Fewer means the corpus shrank and the run \
         is scoring itself against a smaller universe, more means an image was added and has to be \
         accounted for on one side of the ratio or the other",
        sweep.images
    );
    assert_eq!(
        sweep.assemblies, CORPUS_ASSEMBLIES,
        "{} of the {CORPUS_IMAGES} discovered images decompiled and the recorded state is \
         {CORPUS_ASSEMBLIES} of {CORPUS_IMAGES}; a smaller number means an assembly stopped \
         parsing, a larger one means new coverage that has to be recorded here",
        sweep.assemblies
    );
    let refusal_golden: Vec<RefusedImage> = read_refusal_golden();
    let refused_names: BTreeSet<&str> = refusal_golden
        .iter()
        .map(|r: &RefusedImage| r.image.as_str())
        .collect();
    let unrecorded_refusals: Vec<&RefusedImage> = sweep
        .refused
        .iter()
        .filter(|r: &&RefusedImage| !refused_names.contains(r.image.as_str()))
        .collect();
    assert!(
        unrecorded_refusals.is_empty(),
        "{} images did not decompile and {} does not list them. An image that used to decompile \
         and now does not is a regression in the reader. An image that never decompiled is either \
         a native binary this pass is right to decline, in which case record it with \
         `{REFRESH_COMMAND}`, or a fixture that has been contributing nothing since the day it \
         landed.\n{}",
        unrecorded_refusals.len(),
        golden_path(UNPARSED_GOLDEN_REL).display(),
        unrecorded_refusals
            .iter()
            .map(|r: &&RefusedImage| format!("  {}", r.record()))
            .collect::<Vec<String>>()
            .join("\n")
    );
    assert!(
        sweep.methods >= CORPUS_METHOD_FLOOR,
        "the sweep emitted {} bodies against a floor of {CORPUS_METHOD_FLOOR}; losing an emitted \
         body is a regression even when every remaining body is clean. This floor counts every \
         body the pass emits, including the ones that state a refusal, so it is a population \
         floor and never a count of bodies recovered into legal source",
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

    let golden: Vec<RecoveredBody> = read_underflow_golden();
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
        golden_path(STACK_UNDERFLOW_GOLDEN_REL).display(),
        sweep.methods,
        sweep.assemblies,
        render(&unrecorded)
    );
}

#[test]
fn recorded_stack_underflow_bodies_are_current() {
    let sweep: PlaceholderSweep = sweep_placeholders();
    if std::env::var_os(STACK_UNDERFLOW_UPDATE_ENV).is_some() {
        write_golden(
            STACK_UNDERFLOW_GOLDEN_REL,
            &sweep
                .underflowed
                .iter()
                .map(RecoveredBody::record)
                .collect::<Vec<String>>(),
        );
        write_golden(
            UNPARSED_GOLDEN_REL,
            &sweep
                .refused
                .iter()
                .map(RefusedImage::record)
                .collect::<Vec<String>>(),
        );
        panic!(
            "{STACK_UNDERFLOW_UPDATE_ENV} was set, so {} now holds the {} bodies this run \
             observed and {} holds the {} images it could not decompile. Read both diffs before \
             committing them: an added body is one that stopped reconstructing, a removed body is \
             one that started, and an added image is one the reader no longer accepts. Re-run \
             without the variable to check the gate.",
            golden_path(STACK_UNDERFLOW_GOLDEN_REL).display(),
            sweep.underflowed.len(),
            golden_path(UNPARSED_GOLDEN_REL).display(),
            sweep.refused.len()
        );
    }
    let golden: Vec<RecoveredBody> = read_underflow_golden();
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
        golden_path(STACK_UNDERFLOW_GOLDEN_REL).display(),
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

    let refusal_golden: Vec<RefusedImage> = read_refusal_golden();
    let refused_now: BTreeSet<&str> = sweep
        .refused
        .iter()
        .map(|r: &RefusedImage| r.image.as_str())
        .collect();
    let accepted: Vec<&RefusedImage> = refusal_golden
        .iter()
        .filter(|r: &&RefusedImage| !refused_now.contains(r.image.as_str()))
        .collect();
    assert!(
        accepted.is_empty(),
        "{} images listed in {} now decompile. That is new coverage, not a failure: drop them \
         from the record with `{REFRESH_COMMAND}`, and raise CORPUS_ASSEMBLIES to match, since \
         the bodies they bring are now part of the population.\n{}",
        accepted.len(),
        golden_path(UNPARSED_GOLDEN_REL).display(),
        accepted
            .iter()
            .map(|r: &&RefusedImage| format!("  {}", r.record()))
            .collect::<Vec<String>>()
            .join("\n")
    );
    let changed_reasons: Vec<String> = refusal_golden
        .iter()
        .filter_map(|r: &RefusedImage| {
            let current: &RefusedImage = sweep
                .refused
                .iter()
                .find(|o: &&RefusedImage| o.image == r.image)?;
            (current.reason != r.reason).then(|| {
                format!(
                    "  {}\n    recorded: {}\n    current:  {}",
                    r.image, r.reason, current.reason
                )
            })
        })
        .collect();
    assert!(
        changed_reasons.is_empty(),
        "{} images are still declined but for a different stated reason than the one on record. \
         The reason is what tells a reader whether the refusal is correct, so refresh it with \
         `{REFRESH_COMMAND}` and check that the new wording still describes a native image rather \
         than a reader that broke earlier than it used to.\n{}",
        changed_reasons.len(),
        changed_reasons.join("\n")
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

const BASELINE_MERGE_RECOVERED: [(u32, &str); 7] = [
    (
        0x0600_0014,
        "a value live across a two-arm merge, stored to a field at the join",
    ),
    (
        0x0600_010e,
        "a value live across a two-arm merge, stored to a local after a loop",
    ),
    (
        0x0600_01a3,
        "a value live across a two-arm merge inside a loop body",
    ),
    (
        0x0600_01bb,
        "two values live across two consecutive two-arm merges",
    ),
    (
        0x0600_0006,
        "two nested merges whose arms each consume the address the condition tested, so each arm \
         is re-read against the stack the condition block left",
    ),
    (
        0x0600_000c,
        "two nested merges whose arms each consume the address the condition tested, so each arm \
         is re-read against the stack the condition block left",
    ),
    (
        0x0600_0223,
        "a merge whose taken edge reaches the join directly with the tested value, while the other \
         arm stores one delegate to a local and to the cache field before pushing it",
    ),
];

fn baseline_method_by_token(asm: &DecompiledAssembly, token: u32) -> &StructuredMethod {
    asm.methods
        .iter()
        .find(|m: &&StructuredMethod| m.token == token)
        .unwrap_or_else(|| panic!("clean baseline carries method 0x{token:08x}"))
}

#[test]
fn clean_baseline_merge_bodies_recover_their_conditional_value() {
    let asm: DecompiledAssembly = baseline();
    for (token, cause) in BASELINE_MERGE_RECOVERED {
        let method: &StructuredMethod = baseline_method_by_token(&asm, token);
        assert!(
            !method.body.contains(STACK_UNDERFLOW),
            "0x{token:08x} is {cause}; the value is carried across the join, so the body must \
             recover with no placeholder:\n{}",
            method.body
        );
        assert!(
            method.body.contains(" ? "),
            "0x{token:08x} is {cause}; the merged value must read as a conditional \
             expression:\n{}",
            method.body
        );
    }
}

#[test]
fn no_clean_baseline_body_abstains_on_the_operand_stack() {
    let asm: DecompiledAssembly = baseline();
    let golden: Vec<RecoveredBody> = read_underflow_golden();
    let abstaining: Vec<&StructuredMethod> = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains(STACK_UNDERFLOW))
        .collect();
    assert!(
        abstaining.is_empty(),
        "the clean baseline carries no protector, so every one of its bodies has to reconstruct \
         from a stack model that agrees with the real one; {} still abstain, first:\n{}",
        abstaining.len(),
        abstaining
            .first()
            .map_or_else(String::new, |m: &&StructuredMethod| m.body.clone())
    );
    assert!(
        !golden
            .iter()
            .any(|b: &RecoveredBody| b.image == "megafile/EdgeCases.baseline.dll"),
        "{} still lists clean baseline bodies even though none abstains",
        golden_path(STACK_UNDERFLOW_GOLDEN_REL).display()
    );
}

const POSITIONAL_PARAMETER_RULE: &str = "a signature position keeps a positional argN name when, \
     and only when, the Param table carries no usable name for it: either no Param row exists with \
     that sequence, or the row exists with an empty name, and the body does not store the argument \
     straight into a field whose name can be read instead. Sequence 0 is the return value and is \
     never a parameter, and `this` occupies no Param row, so an instance method is read the same \
     way as a static one.";

const BASELINE_UNNAMED_PARAMS: [(u32, &str); 1] = [(
    0x0600_0010,
    "System.Runtime.CompilerServices.NullableAttribute::.ctor(byte), compiler-embedded, whose \
     single parameter has no Param row at all. Its three sibling embedded attribute constructors \
     0x06000011, 0x06000012 and 0x06000013 also carry no Param row, and they do recover a name \
     because each stores its argument straight into a field; this one wraps the argument in an \
     array first, so no field store names it",
)];

fn is_positional_parameter_name(name: &str) -> bool {
    name.strip_prefix("arg").is_some_and(|digits: &str| {
        !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
    })
}

fn signature_header(signature: &str) -> Option<&str> {
    signature.lines().next_back()
}

fn parameter_declarations(signature: &str) -> Vec<(usize, &str)> {
    let Some(header): Option<&str> = signature_header(signature) else {
        return Vec::new();
    };
    let (Some(open), Some(close)): (Option<usize>, Option<usize>) =
        (header.find('('), header.rfind(')'))
    else {
        return Vec::new();
    };
    if close <= open + 1 {
        return Vec::new();
    }
    let Some(declarations): Option<Vec<&str>> =
        split_csharp_parameter_declarations(&header[open + 1..close])
    else {
        return Vec::new();
    };
    declarations
        .into_iter()
        .enumerate()
        .map(|(index, raw): (usize, &str)| (index, raw.trim()))
        .collect()
}

fn declared_parameter_name(declaration: &str) -> Option<&str> {
    declaration
        .rsplit_once(' ')
        .map(|(_, name): (&str, &str)| name)
}

fn positional_parameters(signature: &str) -> Vec<(usize, String)> {
    parameter_declarations(signature)
        .into_iter()
        .filter_map(|(index, declaration): (usize, &str)| {
            let name: &str = declared_parameter_name(declaration)?;
            is_positional_parameter_name(name).then(|| (index, name.to_owned()))
        })
        .collect()
}

fn baseline_model() -> AssemblyModel {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    let pe: PeImage = parse(&bytes).expect("parse the clean baseline as a PE image");
    let clr: ClrHeader =
        parse_clr_header(&bytes, &pe).expect("clean baseline carries a CLR header");
    let root: MetadataRoot =
        parse_metadata_root(&bytes, &pe, &clr).expect("clean baseline carries a metadata root");
    Resolver::build(&bytes, &pe, &clr, &root)
        .expect("build a resolver over the clean baseline")
        .model()
}

fn metadata_parameter_name(model: &AssemblyModel, token: u32, position: usize) -> Option<String> {
    let sequence: u16 = u16::try_from(position.saturating_add(1)).ok()?;
    model
        .types
        .iter()
        .flat_map(|t: &TypeModel| t.methods.iter())
        .find(|m: &&MethodModel| m.token == token)?
        .parameters
        .iter()
        .find(|p: &&ParamModel| p.sequence == sequence)
        .map(|p: &ParamModel| p.name.clone())
        .filter(|name: &String| !name.is_empty())
}

#[test]
fn typed_local_rate_is_total_on_clean_baseline() {
    let asm: DecompiledAssembly = baseline();
    let model: AssemblyModel = baseline_model();
    let untyped_methods: usize = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains("var local"))
        .count();
    assert_eq!(
        untyped_methods, 0,
        "no method on the clean baseline may carry an untyped `var` local"
    );

    let positional: Vec<(u32, Vec<(usize, String)>)> = asm
        .methods
        .iter()
        .map(|m: &StructuredMethod| (m.token, positional_parameters(&m.signature)))
        .filter(|(_, params): &(u32, Vec<(usize, String)>)| !params.is_empty())
        .collect();

    let mut name_carrying: Vec<String> = Vec::new();
    for (token, params) in &positional {
        for (position, rendered) in params {
            let Some(recorded): Option<String> = metadata_parameter_name(&model, *token, *position)
            else {
                continue;
            };
            name_carrying.push(format!(
                "  0x{token:08x} parameter {position} renders `{rendered}` while the Param table \
                 names it `{recorded}`"
            ));
        }
    }
    assert!(
        name_carrying.is_empty(),
        "a parameter may only keep a positional `argN` when .NET metadata carries no name for it, \
         and {} keep one anyway. A compiler-generated name such as `<>1__state` is still a name and \
         has to be read through, not discarded:\n{}",
        name_carrying.len(),
        name_carrying.join("\n")
    );

    let observed: BTreeSet<u32> = positional
        .iter()
        .map(|(token, _): &(u32, Vec<(usize, String)>)| *token)
        .collect();
    let recorded: BTreeSet<u32> = BASELINE_UNNAMED_PARAMS
        .iter()
        .map(|(token, _): &(u32, &str)| *token)
        .collect();
    assert_eq!(
        observed,
        recorded,
        "the clean baseline methods that keep a positional parameter are recorded one by one with \
         the reason no name exists, so the set is pinned rather than counted. The rule is: \
         {POSITIONAL_PARAMETER_RULE}\nRecorded:\n{}",
        BASELINE_UNNAMED_PARAMS
            .iter()
            .map(|(token, reason): &(u32, &str)| format!("  0x{token:08x} is {reason}"))
            .collect::<Vec<String>>()
            .join("\n")
    );
}

fn declares_compiler_generated_member(signature: &str) -> bool {
    signature
        .lines()
        .take(2)
        .any(|line: &str| is_mangled_metadata_identifier(line))
}

fn live_statement_lines(body: &str) -> impl Iterator<Item = (usize, &str)> {
    body.lines()
        .enumerate()
        .skip_while(|(_, line): &(usize, &str)| line.trim() != "{")
        .filter(|(_, line): &(usize, &str)| !line.trim_start().starts_with("//"))
}

#[test]
fn no_recovered_body_emits_a_mangled_metadata_identifier_as_live_code() {
    let asm: DecompiledAssembly = baseline();
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned: usize = 0;
    for m in &asm.methods {
        if declares_compiler_generated_member(&m.signature) {
            continue;
        }
        scanned += 1;
        for (index, line) in live_statement_lines(&m.body) {
            let Some(token): Option<&str> = line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '<' || c == '>'))
                .find(|t: &&str| is_mangled_metadata_identifier(t))
            else {
                continue;
            };
            offenders.push(format!(
                "  0x{:08x} line {} emits `{token}`, which no C# compiler can parse as an \
                 identifier:\n    {}",
                m.token,
                index + 1,
                line.trim()
            ));
        }
    }
    assert!(
        scanned > 100,
        "this has to scan a real body of user methods to prove anything; saw {scanned}"
    );
    assert!(
        offenders.is_empty(),
        "a name the compiler mangled is not a legal C# identifier, so a body that still refers to \
         one has not been lowered and must state a refusal instead of emitting text no compiler \
         accepts; {} of {scanned} user methods do not:\n{}",
        offenders.len(),
        offenders
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<String>>()
            .join("\n")
    );
}

#[test]
fn a_mangled_identifier_is_told_apart_from_a_generic_type() {
    for mangled in [
        "<>c__DisplayClass1_0",
        "<CrossJoin>b__0",
        "<Length>k__BackingField",
        "<>1__state",
        "<>t__builder",
        "<>9__0",
        "<EvenSquares>d__0",
    ] {
        assert!(
            is_mangled_metadata_identifier(mangled),
            "{mangled} is a mangled metadata name"
        );
    }
    for legal in [
        "List<int>",
        "System.Collections.Generic.IEnumerable<int>",
        "Dictionary<string,double>",
        "values",
        "local0",
        "Func<int,bool>",
        "a<b",
        "x>y",
        "",
    ] {
        assert!(
            !is_mangled_metadata_identifier(legal),
            "{legal} is legal C# and must not be flagged"
        );
    }
}

const PARAMETER_NAME_BASELINES: [&str; 3] = [
    "megafile/EdgeCases.baseline.dll",
    "megafile/EdgeCases.obfuscar.dll",
    "megafile/EdgeCases.confuserex2.dll",
];

fn corpus_model_and_assembly(rel: &str) -> (AssemblyModel, DecompiledAssembly) {
    let mut path: PathBuf = PathBuf::from(CORPUS_ROOT_REL);
    path.push(rel);
    let bytes: Vec<u8> = load(&path.to_string_lossy());
    let pe: PeImage = parse(&bytes).unwrap_or_else(|e| panic!("parse {rel} as a PE image: {e}"));
    let clr: ClrHeader =
        parse_clr_header(&bytes, &pe).unwrap_or_else(|e| panic!("{rel} carries a CLR header: {e}"));
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr)
        .unwrap_or_else(|e| panic!("{rel} carries a metadata root: {e}"));
    let model: AssemblyModel = Resolver::build(&bytes, &pe, &clr, &root)
        .unwrap_or_else(|e| panic!("build a resolver over {rel}: {e}"))
        .model();
    let asm: DecompiledAssembly =
        decompile_assembly(&bytes).unwrap_or_else(|e| panic!("decompile {rel}: {e}"));
    (model, asm)
}

#[test]
fn every_recovered_parameter_position_binds_an_identifier() {
    let mut offenders: Vec<String> = Vec::new();
    for rel in PARAMETER_NAME_BASELINES {
        let (_, asm): (AssemblyModel, DecompiledAssembly) = corpus_model_and_assembly(rel);
        for m in &asm.methods {
            for (index, declaration) in parameter_declarations(&m.signature) {
                if declared_parameter_name(declaration).is_some() {
                    continue;
                }
                offenders.push(format!(
                    "  {rel} 0x{:08x} position {index} renders `{declaration}` with no identifier, \
                     so the emitted signature declares a parameter the body cannot refer to",
                    m.token
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a parameter whose Param row exists with an empty name is still a parameter and has to \
         keep a positional name rather than render as a bare type; {} do not:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

#[test]
fn a_parameter_name_metadata_carries_is_never_replaced_by_a_positional_one() {
    let mut lost: Vec<String> = Vec::new();
    for rel in PARAMETER_NAME_BASELINES {
        let (model, asm): (AssemblyModel, DecompiledAssembly) = corpus_model_and_assembly(rel);
        for m in &asm.methods {
            let Some(meta): Option<&MethodModel> = model
                .types
                .iter()
                .flat_map(|t: &TypeModel| t.methods.iter())
                .find(|candidate: &&MethodModel| candidate.token == m.token)
            else {
                continue;
            };
            for (index, declaration) in parameter_declarations(&m.signature) {
                let Some(rendered): Option<&str> = declared_parameter_name(declaration) else {
                    continue;
                };
                if !is_positional_parameter_name(rendered) {
                    continue;
                }
                let Some(recorded): Option<&ParamModel> = meta
                    .parameters
                    .iter()
                    .find(|p: &&ParamModel| usize::from(p.sequence) == index.saturating_add(1))
                else {
                    continue;
                };
                if recorded.name.is_empty() {
                    continue;
                }
                lost.push(format!(
                    "  {rel} 0x{:08x} position {index} renders `{rendered}` while its Param row \
                     names it `{}`",
                    m.token, recorded.name
                ));
            }
        }
    }
    assert!(
        lost.is_empty(),
        "{POSITIONAL_PARAMETER_RULE} {} positions break it:\n{}",
        lost.len(),
        lost.join("\n")
    );
}

#[test]
fn the_return_value_param_row_is_never_read_as_a_parameter() {
    let (model, asm): (AssemblyModel, DecompiledAssembly) =
        corpus_model_and_assembly("megafile/EdgeCases.baseline.dll");
    let mut sequence_zero_rows: usize = 0;
    let mut checked: usize = 0;
    let mut wrong: Vec<String> = Vec::new();
    for m in &asm.methods {
        let Some(meta): Option<&MethodModel> = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.methods.iter())
            .find(|candidate: &&MethodModel| candidate.token == m.token)
        else {
            continue;
        };
        let Some(zero): Option<&ParamModel> = meta
            .parameters
            .iter()
            .find(|p: &&ParamModel| p.sequence == 0)
        else {
            continue;
        };
        sequence_zero_rows += 1;
        if zero.name.is_empty() {
            continue;
        }
        checked += 1;
        for (index, declaration) in parameter_declarations(&m.signature) {
            if declared_parameter_name(declaration) == Some(zero.name.as_str()) {
                wrong.push(format!(
                    "  0x{:08x} position {index} took the sequence 0 return-value name `{}`",
                    m.token, zero.name
                ));
            }
        }
    }
    assert!(
        sequence_zero_rows > 0,
        "the clean baseline has to carry sequence 0 Param rows for this to prove anything"
    );
    assert!(
        wrong.is_empty(),
        "sequence 0 names the return value, never a parameter, so a method that carries one must \
         still read its first parameter from sequence 1; {} did not ({sequence_zero_rows} rows \
         seen, {checked} of them named):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn an_instance_method_reads_its_first_parameter_from_sequence_one() {
    let (model, asm): (AssemblyModel, DecompiledAssembly) =
        corpus_model_and_assembly("megafile/EdgeCases.baseline.dll");
    let mut instance_checked: usize = 0;
    let mut static_checked: usize = 0;
    let mut wrong: Vec<String> = Vec::new();
    for m in &asm.methods {
        let Some(meta): Option<&MethodModel> = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.methods.iter())
            .find(|candidate: &&MethodModel| candidate.token == m.token)
        else {
            continue;
        };
        let Some(first): Option<&ParamModel> = meta
            .parameters
            .iter()
            .find(|p: &&ParamModel| p.sequence == 1)
        else {
            continue;
        };
        if first.name.is_empty() || !first.name.bytes().all(|b: u8| b.is_ascii_alphanumeric()) {
            continue;
        }
        if meta.is_static() {
            static_checked += 1;
        } else {
            instance_checked += 1;
        }
        let Some((_, declaration)): Option<(usize, &str)> =
            parameter_declarations(&m.signature).into_iter().next()
        else {
            continue;
        };
        let rendered: Option<&str> = declared_parameter_name(declaration);
        if rendered != Some(first.name.as_str()) {
            wrong.push(format!(
                "  0x{:08x} static={} renders `{declaration}` first while sequence 1 names `{}`",
                m.token,
                meta.is_static(),
                first.name
            ));
        }
    }
    assert!(
        instance_checked > 0 && static_checked > 0,
        "both an instance and a static method must be covered for the off-by-one to be provable; \
         saw {instance_checked} instance and {static_checked} static"
    );
    assert!(
        wrong.is_empty(),
        "`this` occupies no Param row, so sequence 1 is the first declared parameter on an \
         instance method exactly as it is on a static one; {} disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
