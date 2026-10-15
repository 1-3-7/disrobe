#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchFile;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_mobile::{
    DecompileReport, DecompiledFunction, HermesModule, HermesStructuring, MetroModule,
    StructureDecline, decompile_hermes_module, decompile_hermes_module_with, parse_hermes_module,
};
use sha2::{Digest, Sha256};

const NODE_BACKSTOP: Duration = Duration::from_mins(2);
const NODE_CAPTURE: usize = 1 << 20;

const RUNNER: &str = "const fs = require('fs'); const vm = require('vm'); \
globalThis.print = function () { console.log(Array.prototype.map.call(arguments, String).join(' ')); }; \
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'), { filename: process.argv[1] });";

struct Program {
    name: &'static str,
    bytecode_sha256: &'static str,
    shapes: &'static str,
}

const PROGRAMS: &[Program] = &[
    Program {
        name: "mixed",
        bytecode_sha256: "050ed74cb5b85ba2e4e7c3e11d289293af7b9eef29cdadaf0d320d7f83bd54c7",
        shapes: "prototype methods, closures, try/catch/finally, generator, async function, \
                 labelled continue, iterator destructuring, computed object keys",
    },
    Program {
        name: "control",
        bytecode_sha256: "9cfbc176a478d3cf218536b3648e217feb5eeffde916bc28b76817f1e784eb7d",
        shapes: "if/else chains, dense and fall-through switches, while/do/for loops, labelled \
                 break and continue, short-circuit and nullish operators",
    },
    Program {
        name: "closures",
        bytecode_sha256: "386c146019dd478a530422c5f8149b1b8aa83aeda676010d2a819686a0d56088",
        shapes: "captured counters, closures created in loops, recursion, arguments, default and \
                 rest parameters, three-level captures, spread calls, strict this",
    },
    Program {
        name: "objects",
        bytecode_sha256: "a66888da92833fe05bcee39af629db3a297a68ab006b452cf2021448809c6436",
        shapes: "accessors, __proto__ literals, holes, spread, object and array destructuring, \
                 for-in with deletion, for-of over arrays, strings and maps, constructors",
    },
    Program {
        name: "exceptions",
        bytecode_sha256: "78e1bd76f657038c32f2f7799555f5394d61db0723f277bd4d4d03fb8ed417b2",
        shapes: "try/catch, try/finally with early return, nested rethrow, continue from a catch, \
                 optional catch binding, runtime ReferenceError and TypeError",
    },
    Program {
        name: "generators",
        bytecode_sha256: "3a8a830b64a2dcc3edbe4a6a1c243c27db0f00723fa642ded34ec270b6ad8573",
        shapes: "yield in loops, sent values, return values, infinite generators under for-of, \
                 generator spread, return() and throw() on a suspended generator",
    },
    Program {
        name: "async",
        bytecode_sha256: "4fa40bccd75ec4f732a0843a92db61b6b4de73d4f33d863da630397b6d18f385",
        shapes: "await chains, await in loops, rejected awaits caught by try, promise chaining",
    },
    Program {
        name: "values",
        bytecode_sha256: "b4aee0f37c77f0f75386b862c136ef0e8e6ac4f21632ee6dc71d6b2f19618b80",
        shapes: "template literals, tagged templates, regexp exec loops, bigint arithmetic, \
                 number edge cases, coercing operators, prefix and postfix updates, compound \
                 and logical assignment",
    },
    Program {
        name: "metro",
        bytecode_sha256: "6d089976be0a985408026ee521d20c02d946f780b99bb35a1c80d6d16b2ef438",
        shapes: "a Metro module registry: __d factories, require, import-default and \
                 import-all through the dependency map, __r entry",
    },
    Program {
        name: "construct",
        bytecode_sha256: "2cbe5426f8d6a5d0aaa04261f88af365dc0d0a082521bd8fa408b2333257497e",
        shapes: "new with a conditional argument, a constructor returning an object, new on a \
                 member chain, new on a computed callee, new with spread arguments",
    },
    Program {
        name: "cleanup",
        bytecode_sha256: "c46530bea821375b09766edaff291034d3e87108c42818dc592c528b85c5d82b",
        shapes: "return() through finally, nested finally, an overriding finally, iterator close \
                 on for-of, a throwing cleanup, branching and looping cleanups, a cleanup that \
                 yields",
    },
    Program {
        name: "names",
        bytecode_sha256: "b8aad3e2bfadbfd44a0801fb3c3ce9e4eabd0b34ee844e7ca9eb60b1479e9c79",
        shapes: "methods named like the globals they call, a named function expression calling \
                 itself, a global function replaced after a reference to it was kept",
    },
    Program {
        name: "rnassets",
        bytecode_sha256: "8db21e4f906ad458b314779291190507a98d6316997e045accf7acceb69fcf86",
        shapes: "Metro asset modules registering React Native packager asset records with an \
                 asset registry module, read back through getAssetByID",
    },
    Program {
        name: "branches",
        bytecode_sha256: "c4d47b1e3b616ce590e339570b555a06504053667016da493a35db3281e6e88a",
        shapes: "short-circuit conditions feeding ternaries, nullish and optional chains, \
                 condition side-effect order, labelled breaks out of nested loops, switch \
                 fall-through with a conditional break, continue and break through finally",
    },
    Program {
        name: "delegation",
        bytecode_sha256: "879a2cbff9e05ce46eae688fc7a9f318e573ce93623da07e533641778a9d3a2a",
        shapes: "yield* forwarding next, throw and return, delegation to arrays, to iterators \
                 without throw, results passed through by identity, a return() that declines to \
                 finish",
    },
];

fn behaviour_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("behaviour")
}

fn read(name: &str) -> Vec<u8> {
    let path: PathBuf = behaviour_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is committed, so a run that cannot read it grades nothing: {error}",
            path.display()
        )
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut acc: String, b: &u8| {
            use std::fmt::Write as _;
            let _: std::fmt::Result = write!(acc, "{b:02x}");
            acc
        })
}

fn node_binary() -> PathBuf {
    let candidate: PathBuf = PathBuf::from("node");
    let probe: Option<CapturedOutput> = run_captured(
        candidate.as_path(),
        &["--version"],
        NODE_BACKSTOP,
        NODE_CAPTURE,
    )
    .unwrap_or_else(|error: std::io::Error| {
        panic!(
            "node is the engine this grader re-executes recovered programs in and it \
                     could not be launched: {error}. Install Node.js; the grader fails rather \
                     than skips because a skipped reference reports green over an unmeasured claim"
        )
    });
    let out: CapturedOutput =
        probe.unwrap_or_else(|| panic!("node --version did not finish inside {NODE_BACKSTOP:?}"));
    assert_eq!(out.exit_code, Some(0), "node --version must succeed");
    candidate
}

fn run_script(source: &str) -> Result<String, String> {
    run_script_within(source, NODE_BACKSTOP)
        .unwrap_or_else(|| panic!("node must finish inside {NODE_BACKSTOP:?}"))
}

fn run_script_within(source: &str, backstop: Duration) -> Option<Result<String, String>> {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_hermes_behaviour", "js").expect("scratch file");
    file.write_all(source.as_bytes()).expect("write program");
    drop(file);
    let path: String = scratch
        .path()
        .to_str()
        .expect("utf-8 scratch path")
        .to_owned();
    let node: PathBuf = node_binary();
    let args: [&str; 3] = ["-e", RUNNER, path.as_str()];
    let captured: CapturedOutput =
        run_captured(node.as_path(), &args, backstop, NODE_CAPTURE).expect("spawn node")?;
    let stdout: String = String::from_utf8_lossy(&captured.stdout).replace("\r\n", "\n");
    Some(if captured.exit_code == Some(0) {
        Ok(stdout)
    } else {
        Err(format!(
            "exit {:?}\n--stdout--\n{stdout}\n--stderr--\n{}",
            captured.exit_code,
            String::from_utf8_lossy(&captured.stderr)
        ))
    })
}

fn assert_structured(label: &str, recovered: &DecompileReport) {
    let unstructured: Vec<String> = recovered
        .functions
        .iter()
        .filter_map(|function: &DecompiledFunction| {
            function
                .structure_decline
                .filter(|reason: &StructureDecline| {
                    *reason != StructureDecline::UnreachableExceptionHandler
                })
                .map(|reason: StructureDecline| format!("{} {reason:?}", function.name))
        })
        .collect();
    assert!(
        unstructured.is_empty(),
        "{label}: every function must come out as structured statements rather than the block \
         dispatcher, except one whose exception edges make its graph irreducible; unstructured: \
         {unstructured:?}"
    );
}

fn reference(program: &Program) -> String {
    String::from_utf8(read(&format!("{}.hermes-stdout.txt", program.name)))
        .expect("the interpreter output is utf-8")
}

fn report(program: &Program) -> DecompileReport {
    let bytes: Vec<u8> = read(&format!("{}.hbc", program.name));
    assert_eq!(
        sha256_hex(&bytes),
        program.bytecode_sha256,
        "{}.hbc must be exactly the bytes build.py produced with hermesc 0.12.0",
        program.name
    );
    let module: HermesModule = parse_hermes_module(&bytes).expect("hermes module parse");
    assert_eq!(module.header.version, 89, "{}", program.name);
    decompile_hermes_module(&module)
}

#[test]
fn the_reference_output_is_what_the_original_source_prints() {
    for program in PROGRAMS {
        let source: String = String::from_utf8(read(&format!("{}.js", program.name)))
            .expect("the authored source is utf-8");
        let printed: String = run_script(&source).unwrap_or_else(|error: String| {
            panic!("{}.js must run under node: {error}", program.name)
        });
        assert_eq!(
            printed,
            reference(program),
            "{}: the committed interpreter output must equal what the authored source prints, \
             or the reference would grade the recovery against another program",
            program.name
        );
        assert!(!printed.is_empty(), "{}", program.name);
    }
}

#[test]
fn every_behaviour_program_reexecutes_to_the_hermes_interpreter_output() {
    let mut matched: usize = 0;
    let mut functions: usize = 0;
    for program in PROGRAMS {
        let recovered: DecompileReport = report(program);
        assert_eq!(
            recovered.total_fallback_ops, 0,
            "{} ({}): every instruction must be recovered; declined {:?}",
            program.name, program.shapes, recovered.declined_opcodes
        );
        assert_structured(program.name, &recovered);
        assert!(
            !recovered.program.contains("$unrecovered"),
            "{}: the recovered program calls the refusal helper",
            program.name
        );
        let got: String = run_script(&recovered.program).unwrap_or_else(|error: String| {
            panic!(
                "{} ({}): the recovered program must run under node: {error}\n--program--\n{}",
                program.name, program.shapes, recovered.program
            )
        });
        assert_eq!(
            got,
            reference(program),
            "{} ({}): the recovered program printed something other than the Hermes interpreter\n\
             --program--\n{}",
            program.name,
            program.shapes,
            recovered.program
        );
        matched += 1;
        functions += recovered.function_count;
        eprintln!(
            "{}: {} functions, {} structured, {} ops recovered, output matched",
            program.name,
            recovered.function_count,
            recovered.structured_functions,
            recovered.total_reconstructed_ops
        );
    }
    assert_eq!(matched, PROGRAMS.len());
    assert_eq!(
        functions, PINNED_FUNCTIONS,
        "the function population is pinned so a program that loses functions fails here"
    );
}

const PINNED_FUNCTIONS: usize = 204;

#[test]
fn the_differential_rejects_a_recovery_with_one_operator_flipped() {
    let mut rejected: usize = 0;
    for program in PROGRAMS {
        let recovered: DecompileReport = report(program);
        let want: String = reference(program);
        let sites: Vec<usize> = recovered
            .program
            .match_indices(" + ")
            .map(|(at, _): (usize, &str)| at)
            .take(MUTATION_SITES)
            .collect();
        let caught: bool = sites.iter().any(|at: &usize| {
            let mut mutated: String = recovered.program.clone();
            mutated.replace_range(*at..*at + 3, " - ");
            run_script_within(&mutated, MUTANT_BACKSTOP).is_none_or(
                |got: Result<String, String>| got.as_deref().ok() != Some(want.as_str()),
            )
        });
        assert!(
            sites.is_empty() || caught,
            "{}: none of the first {} additions changed the output when flipped to a subtraction, \
             so the differential cannot see a wrong operator in this program",
            program.name,
            sites.len()
        );
        rejected += usize::from(caught);
    }
    assert!(
        rejected >= 7,
        "only {rejected} programs carried an addition whose flip the differential caught"
    );
}

const MUTATION_SITES: usize = 12;
const MUTANT_BACKSTOP: Duration = Duration::from_secs(10);

#[test]
fn every_function_body_is_inlined_into_the_program_it_is_graded_through() {
    for program in PROGRAMS {
        let recovered: DecompileReport = report(program);
        assert!(
            !recovered.program.contains("/* fn #"),
            "{}: a closure was left as a placeholder, so its body is not graded by re-execution",
            program.name
        );
        let declared: usize = recovered
            .functions
            .iter()
            .filter(|function: &&DecompiledFunction| function.instruction_count > 0)
            .count();
        assert_eq!(declared, recovered.function_count, "{}", program.name);
    }
}

#[test]
fn the_metro_registry_is_read_back_from_the_global_code() {
    let metro: &Program = PROGRAMS
        .iter()
        .find(|p: &&Program| p.name == "metro")
        .expect("metro program");
    let recovered: DecompileReport = report(metro);
    let table: Vec<(u64, Vec<u64>)> = recovered
        .metro_modules
        .iter()
        .map(|m: &MetroModule| (m.id, m.dependencies.clone()))
        .collect();
    assert_eq!(
        table,
        vec![
            (0, vec![1, 2, 3]),
            (1, Vec::new()),
            (2, vec![1]),
            (3, Vec::new())
        ],
        "the module table must match the four __d calls in metro.js"
    );
    for module in &recovered.metro_modules {
        let factory: &DecompiledFunction = &recovered.functions[module.factory as usize];
        assert!(
            factory.source.contains(
                "(global, require, importDefault, importAll, module, exports, dependencyMap)"
            ),
            "module {} factory keeps the Metro parameter names; src:\n{}",
            module.id,
            factory.source
        );
    }
}

const SAMPLE_VERSIONS: [(u32, &str); 11] = [
    (
        62,
        "e143f78b679da0724fba14bcf61d4e1f6efc2605919cbc24c1dd45046bdbc4a6",
    ),
    (
        71,
        "aeab21e871dcdfc233c58f95bc94ef0904d7d9eaa1db1a3827eda9ab4c0e5418",
    ),
    (
        74,
        "ea77e6e5c0fea4d9a7f1e4499a392627934e96cb25adf5b436431c5fdfb0bf41",
    ),
    (
        76,
        "13dd7a456178bda7df4a8b0f225e3675fd7181c2166bb49ef2f7ae77de7885e3",
    ),
    (
        83,
        "09a9836e44084dc990f7b1b18b3430cf267d1520ae1a0789557caff47a66b5fa",
    ),
    (
        84,
        "50bf2da19b8b6dba13ed159c657d7a0800ae7f73ead133e0d4cbdce72ea40e04",
    ),
    (
        85,
        "c5916c2e01141de879e3d8552f72feb4c23b70e8c3687ec4e67c7b29a45d16b7",
    ),
    (
        89,
        "6f2b39157bc6e88fed19641e5168e9db4c50ce7be0ea70d42fc966c7286e2705",
    ),
    (
        90,
        "2ac49683d02a59cc22e6665be705a0f36d1e7110fd3bfaaaec46b0ae9c3d97b1",
    ),
    (
        94,
        "0a947d2600f617279bc4a0f644169e3ce53107b69c65aa6aaa668660e4eae65a",
    ),
    (
        96,
        "39ee9eccbd99c8597df7847fa17804a3213982629d093c0ffb01abdd485daa4a",
    ),
];

fn sample_dir() -> PathBuf {
    behaviour_dir().join("..").join("sample")
}

#[test]
fn the_sample_reexecutes_like_its_source_at_every_bytecode_version() {
    let source: String = String::from_utf8(
        std::fs::read(sample_dir().join("sample.js")).expect("sample.js is committed"),
    )
    .expect("sample.js is utf-8");
    let want: String = run_script(&source).expect("sample.js runs under node");
    assert!(!want.is_empty());
    for (version, digest) in SAMPLE_VERSIONS {
        let path: PathBuf = sample_dir().join(format!("sample.hbc.v{version}"));
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
        assert_eq!(sha256_hex(&bytes), digest, "v{version}");
        let module: HermesModule = parse_hermes_module(&bytes).expect("hermes module parse");
        assert_eq!(module.header.version, version);
        let recovered: DecompileReport = decompile_hermes_module(&module);
        assert_eq!(
            recovered.total_fallback_ops, 0,
            "v{version}: declined {:?}",
            recovered.declined_opcodes
        );
        let got: String = run_script(&recovered.program).unwrap_or_else(|error: String| {
            panic!(
                "v{version}: the recovered program must run: {error}
{}",
                recovered.program
            )
        });
        assert_eq!(
            got, want,
            "v{version}: the recovered program printed something other than the source
{}",
            recovered.program
        );
        let mutated: String = recovered.program.replacen(" + ", " - ", 1);
        assert_ne!(
            mutated, recovered.program,
            "v{version}: no addition to flip"
        );
        assert_ne!(
            run_script(&mutated).ok().as_deref(),
            Some(want.as_str()),
            "v{version}: flipping the first addition must change the output"
        );
    }
}

const BAND_VERSIONS: [u32; 3] = [85, 90, 94];
const BAND_UNSUPPORTED: [(u32, &str); 2] = [(85, "objects"), (85, "values")];
const PINNED_BAND_FUNCTIONS: [(u32, usize); 3] = [(85, 193), (90, 204), (94, 204)];

fn bands_dir() -> PathBuf {
    behaviour_dir().join("..").join("bands")
}

#[test]
fn react_native_069_to_072_bytecode_reexecutes_to_the_hermes_interpreter_output() {
    for (version, pinned) in PINNED_BAND_FUNCTIONS {
        assert!(BAND_VERSIONS.contains(&version));
        let mut functions: usize = 0;
        let mut caught: usize = 0;
        let mut graded: usize = 0;
        for program in PROGRAMS {
            if BAND_UNSUPPORTED.contains(&(version, program.name)) {
                continue;
            }
            let path: PathBuf = bands_dir().join(format!("{}.hbc.v{version}", program.name));
            let bytes: Vec<u8> = std::fs::read(&path)
                .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
            let module: HermesModule = parse_hermes_module(&bytes)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(module.header.version, version, "{}", path.display());
            let recovered: DecompileReport = decompile_hermes_module(&module);
            let label: String = format!("{}.v{version}", program.name);
            assert_eq!(
                recovered.total_fallback_ops, 0,
                "{label}: every instruction must be recovered; declined {:?}",
                recovered.declined_opcodes
            );
            assert_structured(&label, &recovered);
            let want: String = reference(program);
            let got: String = run_script(&recovered.program).unwrap_or_else(|error: String| {
                panic!(
                    "{label}: the recovered program must run: {error}\n--program--\n{}",
                    recovered.program
                )
            });
            assert_eq!(
                got, want,
                "{label}: the recovered program printed something other than the Hermes \
                 interpreter printed for the source\n--program--\n{}",
                recovered.program
            );
            functions += recovered.function_count;
            graded += 1;
            let flipped: bool = recovered
                .program
                .match_indices(" + ")
                .map(|(at, _): (usize, &str)| at)
                .take(MUTATION_SITES)
                .any(|at: usize| {
                    let mut mutated: String = recovered.program.clone();
                    mutated.replace_range(at..at + 3, " - ");
                    run_script_within(&mutated, MUTANT_BACKSTOP).is_none_or(
                        |got: Result<String, String>| got.as_deref().ok() != Some(want.as_str()),
                    )
                });
            caught += usize::from(flipped);
        }
        let skipped: usize = BAND_UNSUPPORTED
            .iter()
            .filter(|(at, _): &&(u32, &str)| *at == version)
            .count();
        assert_eq!(graded + skipped, PROGRAMS.len(), "v{version}");
        assert_eq!(
            functions, pinned,
            "v{version}: the function population is pinned"
        );
        assert!(
            caught >= 7,
            "v{version}: only {caught} recovered programs changed output when one addition was \
             flipped, so the comparison cannot see a wrong operator"
        );
    }
}

const MODERN_VERSIONS: [u32; 2] = [98, 99];
const PINNED_MODERN_FUNCTIONS: usize = 237;

fn modern_dir() -> PathBuf {
    behaviour_dir().join("..").join("modern")
}

fn modern_report(name: &str, version: u32) -> DecompileReport {
    let path: PathBuf = modern_dir().join(format!("{name}.hbc.v{version}"));
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
    let module: HermesModule =
        parse_hermes_module(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert_eq!(module.header.version, version, "{}", path.display());
    decompile_hermes_module(&module)
}

#[test]
fn modern_bytecode_reexecutes_to_what_the_source_prints() {
    let sample_source: String = String::from_utf8(
        std::fs::read(sample_dir().join("sample.js")).expect("sample.js is committed"),
    )
    .expect("sample.js is utf-8");
    let sample_output: String = run_script(&sample_source).expect("sample.js runs under node");
    let features_source: String = String::from_utf8(
        std::fs::read(modern_dir().join("features.js")).expect("features.js is committed"),
    )
    .expect("features.js is utf-8");
    let features_output: String =
        run_script(&features_source).expect("features.js runs under node");
    assert!(
        features_output.contains("square#1:9") && features_output.contains("0|3|6|9"),
        "the classes, private fields and closures program prints its expected checkpoints"
    );
    for version in MODERN_VERSIONS {
        let mut functions: usize = 0;
        let mut caught: usize = 0;
        let cases: Vec<(&str, String)> = PROGRAMS
            .iter()
            .map(|program: &Program| (program.name, reference(program)))
            .chain(std::iter::once(("sample", sample_output.clone())))
            .chain(std::iter::once(("features", features_output.clone())))
            .collect();
        for (name, want) in &cases {
            let recovered: DecompileReport = modern_report(name, version);
            assert_eq!(
                recovered.total_fallback_ops, 0,
                "{name}.v{version}: every instruction must be recovered; declined {:?}",
                recovered.declined_opcodes
            );
            assert_structured(&format!("{name}.v{version}"), &recovered);
            let got: String = run_script(&recovered.program).unwrap_or_else(|error: String| {
                panic!(
                    "{name}.v{version}: the recovered program must run: {error}\n--program--\n{}",
                    recovered.program
                )
            });
            assert_eq!(
                &got, want,
                "{name}.v{version}: the recovered program printed something other than the \
                 source\n--program--\n{}",
                recovered.program
            );
            functions += recovered.function_count;
            let flipped: bool = recovered
                .program
                .match_indices(" + ")
                .map(|(at, _): (usize, &str)| at)
                .take(MUTATION_SITES)
                .any(|at: usize| {
                    let mut mutated: String = recovered.program.clone();
                    mutated.replace_range(at..at + 3, " - ");
                    run_script_within(&mutated, MUTANT_BACKSTOP).is_none_or(
                        |got: Result<String, String>| got.as_deref().ok() != Some(want.as_str()),
                    )
                });
            caught += usize::from(flipped);
        }
        assert_eq!(
            functions, PINNED_MODERN_FUNCTIONS,
            "v{version}: the function population is pinned"
        );
        assert!(
            caught >= 8,
            "v{version}: only {caught} recovered programs changed output when one addition was \
             flipped, so the comparison cannot see a wrong operator"
        );
    }
}

fn bytecode_cases() -> Vec<(String, PathBuf, String)> {
    let sample_source: String = String::from_utf8(
        std::fs::read(sample_dir().join("sample.js")).expect("sample.js is committed"),
    )
    .expect("sample.js is utf-8");
    let sample_output: String = run_script(&sample_source).expect("sample.js runs under node");
    let mut cases: Vec<(String, PathBuf, String)> = Vec::new();
    for program in PROGRAMS {
        let want: String = reference(program);
        cases.push((
            format!("{}.v89", program.name),
            behaviour_dir().join(format!("{}.hbc", program.name)),
            want.clone(),
        ));
        for version in MODERN_VERSIONS {
            cases.push((
                format!("{}.v{version}", program.name),
                modern_dir().join(format!("{}.hbc.v{version}", program.name)),
                want.clone(),
            ));
        }
        for version in BAND_VERSIONS {
            if BAND_UNSUPPORTED.contains(&(version, program.name)) {
                continue;
            }
            cases.push((
                format!("{}.v{version}", program.name),
                bands_dir().join(format!("{}.hbc.v{version}", program.name)),
                want.clone(),
            ));
        }
    }
    for (version, _) in SAMPLE_VERSIONS {
        cases.push((
            format!("sample.v{version}"),
            sample_dir().join(format!("sample.hbc.v{version}")),
            sample_output.clone(),
        ));
    }
    cases
}

#[test]
fn every_program_reexecutes_with_every_function_laid_out_as_labelled_blocks() {
    let mut functions: usize = 0;
    let mut graded: usize = 0;
    let mut dropped_breaks_caught: usize = 0;
    let mut dispatched: usize = 0;
    for (label, path, want) in bytecode_cases() {
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()));
        let module: HermesModule =
            parse_hermes_module(&bytes).unwrap_or_else(|error| panic!("{label}: {error}"));
        let recovered: DecompileReport =
            decompile_hermes_module_with(&module, HermesStructuring::LabeledBlocks);
        assert_eq!(
            recovered.total_fallback_ops, 0,
            "{label}: every instruction must be recovered; declined {:?}",
            recovered.declined_opcodes
        );
        assert_structured(&label, &recovered);
        dispatched += recovered
            .functions
            .iter()
            .filter(|function: &&DecompiledFunction| function.structure_decline.is_some())
            .count();
        let got: String = run_script(&recovered.program).unwrap_or_else(|error: String| {
            panic!(
                "{label}: the labelled-block program must run: {error}\n--program--\n{}",
                recovered.program
            )
        });
        assert_eq!(
            got, want,
            "{label}: the labelled-block program printed something other than the reference\n\
             --program--\n{}",
            recovered.program
        );
        functions += recovered.function_count;
        graded += 1;
        if label == "branches.v89" {
            let sites: Vec<(usize, usize)> = recovered
                .program
                .match_indices("break $loop")
                .filter_map(|(at, _): (usize, &str)| {
                    recovered.program[at..]
                        .find(';')
                        .map(|end: usize| (at, at + end + 1))
                })
                .take(MUTATION_SITES)
                .collect();
            for (start, end) in sites {
                let mut mutated: String = recovered.program.clone();
                mutated.replace_range(start..end, ";");
                let changed: bool = run_script_within(&mutated, MUTANT_BACKSTOP).is_none_or(
                    |got: Result<String, String>| got.as_deref().ok() != Some(want.as_str()),
                );
                dropped_breaks_caught += usize::from(changed);
            }
        }
    }
    assert!(
        dropped_breaks_caught >= 6,
        "only {dropped_breaks_caught} of the first {MUTATION_SITES} labelled breaks in the \
         branches program changed its output when removed, so the comparison cannot see a jump \
         that lands in the wrong place"
    );
    assert_eq!(
        (graded, functions, dispatched),
        PINNED_LABELED_BLOCKS,
        "every compiled program at every version is graded"
    );
}

const PINNED_LABELED_BLOCKS: (usize, usize, usize) = (99, 1_295, 18);
