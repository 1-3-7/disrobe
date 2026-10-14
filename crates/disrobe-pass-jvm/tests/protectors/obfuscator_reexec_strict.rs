#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_jvm::{
    ProguardMapping, RecoveredUnit, SourceRecovery, SourceRecoveryOptions, extract_jar,
    parse_proguard_mapping, parse_yguard_renamelog, recover_sources,
};
use disrobe_testkit::{CommandSpec, ToolError, ToolOutput, tool_output};
use sha2::{Digest, Sha256};

use crate::common;

const TOOL_TIMEOUT: Duration = Duration::from_mins(1);
const TOOL_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const MAIN_SIGNATURE: &str = "static void main(";
const MUTATION: &str = "\nSystem.out.println(\"seeded mutation\");\n";

enum Reference {
    CleanJar {
        jar: &'static str,
        record: &'static str,
    },
    Sources(&'static [&'static str]),
    SourceAs {
        source: &'static str,
        file_name: &'static str,
    },
}

enum Names {
    None,
    Proguard(&'static str),
    YguardLog(&'static str),
}

struct Fixture {
    name: &'static str,
    obfuscated: &'static [&'static str],
    reference: Reference,
    main: &'static str,
    names: Names,
}

const JBCO_SAMPLE: &[&str] = &["obfuscators/jbco/gauntlet/Sample.java"];
const YGUARD_CALCULATOR: &[&str] = &["obfuscators/yguard/gauntlet/Calculator.java"];
const SWITCH_DISPATCH: &[&str] = &["evalshapes/SwitchDispatch.java"];
const SKID_RECORD: &str = "obfuscators/skidfuscator/real/build-record.json";
const YGUARD_RECORD: &str = "obfuscators/yguard/real/build-record.json";
const PROGUARD_RECORD: &str = "proguard/real/build-record.json";

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "jbco/real/Sample.names.jar",
        obfuscated: &["obfuscators/jbco/real/Sample.names.jar"],
        reference: Reference::Sources(JBCO_SAMPLE),
        main: "com.example.app.Sample",
        names: Names::None,
    },
    Fixture {
        name: "jbco/real/Sample.flow.jar",
        obfuscated: &["obfuscators/jbco/real/Sample.flow.jar"],
        reference: Reference::Sources(JBCO_SAMPLE),
        main: "com.example.app.Sample",
        names: Names::None,
    },
    Fixture {
        name: "jbco/real/Calculator.names.jar",
        obfuscated: &["obfuscators/jbco/real/Calculator.names.jar"],
        reference: Reference::Sources(YGUARD_CALCULATOR),
        main: "com.example.app.Calculator",
        names: Names::None,
    },
    Fixture {
        name: "jbco/real/SwitchDispatch.names.jar",
        obfuscated: &["obfuscators/jbco/real/SwitchDispatch.names.jar"],
        reference: Reference::Sources(SWITCH_DISPATCH),
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::None,
    },
    Fixture {
        name: "jbco/real/SwitchDispatch.flow.jar",
        obfuscated: &["obfuscators/jbco/real/SwitchDispatch.flow.jar"],
        reference: Reference::Sources(SWITCH_DISPATCH),
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::None,
    },
    Fixture {
        name: "yguard/Calculator-obf.jar",
        obfuscated: &["obfuscators/yguard/Calculator-obf.jar"],
        reference: Reference::Sources(YGUARD_CALCULATOR),
        main: "com.example.app.Calculator",
        names: Names::YguardLog("obfuscators/yguard/renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/Sample.rename.jar",
        obfuscated: &["obfuscators/yguard/real/Sample.rename.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/Sample.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::YguardLog("obfuscators/yguard/real/Sample.rename.renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/Sample.linenumbers.jar",
        obfuscated: &["obfuscators/yguard/real/Sample.linenumbers.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/Sample.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::YguardLog("obfuscators/yguard/real/Sample.linenumbers.renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/Calculator.rename.jar",
        obfuscated: &["obfuscators/yguard/real/Calculator.rename.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/Calculator.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::YguardLog("obfuscators/yguard/real/Calculator.rename.renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/Calculator.linenumbers.jar",
        obfuscated: &["obfuscators/yguard/real/Calculator.linenumbers.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/Calculator.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::YguardLog("obfuscators/yguard/real/Calculator.linenumbers.renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/SwitchDispatch.rename.jar",
        obfuscated: &["obfuscators/yguard/real/SwitchDispatch.rename.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/SwitchDispatch.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::YguardLog("obfuscators/yguard/real/SwitchDispatch.rename.renamelog.xml"),
    },
    Fixture {
        name: "yguard/real/SwitchDispatch.linenumbers.jar",
        obfuscated: &["obfuscators/yguard/real/SwitchDispatch.linenumbers.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/yguard/real/SwitchDispatch.clean.jar",
            record: YGUARD_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::YguardLog("obfuscators/yguard/real/SwitchDispatch.linenumbers.renamelog.xml"),
    },
    Fixture {
        name: "skidfuscator/Sample-skid.jar",
        obfuscated: &["obfuscators/skidfuscator/Sample-skid.jar"],
        reference: Reference::SourceAs {
            source: "obfuscators/skidfuscator/Sample-src.java",
            file_name: "Sample.java",
        },
        main: "Sample",
        names: Names::None,
    },
    Fixture {
        name: "skidfuscator/real/Sample.skidfuscator.jar",
        obfuscated: &["obfuscators/skidfuscator/real/Sample.skidfuscator.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/skidfuscator/real/Sample.clean.jar",
            record: SKID_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::None,
    },
    Fixture {
        name: "skidfuscator/real/Calculator.skidfuscator.jar",
        obfuscated: &["obfuscators/skidfuscator/real/Calculator.skidfuscator.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/skidfuscator/real/Calculator.clean.jar",
            record: SKID_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::None,
    },
    Fixture {
        name: "skidfuscator/real/SwitchDispatch.skidfuscator.jar",
        obfuscated: &["obfuscators/skidfuscator/real/SwitchDispatch.skidfuscator.jar"],
        reference: Reference::CleanJar {
            jar: "obfuscators/skidfuscator/real/SwitchDispatch.clean.jar",
            record: SKID_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::None,
    },
    Fixture {
        name: "proguard/real/Sample.rename.jar",
        obfuscated: &["proguard/real/Sample.rename.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Sample.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::Proguard("proguard/real/Sample.rename.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/Sample.optimize.jar",
        obfuscated: &["proguard/real/Sample.optimize.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Sample.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::Proguard("proguard/real/Sample.optimize.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/Sample.aggressive.jar",
        obfuscated: &["proguard/real/Sample.aggressive.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Sample.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Sample",
        names: Names::Proguard("proguard/real/Sample.aggressive.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/Calculator.rename.jar",
        obfuscated: &["proguard/real/Calculator.rename.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Calculator.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::Proguard("proguard/real/Calculator.rename.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/Calculator.optimize.jar",
        obfuscated: &["proguard/real/Calculator.optimize.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Calculator.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::Proguard("proguard/real/Calculator.optimize.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/Calculator.aggressive.jar",
        obfuscated: &["proguard/real/Calculator.aggressive.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/Calculator.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.example.app.Calculator",
        names: Names::Proguard("proguard/real/Calculator.aggressive.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/SwitchDispatch.rename.jar",
        obfuscated: &["proguard/real/SwitchDispatch.rename.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/SwitchDispatch.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::Proguard("proguard/real/SwitchDispatch.rename.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/SwitchDispatch.optimize.jar",
        obfuscated: &["proguard/real/SwitchDispatch.optimize.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/SwitchDispatch.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::Proguard("proguard/real/SwitchDispatch.optimize.mapping.txt"),
    },
    Fixture {
        name: "proguard/real/SwitchDispatch.aggressive.jar",
        obfuscated: &["proguard/real/SwitchDispatch.aggressive.jar"],
        reference: Reference::CleanJar {
            jar: "proguard/real/SwitchDispatch.clean.jar",
            record: PROGUARD_RECORD,
        },
        main: "com.disrobe.bench.SwitchDispatch",
        names: Names::Proguard("proguard/real/SwitchDispatch.aggressive.mapping.txt"),
    },
    Fixture {
        name: "proguard/Hello-obf.jar",
        obfuscated: &["proguard/Hello-obf.jar"],
        reference: Reference::Sources(&["proguard/Hello.java"]),
        main: "Hello",
        names: Names::Proguard("proguard/mapping.txt"),
    },
    Fixture {
        name: "proguard/EdgeCases-pg.jar",
        obfuscated: &["proguard/EdgeCases-pg.jar"],
        reference: Reference::Sources(&["megafile/EdgeCases.java"]),
        main: "EdgeCases",
        names: Names::Proguard("proguard/EdgeCases-mapping.txt"),
    },
    Fixture {
        name: "r8/Hello-r8.jar",
        obfuscated: &["r8/Hello-r8.jar"],
        reference: Reference::Sources(&["proguard/Hello.java"]),
        main: "Hello",
        names: Names::Proguard("r8/mapping.txt"),
    },
    Fixture {
        name: "r8/EdgeCases-r8.jar",
        obfuscated: &["r8/EdgeCases-r8.jar"],
        reference: Reference::Sources(&["megafile/EdgeCases.java"]),
        main: "EdgeCases",
        names: Names::Proguard("r8/EdgeCases-mapping.txt"),
    },
    Fixture {
        name: "allatori/AllatoriStrings+AllatoriCaller",
        obfuscated: &[
            "allatori/AllatoriStrings.class",
            "allatori/AllatoriCaller.class",
        ],
        reference: Reference::Sources(&["allatori/Secret.java", "allatori/Caller.java"]),
        main: "com.disrobe.sample.Secret",
        names: Names::None,
    },
    Fixture {
        name: "stringer/StringerClassic.class",
        obfuscated: &["stringer/StringerClassic.class"],
        reference: Reference::Sources(&["stringer/StringerClassic.java"]),
        main: "com.disrobe.bench.StringerClassic",
        names: Names::None,
    },
];

const FULLY_RECOVERED: &[&str] = &[
    "jbco/real/Sample.names.jar",
    "jbco/real/Sample.flow.jar",
    "jbco/real/Calculator.names.jar",
    "jbco/real/SwitchDispatch.names.jar",
    "jbco/real/SwitchDispatch.flow.jar",
    "yguard/Calculator-obf.jar",
    "yguard/real/Sample.rename.jar",
    "yguard/real/Sample.linenumbers.jar",
    "yguard/real/Calculator.rename.jar",
    "yguard/real/Calculator.linenumbers.jar",
    "yguard/real/SwitchDispatch.rename.jar",
    "yguard/real/SwitchDispatch.linenumbers.jar",
    "skidfuscator/Sample-skid.jar",
    "skidfuscator/real/Sample.skidfuscator.jar",
    "skidfuscator/real/Calculator.skidfuscator.jar",
    "skidfuscator/real/SwitchDispatch.skidfuscator.jar",
    "proguard/real/Sample.rename.jar",
    "proguard/real/Sample.optimize.jar",
    "proguard/real/Sample.aggressive.jar",
    "proguard/real/Calculator.rename.jar",
    "proguard/real/Calculator.optimize.jar",
    "proguard/real/Calculator.aggressive.jar",
    "proguard/real/SwitchDispatch.rename.jar",
    "proguard/real/SwitchDispatch.optimize.jar",
    "proguard/real/SwitchDispatch.aggressive.jar",
    "proguard/Hello-obf.jar",
    "r8/Hello-r8.jar",
    "stringer/StringerClassic.class",
];

struct Residual {
    fixture: &'static str,
    observed: &'static str,
    cause: &'static str,
}

const NAMED_RESIDUALS: &[Residual] = &[
    Residual {
        fixture: "proguard/EdgeCases-pg.jar",
        observed: "decompiler fell back on 17 method(s) of EdgeCases",
        cause: "the four records keep toString, hashCode and equals as ObjectMethods call sites, \
                four pattern switches keep their typeSwitch call sites, and three regions stay \
                unstructured; the ProGuard build also throws at run time because its optimizer \
                pruned the Direction constant array",
    },
    Residual {
        fixture: "r8/EdgeCases-r8.jar",
        observed: "decompiler fell back on 10 method(s) of EdgeCases",
        cause: "six try-with-resources and finally handlers that R8 reshaped into shared handler \
                code form no foldable chain, and four pattern switches keep their typeSwitch \
                call sites",
    },
    Residual {
        fixture: "allatori/AllatoriStrings+AllatoriCaller",
        observed: "decompiler fell back on 1 method(s) of com/disrobe/sample/Caller",
        cause: "the caller-keyed decryptor shuffles its stack with swap and dup_x2, which the \
                lifter does not render, and Caller still decrypts through Secret's routine",
    },
];

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("jvm");
    for part in parts {
        for segment in part.split('/') {
            path.push(segment);
        }
    }
    path
}

fn read_corpus(rel: &str) -> Vec<u8> {
    std::fs::read(corpus(&[rel])).unwrap_or_else(|error| panic!("read corpus/jvm/{rel}: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn run_tool(command: CommandSpec, label: &str) -> ToolOutput {
    let output: ToolOutput = tool_output(command)
        .unwrap_or_else(|error: ToolError| panic!("{label} could not start: {error}"));
    assert!(!output.timed_out, "{label} timed out");
    output
}

fn run_java(java: &Path, classpath: &Path, main: &str) -> ToolOutput {
    run_tool(
        CommandSpec::new(java, TOOL_TIMEOUT)
            .arg("-cp")
            .arg(classpath)
            .arg(main)
            .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES),
        &format!("run {main} from {}", classpath.display()),
    )
}

fn compile_sources(javac: &Path, output: &Path, sources: &[PathBuf]) -> Result<(), String> {
    std::fs::create_dir_all(output).expect("create javac output directory");
    let mut command: CommandSpec = CommandSpec::new(javac, TOOL_TIMEOUT)
        .arg("-nowarn")
        .arg("-proc:none")
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(output)
        .capture_limits(TOOL_CAPTURE_BYTES, TOOL_CAPTURE_BYTES);
    for source in sources {
        command = command.arg(source);
    }
    let output: ToolOutput = run_tool(command, "javac");
    if output.success {
        Ok(())
    } else {
        Err(format!("{}{}", output.stdout_text(), output.stderr_text()))
    }
}

fn verified_clean_jar(jar: &str, record: &str) -> PathBuf {
    let record_text: String =
        std::fs::read_to_string(corpus(&[record])).expect("read build record");
    let record_json: serde_json::Value =
        serde_json::from_str(&record_text).expect("parse build record");
    let file_name: &str = jar.rsplit('/').next().expect("jar file name");
    let expected: &str = record_json["files"][format!("files/{file_name}")]
        .as_str()
        .unwrap_or_else(|| panic!("{record} has no sha256 for {file_name}"));
    let path: PathBuf = corpus(&[jar]);
    let bytes: Vec<u8> = std::fs::read(&path).expect("read clean jar");
    assert_eq!(
        sha256(&bytes),
        expected,
        "{jar} does not match its build record; refusing to execute an unrecorded binary"
    );
    path
}

fn reference_output(fixture: &Fixture, javac: &Path, java: &Path, root: &Path) -> ToolOutput {
    match &fixture.reference {
        Reference::CleanJar { jar, record } => {
            let clean: PathBuf = verified_clean_jar(jar, record);
            run_java(java, &clean, fixture.main)
        }
        Reference::Sources(sources) => {
            let paths: Vec<PathBuf> = sources.iter().map(|rel: &&str| corpus(&[rel])).collect();
            run_authored_reference(fixture, javac, java, root, &paths)
        }
        Reference::SourceAs { source, file_name } => {
            let renamed: PathBuf = root.join("reference-source").join(file_name);
            std::fs::create_dir_all(renamed.parent().expect("reference source parent"))
                .expect("create reference source directory");
            std::fs::copy(corpus(&[source]), &renamed)
                .unwrap_or_else(|error| panic!("copy corpus/jvm/{source}: {error}"));
            run_authored_reference(fixture, javac, java, root, &[renamed])
        }
    }
}

fn run_authored_reference(
    fixture: &Fixture,
    javac: &Path,
    java: &Path,
    root: &Path,
    sources: &[PathBuf],
) -> ToolOutput {
    let classes: PathBuf = root.join("reference");
    compile_sources(javac, &classes, sources).unwrap_or_else(|error| {
        panic!(
            "authored reference for {} did not compile: {error}",
            fixture.name
        )
    });
    run_java(java, &classes, fixture.main)
}

fn obfuscated_class_files(fixture: &Fixture) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for rel in fixture.obfuscated {
        let bytes: Vec<u8> = read_corpus(rel);
        if Path::new(rel)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("jar"))
        {
            let extracted = extract_jar(&bytes)
                .unwrap_or_else(|error| panic!("extract corpus/jvm/{rel}: {error}"));
            out.extend(extracted.classes.into_values());
        } else {
            out.push(bytes);
        }
    }
    out
}

fn name_mapping(fixture: &Fixture) -> Option<ProguardMapping> {
    match &fixture.names {
        Names::None => None,
        Names::Proguard(rel) => {
            let text: String = String::from_utf8(read_corpus(rel)).expect("utf-8 mapping");
            Some(parse_proguard_mapping(&text).expect("parse ProGuard mapping"))
        }
        Names::YguardLog(rel) => {
            let text: String = String::from_utf8(read_corpus(rel)).expect("utf-8 renamelog");
            Some(parse_yguard_renamelog(&text).expect("parse yGuard renamelog"))
        }
    }
}

fn recover(fixture: &Fixture) -> Result<SourceRecovery, String> {
    let classes: Vec<Vec<u8>> = obfuscated_class_files(fixture);
    let mapping: Option<ProguardMapping> = name_mapping(fixture);
    let options: SourceRecoveryOptions<'_> = SourceRecoveryOptions {
        mapping: mapping.as_ref(),
    };
    recover_sources(&classes, options).map_err(|error| format!("recovery refused: {error}"))
}

fn write_units(root: &Path, units: &[RecoveredUnit]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for unit in units {
        let path: PathBuf = root.join(&unit.relative_path);
        std::fs::create_dir_all(path.parent().expect("unit parent")).expect("create unit dir");
        std::fs::write(&path, &unit.source)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        paths.push(path);
    }
    paths
}

fn compile_and_compare(
    fixture: &Fixture,
    javac: &Path,
    java: &Path,
    root: &Path,
    reference: &ToolOutput,
    units: &[RecoveredUnit],
    label: &str,
) -> Option<String> {
    let source_root: PathBuf = root.join(format!("{label}-source"));
    let class_root: PathBuf = root.join(format!("{label}-classes"));
    let paths: Vec<PathBuf> = write_units(&source_root, units);
    if let Err(error) = compile_sources(javac, &class_root, &paths) {
        return Some(format!("recovered source did not compile: {error}"));
    }
    let recovered: ToolOutput = run_java(java, &class_root, fixture.main);
    if recovered.exit_code != reference.exit_code {
        return Some(format!(
            "recovered program exited {:?} where the reference exited {:?}: {}",
            recovered.exit_code,
            reference.exit_code,
            recovered.stderr_text()
        ));
    }
    if recovered.stdout != reference.stdout {
        return Some(format!(
            "recovered program stdout differs from the reference:\n--- reference\n{}\n--- recovered\n{}",
            reference.stdout_text(),
            recovered.stdout_text()
        ));
    }
    None
}

fn grade(fixture: &Fixture, javac: &Path, java: &Path) -> Option<String> {
    let scratch: ScratchDir = ScratchDir::create("obfuscator_reexec_strict").expect("scratch");
    let root: &Path = scratch.path();
    let reference: ToolOutput = reference_output(fixture, javac, java, root);
    assert!(
        reference.success,
        "reference program for {} failed: {}",
        fixture.name,
        reference.stderr_text()
    );
    let recovery: SourceRecovery = match recover(fixture) {
        Ok(recovery) => recovery,
        Err(reason) => return Some(reason),
    };
    if let Some(unit) = recovery
        .units
        .iter()
        .find(|unit: &&RecoveredUnit| unit.fallback_methods != 0)
    {
        return Some(format!(
            "decompiler fell back on {} method(s) of {}",
            unit.fallback_methods, unit.class_name
        ));
    }
    compile_and_compare(
        fixture,
        javac,
        java,
        root,
        &reference,
        &recovery.units,
        "recovered",
    )
}

fn fixture_named(name: &str) -> &'static Fixture {
    FIXTURES
        .iter()
        .find(|fixture: &&Fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("{name} is not a graded fixture"))
}

#[test]
fn every_fixture_is_pinned_exactly_once() {
    let names: BTreeSet<&str> = FIXTURES
        .iter()
        .map(|fixture: &Fixture| fixture.name)
        .collect();
    assert_eq!(names.len(), FIXTURES.len(), "duplicate fixture name");
    let full: BTreeSet<&str> = FULLY_RECOVERED.iter().copied().collect();
    let residual: BTreeSet<&str> = NAMED_RESIDUALS
        .iter()
        .map(|residual: &Residual| residual.fixture)
        .collect();
    assert_eq!(
        full.len(),
        FULLY_RECOVERED.len(),
        "a fixture is listed twice as fully recovered"
    );
    assert_eq!(
        residual.len(),
        NAMED_RESIDUALS.len(),
        "a fixture is listed twice as a residual"
    );
    assert!(
        full.is_disjoint(&residual),
        "a fixture cannot be both fully recovered and a residual"
    );
    let pinned: BTreeSet<&str> = full.union(&residual).copied().collect();
    assert_eq!(
        pinned, names,
        "every graded fixture must be pinned as fully recovered or as a named residual"
    );
    for residual in NAMED_RESIDUALS {
        assert!(
            !residual.observed.is_empty() && !residual.cause.is_empty(),
            "{} needs a pinned observation and a named cause",
            residual.fixture
        );
    }
}

#[test]
fn recovered_programs_reexecute_like_their_clean_counterparts() {
    let javac: PathBuf = common::grader_jdk_tool("javac");
    let java: PathBuf = common::grader_jdk_tool("java");
    let expected_residuals: BTreeMap<&str, &str> = NAMED_RESIDUALS
        .iter()
        .map(|residual: &Residual| (residual.fixture, residual.observed))
        .collect();
    let mut failures: Vec<String> = Vec::new();
    for fixture in FIXTURES {
        let residual: Option<String> = grade(fixture, &javac, &java);
        match (residual, expected_residuals.get(fixture.name)) {
            (None, None) => eprintln!("{}: full", fixture.name),
            (None, Some(expected)) => failures.push(format!(
                "{}: recovered fully; promote it from the residual list ({expected}) to FULLY_RECOVERED",
                fixture.name
            )),
            (Some(observed), None) => {
                failures.push(format!("{}: pinned as fully recovered but {observed}", fixture.name));
            }
            (Some(observed), Some(expected)) => {
                if observed.contains(expected) {
                    eprintln!("{}: residual: {expected}", fixture.name);
                } else {
                    failures.push(format!(
                        "{}: residual changed; pinned `{expected}`, observed {observed}",
                        fixture.name
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "strict re-execution grade changed:\n{}",
        failures.join("\n\n")
    );
}

#[test]
fn a_mutated_recovery_turns_every_fully_recovered_fixture_red() {
    let javac: PathBuf = common::grader_jdk_tool("javac");
    let java: PathBuf = common::grader_jdk_tool("java");
    assert!(
        !FULLY_RECOVERED.is_empty(),
        "the mutation control needs at least one fully recovered fixture"
    );
    for name in FULLY_RECOVERED {
        let fixture: &Fixture = fixture_named(name);
        let scratch: ScratchDir =
            ScratchDir::create("obfuscator_reexec_mutation").expect("scratch");
        let root: &Path = scratch.path();
        let reference: ToolOutput = reference_output(fixture, &javac, &java, root);
        let recovery: SourceRecovery = recover(fixture).expect("recovery of a pinned fixture");
        let mut mutated: Vec<RecoveredUnit> = recovery.units.clone();
        let target: &mut RecoveredUnit = mutated
            .iter_mut()
            .find(|unit: &&mut RecoveredUnit| unit.source.contains(MAIN_SIGNATURE))
            .expect("a fully recovered program declares its main method");
        let signature: usize = target.source.find(MAIN_SIGNATURE).expect("main signature");
        let body: usize = signature
            + target.source[signature..]
                .find('{')
                .expect("main body opens after its signature")
            + 1;
        target.source.insert_str(body, MUTATION);
        let verdict: Option<String> = compile_and_compare(
            fixture, &javac, &java, root, &reference, &mutated, "mutated",
        );
        assert!(
            verdict.is_some_and(|reason: String| reason.contains("stdout differs")),
            "{name}: the comparison accepted a recovery that prints an extra line"
        );
    }
}

fn declared_field_names(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line: &&str| {
            line.ends_with(';')
                && !line.contains('(')
                && ["private ", "public ", "protected ", "static ", "final "]
                    .iter()
                    .any(|modifier: &&str| line.starts_with(modifier))
        })
        .filter_map(|line: &str| {
            let declaration: &str = line.split('=').next()?.trim_end_matches(';').trim();
            declaration.rsplit(' ').next()
        })
        .collect()
}

#[test]
fn skidfuscator_constructor_aliases_and_numeric_names_render_as_java() {
    let fixture: &Fixture = fixture_named("skidfuscator/real/Calculator.skidfuscator.jar");
    let recovery: SourceRecovery = recover(fixture).expect("recovery");
    let mut fields: usize = 0;
    for unit in &recovery.units {
        assert!(
            !unit.source.contains(".<init>("),
            "{}: a constructor call through a copy of `this` was rendered as a method call",
            unit.class_name
        );
        for name in declared_field_names(&unit.source) {
            fields += 1;
            assert!(
                name.starts_with(|first: char| first.is_ascii_alphabetic()
                    || first == '_'
                    || first == '$'),
                "{}: field `{name}` is not a Java identifier",
                unit.class_name
            );
        }
    }
    assert!(
        fields > 0,
        "the recovered Skidfuscator classes declared no fields"
    );
}
