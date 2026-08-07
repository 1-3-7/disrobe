#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use disrobe_core::scratch::ScratchDir;
use disrobe_typerec::dwarf_gt::{self, DebugImage, GroundTruthFunction};
use disrobe_typerec::dwarf_location::{LocationSurvey, UnlocatedReason};
use disrobe_typerec::grade::{self, GradeReport};

#[path = "support/cc_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod cc_toolchain;

use cc_toolchain::CcToolchain;

const GRADED: &str = "the fresh-build DWARF type reference";
const CONTROL_FLOW_ENFORCEMENT: &str = "-fcf-protection=full";
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
const DECLARED_VARIABLES: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leg {
    id: &'static str,
    version: u16,
    dwarf_flag: &'static str,
    protection: &'static str,
}

const LEGS: [Leg; 8] = [
    Leg {
        id: "dwarf2-cet",
        version: 2,
        dwarf_flag: "-gdwarf-2",
        protection: CONTROL_FLOW_ENFORCEMENT,
    },
    Leg {
        id: "dwarf2-plain",
        version: 2,
        dwarf_flag: "-gdwarf-2",
        protection: "-fcf-protection=none",
    },
    Leg {
        id: "dwarf3-cet",
        version: 3,
        dwarf_flag: "-gdwarf-3",
        protection: CONTROL_FLOW_ENFORCEMENT,
    },
    Leg {
        id: "dwarf3-plain",
        version: 3,
        dwarf_flag: "-gdwarf-3",
        protection: "-fcf-protection=none",
    },
    Leg {
        id: "dwarf4-cet",
        version: 4,
        dwarf_flag: "-gdwarf-4",
        protection: CONTROL_FLOW_ENFORCEMENT,
    },
    Leg {
        id: "dwarf4-plain",
        version: 4,
        dwarf_flag: "-gdwarf-4",
        protection: "-fcf-protection=none",
    },
    Leg {
        id: "dwarf5-cet",
        version: 5,
        dwarf_flag: "-gdwarf-5",
        protection: CONTROL_FLOW_ENFORCEMENT,
    },
    Leg {
        id: "dwarf5-plain",
        version: 5,
        dwarf_flag: "-gdwarf-5",
        protection: "-fcf-protection=none",
    },
];

#[derive(Debug, Clone)]
struct Measured {
    survey: LocationSurvey,
    report: GradeReport,
    starts_with_endbr64: bool,
}

fn fixture_source(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    path
}

fn build_and_load(
    toolchain: &CcToolchain,
    work: &std::path::Path,
    source: &OsString,
    id: &str,
    flags: &[&str],
) -> DebugImage {
    let unstripped: String = format!("{id}.unstripped.bin");
    let stripped: String = format!("{id}.stripped.bin");
    if let Err(defect) =
        cc_toolchain::compile(toolchain, work, source, &OsString::from(&unstripped), flags)
    {
        panic!(
            "{GRADED} cannot be measured on the {id} leg because the compiler refused the corpus: \
             {defect}"
        );
    }
    if let Err(defect) = cc_toolchain::strip_debug(
        toolchain,
        work,
        &OsString::from(&unstripped),
        &OsString::from(&stripped),
    ) {
        panic!("{GRADED} cannot be measured on the {id} leg because the strip failed: {defect}");
    }
    let unstripped_bytes: Vec<u8> = std::fs::read(work.join(&unstripped))
        .unwrap_or_else(|error| panic!("read the {id} unstripped build: {error}"));
    let stripped_bytes: Vec<u8> = std::fs::read(work.join(&stripped))
        .unwrap_or_else(|error| panic!("read the {id} stripped build: {error}"));
    let ground_truth: DebugImage = dwarf_gt::load(&unstripped_bytes)
        .unwrap_or_else(|error| panic!("read the DWARF of the {id} build: {error}"));
    let (base, text): (u64, Vec<u8>) = dwarf_gt::load_text(&stripped_bytes)
        .unwrap_or_else(|error| panic!("read the .text of the stripped {id} build: {error}"));
    assert_eq!(
        base, ground_truth.text_base,
        "the {id} strip moved .text, so the reference addresses no longer describe the input",
    );
    assert_eq!(
        text, ground_truth.text,
        "the {id} strip altered .text bytes, so the reference no longer describes the input",
    );
    DebugImage {
        text_base: base,
        text,
        functions: ground_truth.functions,
        locations: ground_truth.locations,
    }
}

fn measure(image: &DebugImage, leg: Leg) -> Measured {
    let survey: LocationSurvey = image.locations.clone();
    assert!(
        survey.balances(),
        "the {} survey lost {} of {} declared variables without naming a reason: {survey}",
        leg.id,
        survey.declared - survey.located - survey.unlocated_total(),
        survey.declared,
    );
    assert_eq!(
        survey.versions,
        BTreeSet::from([leg.version]),
        "the {} leg asked for DWARF {} and the build carries {:?}, so this leg does not cover the \
         version it claims",
        leg.id,
        leg.version,
        survey.versions,
    );
    assert_eq!(
        survey.declared, DECLARED_VARIABLES,
        "types_corpus.c declares {DECLARED_VARIABLES} named parameters and locals, and the {} \
         build carries {}: {survey}",
        leg.id, survey.declared,
    );
    assert_eq!(
        survey.located, DECLARED_VARIABLES,
        "every declared variable of an -O0 build sits at a frame offset, so the {} leg placing \
         only {} of {DECLARED_VARIABLES} means a location form went unread: {survey}",
        leg.id, survey.located,
    );
    assert_eq!(
        survey.unmodelled_total(),
        0,
        "the {} build carries a location form this reader does not model: {survey}",
        leg.id,
    );
    let report: GradeReport = grade::grade_image(image);
    assert!(
        report.total_vars > 0,
        "the {} build produced no gradeable variable, so this case measured nothing: {survey}",
        leg.id,
    );
    let starts_with_endbr64: bool = image
        .functions
        .first()
        .and_then(|function: &GroundTruthFunction| image.function_bytes(function))
        .is_some_and(|bytes: &[u8]| bytes.starts_with(&ENDBR64));
    Measured {
        survey,
        report,
        starts_with_endbr64,
    }
}

#[test]
fn recompiled_corpus_reproduces_measured_floors() {
    let Some(toolchain): Option<CcToolchain> = cc_toolchain::require(GRADED) else {
        return;
    };
    let scratch: ScratchDir = ScratchDir::create("disrobe_typerec")
        .unwrap_or_else(|error| panic!("{GRADED} needs a working directory: {error}"));
    let work: PathBuf = scratch.path().to_path_buf();
    let source: OsString = cc_toolchain::stage_source(&work, &fixture_source("types_corpus.c"))
        .unwrap_or_else(|defect| panic!("stage the type corpus: {defect}"));

    let enforces_control_flow: bool =
        cc_toolchain::accepts_flag(&toolchain, &work, CONTROL_FLOW_ENFORCEMENT);
    eprintln!(
        "fresh-build type reference: cc={} identity={:?} cf_protection_supported={enforces_control_flow}",
        toolchain.gcc.display(),
        toolchain.identity,
    );

    let mut cet_prologue_seen: bool = false;
    let mut per_version: Vec<(Leg, Measured)> = Vec::new();
    for leg in LEGS {
        if leg.protection == CONTROL_FLOW_ENFORCEMENT && !enforces_control_flow {
            eprintln!(
                "leg {} not run: this compiler refuses {CONTROL_FLOW_ENFORCEMENT}, which only x86 \
                 targets accept",
                leg.id
            );
            continue;
        }
        let flags: [&str; 7] = [
            "-g",
            "-O0",
            leg.dwarf_flag,
            leg.protection,
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,_start",
        ];
        let image: DebugImage = build_and_load(&toolchain, &work, &source, leg.id, &flags);
        let measured: Measured = measure(&image, leg);
        eprintln!(
            "leg {} endbr64_prologue={} {} width_correct={} sign_correct={} mapped={}/{}",
            leg.id,
            measured.starts_with_endbr64,
            measured.survey,
            measured.report.width.correct,
            measured.report.sign.correct,
            measured.report.mapped_vars,
            measured.report.total_vars,
        );
        cet_prologue_seen |= measured.starts_with_endbr64;
        assert_eq!(
            measured.report.mapped_vars, measured.report.total_vars,
            "every reference variable of the {} build must reach a recovered slot",
            leg.id,
        );
        assert!(
            measured.report.width_mismatches.is_empty(),
            "recompiled width must never be wrong on the {} build: {:?}",
            leg.id,
            measured.report.width_mismatches,
        );
        assert!(
            measured.report.sign_mismatches.is_empty(),
            "recompiled signedness must never be wrong on the {} build: {:?}",
            leg.id,
            measured.report.sign_mismatches,
        );
        assert!((measured.report.sign.precision() - 1.0).abs() < f64::EPSILON);
        assert!(
            measured.report.sign.correct >= 1,
            "some signs must be recoverable on the {} build",
            leg.id,
        );
        per_version.push((leg, measured));
    }

    assert!(
        !per_version.is_empty(),
        "{GRADED} ran no leg at all, so it measured nothing",
    );
    if enforces_control_flow {
        assert!(
            cet_prologue_seen,
            "no {CONTROL_FLOW_ENFORCEMENT} build began a function with endbr64, so this case never \
             exercised the prologue shape it exists to cover",
        );
        for version in [2u16, 3, 4, 5] {
            let of_version: Vec<&(Leg, Measured)> = per_version
                .iter()
                .filter(|(leg, _): &&(Leg, Measured)| leg.version == version)
                .collect();
            let [(_, protected), (_, plain)]: [&(Leg, Measured); 2] =
                match of_version.as_slice().try_into() {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
            assert_eq!(
                protected.survey.located, plain.survey.located,
                "a DWARF {version} build placed {} variables with control-flow enforcement and {} \
                 without it, so the prologue shape still decides the reference",
                protected.survey.located, plain.survey.located,
            );
            assert_eq!(
                protected.report.total_vars, plain.report.total_vars,
                "a DWARF {version} build graded a different variable count with and without \
                 control-flow enforcement",
            );
        }
    }
}

#[test]
fn optimised_build_names_every_location_form_it_cannot_place() {
    let Some(toolchain): Option<CcToolchain> = cc_toolchain::require(GRADED) else {
        return;
    };
    let scratch: ScratchDir = ScratchDir::create("disrobe_typerec_forms")
        .unwrap_or_else(|error| panic!("{GRADED} needs a working directory: {error}"));
    let work: PathBuf = scratch.path().to_path_buf();
    let source: OsString = cc_toolchain::stage_source(&work, &fixture_source("location_forms.c"))
        .unwrap_or_else(|defect| panic!("stage the location-form corpus: {defect}"));

    for (id, level, dwarf_flag) in [
        ("forms-o1-dwarf4", "-O1", "-gdwarf-4"),
        ("forms-o2-dwarf5", "-O2", "-gdwarf-5"),
    ] {
        let flags: [&str; 7] = [
            "-g",
            level,
            dwarf_flag,
            "-fno-omit-frame-pointer",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,_start",
        ];
        let image: DebugImage = build_and_load(&toolchain, &work, &source, id, &flags);
        let survey: LocationSurvey = image.locations.clone();
        eprintln!("leg {id} {survey}");
        assert!(
            survey.balances(),
            "the {id} survey lost {} of {} declared variables without naming a reason: {survey}",
            survey.declared - survey.located - survey.unlocated_total(),
            survey.declared,
        );
        assert!(
            survey.declared > 0,
            "the {id} build declared no variable at all, so this case measured nothing",
        );
        assert_eq!(
            survey.unmodelled_total(),
            0,
            "the {id} build carries a location form this reader does not model: {survey}",
        );
        assert!(
            survey.located > 0,
            "an optimised build keeps the volatile local on the stack, so {id} placing none of its \
             variables means the frame forms went unread: {survey}",
        );
        assert!(
            survey.unlocated_total() > 0,
            "an optimised build must hold variables that live somewhere other than a frame slot, \
             so {id} placing every one of them means the survey is not seeing the real forms: \
             {survey}",
        );
        assert!(
            survey.count(UnlocatedReason::RegisterResident) > 0,
            "an optimised build passes arguments in registers, so {id} naming no register-resident \
             variable means the register form is being reported as something else: {survey}",
        );
        assert!(
            survey.unlocated.len() >= 3,
            "an optimised build spreads its variables across several location forms, so {id} \
             naming only {} of them means the forms are collapsing into one bucket: {survey}",
            survey.unlocated.len(),
        );
        assert_eq!(
            survey.count(UnlocatedReason::LocationUnreadable)
                + survey.count(UnlocatedReason::LocationListUnreadable),
            0,
            "a location this reader could not parse is a defect, not a classification: {survey}",
        );
    }
}
