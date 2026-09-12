#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_typerec::dwarf_gt::{self, DebugImage, GroundTruthFunction, GroundTruthVar};
use disrobe_typerec::dwarf_location::LocationSurvey;

const DEBUG_SECTION_PREFIX: &[u8] = b".debug_";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn tracked(relative: &str) -> Vec<u8> {
    let path: PathBuf = workspace_root().join(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{relative} is tracked in git and this case grades nothing without it, so its absence \
             is a damaged checkout and not an optional dependency: {error} ({})",
            path.display()
        )
    })
}

fn fixture(name: &str) -> Vec<u8> {
    tracked(&format!("crates/disrobe-typerec/tests/fixtures/{name}"))
}

fn variables(image: &DebugImage) -> Vec<&GroundTruthVar> {
    image
        .functions
        .iter()
        .flat_map(|function: &GroundTruthFunction| function.vars.iter())
        .collect()
}

#[test]
fn every_committed_dwarf_version_object_yields_located_variables() {
    for (name, version) in [
        ("dwarf_v2.o", 2u16),
        ("dwarf_v3.o", 3),
        ("dwarf_v4.o", 4),
        ("dwarf_v5.o", 5),
    ] {
        let bytes: Vec<u8> = tracked(&format!("corpus/native/formats/{name}"));
        let image: DebugImage = dwarf_gt::load(&bytes)
            .unwrap_or_else(|error| panic!("read the DWARF of {name}: {error}"));
        let survey: LocationSurvey = image.locations.clone();
        eprintln!("{name}: {survey}");
        assert_eq!(
            survey.versions,
            BTreeSet::from([version]),
            "{name} is named for DWARF {version} and carries {:?}",
            survey.versions,
        );
        assert!(
            survey.balances(),
            "{name} lost declared variables without naming a reason: {survey}",
        );
        assert!(
            image.variable_count() > 0,
            "{name} carries DWARF variables at frame offsets, so reading none of them means the \
             location forms of DWARF {version} went unread: {survey}",
        );
        assert_eq!(
            survey.unmodelled_total(),
            0,
            "{name} carries a location form this reader does not model: {survey}",
        );
    }
}

#[test]
fn the_frame_base_location_list_of_a_dwarf_2_object_scopes_its_variables() {
    let bytes: Vec<u8> = tracked("corpus/native/formats/dwarf_v2.o");
    let image: DebugImage = dwarf_gt::load(&bytes).expect("read the DWARF of dwarf_v2.o");
    let reference: Vec<u8> = tracked("corpus/native/formats/dwarf_v4.o");
    let modern: DebugImage = dwarf_gt::load(&reference).expect("read the DWARF of dwarf_v4.o");

    let older: Vec<(String, i64)> = variables(&image)
        .iter()
        .map(|var: &&GroundTruthVar| (var.name.clone(), var.rbp_disp))
        .collect();
    let newer: Vec<(String, i64)> = variables(&modern)
        .iter()
        .map(|var: &&GroundTruthVar| (var.name.clone(), var.rbp_disp))
        .collect();
    eprintln!("dwarf 2 frame-base list placed {older:?}");
    eprintln!("dwarf 4 call-frame cfa placed {newer:?}");
    assert_eq!(
        older, newer,
        "the same source compiled at -gdwarf-2 and -gdwarf-4 must place the same variables at the \
         same frame displacements, whether the frame base arrives as a location list or as \
         DW_OP_call_frame_cfa",
    );
    let function: &GroundTruthFunction = image
        .functions
        .first()
        .expect("dwarf_v2.o carries one subprogram");
    let mut clamped: usize = 0;
    for var in variables(&image) {
        assert!(
            var.scope_lo < var.scope_hi,
            "{} carries an empty live range, so it can never match a recovered object",
            var.name,
        );
        assert!(
            var.scope_lo >= function.low_pc && var.scope_hi <= function.high_pc,
            "{} is live outside the function that declares it",
            var.name,
        );
        if var.scope_lo > function.low_pc {
            clamped += 1;
        }
    }
    assert!(
        clamped > 0,
        "the frame base of dwarf_v2.o is a location list whose frame-pointer entry starts after \
         the prologue, so every variable placed against it must be scoped to that entry rather \
         than to the whole function",
    );
}

#[test]
fn a_truncated_debug_section_is_refused_rather_than_trusted() {
    let mut bytes: Vec<u8> = fixture("types_corpus.unstripped.exe");
    let intact: DebugImage = dwarf_gt::load(&bytes).expect("read the intact fixture");
    assert!(intact.variable_count() > 0, "the intact fixture must grade");

    let starts: Vec<usize> = (0..bytes.len().saturating_sub(DEBUG_SECTION_PREFIX.len()))
        .filter(|offset: &usize| bytes[*offset..].starts_with(DEBUG_SECTION_PREFIX))
        .collect();
    assert!(
        !starts.is_empty(),
        "the fixture must carry named debug sections for this case to damage",
    );

    for cut in [1usize, 3, 7, 16, 64, 255, 1024, 4096] {
        if cut >= bytes.len() {
            continue;
        }
        let damaged: Vec<u8> = bytes[..bytes.len() - cut].to_vec();
        match dwarf_gt::load(&damaged) {
            Ok(image) => assert!(
                image.locations.balances(),
                "a truncated image reported a survey that does not add up: {}",
                image.locations,
            ),
            Err(error) => eprintln!("truncation by {cut} bytes was refused: {error}"),
        }
    }

    for offset in starts {
        for byte in bytes.iter_mut().skip(offset).take(64) {
            *byte ^= 0xff;
        }
        match dwarf_gt::load(&bytes) {
            Ok(image) => assert!(
                image.locations.balances(),
                "a corrupted image reported a survey that does not add up: {}",
                image.locations,
            ),
            Err(error) => eprintln!("corruption at {offset:#x} was refused: {error}"),
        }
        for byte in bytes.iter_mut().skip(offset).take(64) {
            *byte ^= 0xff;
        }
    }
}

#[test]
fn a_hostile_length_field_cannot_make_the_reader_allocate_without_bound() {
    let bytes: Vec<u8> = fixture("types_corpus.unstripped.exe");
    let mut damaged: Vec<u8> = bytes;
    let needle: &[u8] = b".debug_info\0";
    let Some(position): Option<usize> = damaged
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
    else {
        panic!("the fixture must carry a .debug_info section name for this case to damage");
    };
    for offset in position..(position + 512).min(damaged.len()) {
        damaged[offset] = 0xff;
    }
    match dwarf_gt::load(&damaged) {
        Ok(image) => assert!(
            image.locations.balances(),
            "a hostile section header produced a survey that does not add up: {}",
            image.locations,
        ),
        Err(error) => eprintln!("a hostile section header was refused: {error}"),
    }
}

#[test]
fn the_committed_fixture_survey_accounts_for_every_declaration() {
    for name in [
        "types_corpus.unstripped.exe",
        "types_o1_corpus.unstripped.exe",
        "struct_corpus.unstripped.exe",
        "abi_corpus.unstripped.exe",
        "callsite_corpus.unstripped.so",
    ] {
        let image: DebugImage =
            dwarf_gt::load(&fixture(name)).unwrap_or_else(|error| panic!("read {name}: {error}"));
        let survey: LocationSurvey = image.locations.clone();
        eprintln!("{name}: {survey}");
        assert!(
            survey.balances(),
            "{name} lost {} of {} declared variables without naming a reason: {survey}",
            survey.declared - survey.located - survey.unlocated_total(),
            survey.declared,
        );
        assert_eq!(
            survey.unmodelled_total(),
            0,
            "{name} carries a location form this reader does not model: {survey}",
        );
        assert!(
            survey.located > 0,
            "{name} is a graded reference and placed no variable at all: {survey}",
        );
    }
}
