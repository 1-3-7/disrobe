#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::path::PathBuf;

use common::band_gate::{
    BandPopulation, CPYTHON_SERIES, population_disagreements, release_mismatch,
    resolve_band_interpreter,
};
use common::stdlib_measure::{PublishedBar, interpreter_release};

#[test]
fn every_band_pins_a_patch_release_under_its_own_alias() {
    for band in CPYTHON_SERIES {
        let alias: &str = band.toolchain.alias;
        let release: &str = band.toolchain.release;
        assert!(
            release.starts_with(&format!("{alias}.")),
            "the CPython {alias} band pins the release `{release}`, which is not a patch release \
             of {alias}; the resolver asks for the pinned release by name, so a release that \
             belongs to another series would silently resolve the wrong interpreter"
        );
    }
}

#[test]
fn an_interpreter_change_and_a_recovery_change_fail_differently() {
    for band in CPYTHON_SERIES {
        assert!(
            release_mismatch(band.toolchain.release, &band.toolchain).is_none(),
            "the pinned release {} has to compare equal to itself",
            band.toolchain.release
        );
    }

    let band: &common::band_gate::BandRelease = &CPYTHON_SERIES[6];
    let moved_on: String = format!("{}9", band.toolchain.release);
    let Some(interpreter_text): Option<String> = release_mismatch(&moved_on, &band.toolchain)
    else {
        panic!(
            "a run on CPython {moved_on} is not the pinned {}, so it must be reported as an \
             interpreter change",
            band.toolchain.release
        );
    };
    println!("interpreter-change failure text:\n{interpreter_text}");
    assert!(
        interpreter_text.contains(&moved_on) && interpreter_text.contains(band.toolchain.release),
        "the interpreter-change failure has to name both the release that ran and the release the \
         band is pinned to, or a reader cannot tell which way it moved: {interpreter_text}"
    );
    assert!(
        interpreter_text.contains("NOT a recovery regression"),
        "the whole point of this failure is that it cannot be read as a recovery regression, so it \
         has to say so: {interpreter_text}"
    );

    let published: PublishedBar = PublishedBar {
        value: 96.59,
        num: 6_072,
        den: 6_286,
        modules: 200,
    };
    let recovered_more: BandPopulation = BandPopulation {
        objects_ok: 6_076,
        code_objects: 6_286,
        modules: 200,
    };
    let recovery_text: String = population_disagreements(&recovered_more, &published).join("; ");
    println!("recovery-change failure text:\n{recovery_text}");
    assert!(
        recovery_text.contains("numerator"),
        "a recovery change has to surface as a numerator disagreement: {recovery_text}"
    );
    assert!(
        !recovery_text.contains("NOT a recovery regression"),
        "the two failures have to be distinguishable by their text alone: {recovery_text}"
    );
}

#[test]
fn the_resolver_prefers_the_release_each_band_is_pinned_to() {
    let mut wrong: Vec<String> = Vec::new();
    let mut checked: u64 = 0;
    for band in CPYTHON_SERIES {
        let graded: String = format!(
            "the CPython {} band, which is pinned to release {}",
            band.toolchain.alias, band.toolchain.release
        );
        let Some(python): Option<PathBuf> = resolve_band_interpreter(&band.toolchain, &graded)
        else {
            continue;
        };
        let Some(release): Option<String> = interpreter_release(&python) else {
            wrong.push(format!(
                "{}: could not read the release of the resolved interpreter at {}",
                band.toolchain.alias,
                python.display()
            ));
            continue;
        };
        checked += 1;
        println!(
            "{} pinned {} resolved {release} at {}",
            band.toolchain.alias,
            band.toolchain.release,
            python.display()
        );
        if release != band.toolchain.release {
            wrong.push(format!(
                "{} is pinned to {} but resolved {release}; `uv python install {}` would let the \
                 resolver prefer the pinned one over any newer release in the same series",
                band.toolchain.alias, band.toolchain.release, band.toolchain.release
            ));
        }
    }
    assert!(
        checked > 0,
        "no banded interpreter resolved at all, so this case graded nothing about the resolver"
    );
    assert!(
        wrong.is_empty(),
        "a band gate compares a live measurement against counts pinned to one patch release, so \
         the resolver has to return that release whenever the host has it: {}",
        wrong.join("; ")
    );
}
