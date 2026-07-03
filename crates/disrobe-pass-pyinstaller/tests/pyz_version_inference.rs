#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_pyinstaller::{Error, PyzEntry, extract_pyz};
use disrobe_py_marshal::{Object, PyVersion, load};

const REAL_PY313: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyinstaller/pyz_versions/real_py313.pyz");
const REAL_PY311: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyinstaller/pyz_versions/real_py311.pyz");

fn assert_real_pyz(blob: &[u8], expected: PyVersion, tag: &str) {
    let (version, entries): (PyVersion, Vec<PyzEntry>) =
        extract_pyz(blob).expect("a real PyInstaller PYZ must parse");
    assert_eq!(
        version, expected,
        "the recovered version must equal the real interpreter that wrote the PYZ ({tag}), not the 3.12 default",
    );
    assert_ne!(
        version,
        PyVersion::PY312,
        "guard: this fixture is deliberately not 3.12 so a silent 3.12 default would be visible",
    );
    let alpha: &PyzEntry = entries
        .iter()
        .find(|e: &&PyzEntry| e.name == format!("disrobe_pyz_oracle_{tag}_alpha"))
        .expect("the alpha module must be carved from the real toc");
    let loaded: Object = load(&alpha.bytes, version)
        .expect("the carved module body must marshal-load under the recovered version");
    assert!(
        matches!(loaded, Object::Code(_)),
        "a correctly-versioned marshal decode yields a code object",
    );
}

#[test]
fn recovers_python_313_from_real_pyz() {
    assert_real_pyz(REAL_PY313, PyVersion::PY313, "313");
}

#[test]
fn recovers_python_311_from_real_pyz() {
    assert_real_pyz(REAL_PY311, PyVersion::PY311, "311");
}

#[test]
fn unknown_pyc_magic_yields_explicit_signal_not_a_default() {
    let mut tampered: Vec<u8> = REAL_PY313.to_vec();
    let bogus_magic: u32 = 0xDEAD_BEEF;
    tampered[4..8].copy_from_slice(&bogus_magic.to_le_bytes());
    let err: Error = extract_pyz(&tampered)
        .expect_err("an unrecognised pyc magic must error rather than silently assume 3.12");
    match err {
        Error::UnknownPyzMagic(magic) => assert_eq!(
            magic, bogus_magic,
            "the explicit error must carry the unknown magic for diagnosis",
        ),
        other => panic!("expected UnknownPyzMagic, got {other:?}"),
    }
}

#[test]
fn known_magic_never_silently_collapses_to_312() {
    let (v313, _): (PyVersion, Vec<PyzEntry>) = extract_pyz(REAL_PY313).expect("3.13 pyz parses");
    let (v311, _): (PyVersion, Vec<PyzEntry>) = extract_pyz(REAL_PY311).expect("3.11 pyz parses");
    assert_ne!(
        v313, v311,
        "two different real interpreters must not both be reported as one default version",
    );
}
