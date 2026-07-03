#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_precision_loss
)]

use disrobe_pass_pyinstaller::{
    Cookie, EntryType, ExtractOutput, ExtractedEntry, PyzEntry, TocEntry, extract_archive,
    extract_pyz, find_cookie, walk_toc,
};
use disrobe_py_marshal::{Object, PyVersion, load};

const PACKED: &[u8] =
    include_bytes!("../../../corpus/python/freezers/pyinstaller/gauntlet/hello.exe");

const ORIGINAL_SOURCE: &str =
    include_str!("../../../corpus/python/freezers/pyinstaller/gauntlet/hello.py");

const SCRIPT_ENTRY_NAME: &str = "hello";
const PYZ_ENTRY_NAME: &str = "PYZ.pyz";

const PY312_MAGIC_LE: [u8; 4] = [0xCB, 0x0D, 0x0D, 0x0A];
const PY312_PYC_HEADER_LEN: usize = 16;

const SOURCE_IDENTIFIERS: [&str; 11] = [
    "GREETING_PREFIX",
    "MAGIC_CONSTANT",
    "RETRY_LIMIT",
    "Greeter",
    "salutations",
    "greet",
    "fibonacci",
    "classify",
    "negative",
    "even",
    "odd",
];

const SOURCE_STRING_LITERAL: &str = "disrobe-pyinstaller-gauntlet";

fn script_entry(output: &ExtractOutput) -> &ExtractedEntry {
    output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| {
            e.toc.entry_type == EntryType::Script && e.toc.name == SCRIPT_ENTRY_NAME
        })
        .expect("the application script entry must survive extraction")
}

fn marshal_body(entry: &ExtractedEntry) -> &[u8] {
    let data: &[u8] = &entry.data;
    assert!(
        data.len() > PY312_PYC_HEADER_LEN,
        "recovered pyc for '{}' is too short to carry a 3.12 header + body: {} bytes",
        entry.toc.name,
        data.len()
    );
    assert_eq!(
        &data[..4],
        &PY312_MAGIC_LE,
        "recovered pyc for '{}' must carry the CPython 3.12 magic (0x0A0D0DCB le)",
        entry.toc.name
    );
    &data[PY312_PYC_HEADER_LEN..]
}

fn pyz_blob(output: &ExtractOutput) -> Vec<u8> {
    let pyz: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| {
            e.toc.entry_type == EntryType::Pyz && e.toc.name == PYZ_ENTRY_NAME
        })
        .expect("the embedded PYZ archive entry must survive extraction");
    pyz.data.clone()
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[test]
fn pyinstaller_gauntlet_detects_real_onefile_cookie() {
    let cookie: Cookie =
        find_cookie(PACKED).expect("real PyInstaller onefile must expose a MEI cookie");
    assert_eq!(cookie.python_major, 3, "detected python major");
    assert_eq!(cookie.python_minor, 12, "detected python minor");
    assert_eq!(
        cookie.python_libname.as_deref(),
        Some("python312.dll"),
        "v2.1+ cookie must expose the python library name",
    );
    assert!(
        cookie.length_of_package > 0,
        "package length must be non-zero",
    );

    let toc: Vec<TocEntry> =
        walk_toc(PACKED, &cookie).expect("toc must walk the real CArchive layout");
    assert!(
        toc.len() >= 10,
        "real onefile TOC must enumerate the runtime hooks, script, PYZ and bundled binaries; got {}",
        toc.len(),
    );
    let has_script: bool = toc
        .iter()
        .any(|e: &TocEntry| e.entry_type == EntryType::Script && e.name == SCRIPT_ENTRY_NAME);
    assert!(
        has_script,
        "TOC must carry the application script entry '{SCRIPT_ENTRY_NAME}'",
    );
    let has_pyz: bool = toc
        .iter()
        .any(|e: &TocEntry| e.entry_type == EntryType::Pyz);
    assert!(has_pyz, "TOC must carry a PYZ archive entry");
}

#[test]
fn pyinstaller_gauntlet_carves_application_script_to_pyc() {
    let output: ExtractOutput =
        extract_archive(PACKED).expect("extract the real PyInstaller onefile CArchive");
    assert!(
        output.encryption_key.is_none(),
        "unkeyed onefile must not materialize an encryption key",
    );

    let script: &ExtractedEntry = script_entry(&output);
    let body: &[u8] = marshal_body(script);

    let mut hits: usize = 0usize;
    for ident in SOURCE_IDENTIFIERS {
        assert!(
            ORIGINAL_SOURCE.contains(ident),
            "guard: identifier '{ident}' must exist in the clean original source",
        );
        if slice_contains(body, ident.as_bytes()) {
            hits += 1;
        } else {
            println!("gauntlet: identifier '{ident}' absent from recovered marshal body");
        }
    }
    let recovery_pct: f64 = 100.0 * hits as f64 / SOURCE_IDENTIFIERS.len() as f64;
    println!(
        "pyinstaller gauntlet: identifier recovery {}/{} = {recovery_pct:.2}% in carved script pyc",
        hits,
        SOURCE_IDENTIFIERS.len(),
    );
    assert_eq!(
        hits,
        SOURCE_IDENTIFIERS.len(),
        "every clean-source identifier must survive into the carved script marshal (got {recovery_pct:.2}%)",
    );

    assert!(
        ORIGINAL_SOURCE.contains(SOURCE_STRING_LITERAL),
        "guard: string literal must exist in the clean original source",
    );
    assert!(
        slice_contains(body, SOURCE_STRING_LITERAL.as_bytes()),
        "the original string constant '{SOURCE_STRING_LITERAL}' must survive into the carved script marshal",
    );

    let magic_value: u16 = 1337;
    assert!(
        slice_contains(body, &magic_value.to_le_bytes()),
        "the original numeric constant {magic_value} must be present in the carved marshal as a little-endian short int const",
    );
}

fn body_parses_to_code(body: &[u8]) -> bool {
    let version: PyVersion = PyVersion::new(3, 12);
    matches!(load(body, version), Ok(Object::Code(_)))
}

#[test]
fn pyinstaller_gauntlet_carves_pyz_modules_to_code_objects() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract real onefile");
    let blob: Vec<u8> = pyz_blob(&output);

    let (_py_version, entries) =
        extract_pyz(&blob).expect("the embedded PYZ must parse and decompress");
    assert!(
        entries.len() >= 20,
        "a real onefile PYZ bundles the stdlib slice; expected many modules, got {}",
        entries.len(),
    );

    let future_mod: &PyzEntry = entries
        .iter()
        .find(|e: &&PyzEntry| e.name == "__future__")
        .expect("the PYZ must carve the stdlib __future__ module");
    let loaded: Object = load(&future_mod.bytes, PyVersion::new(3, 12))
        .expect("the carved __future__ body must be a loadable marshal stream");
    let Object::Code(future_code) = loaded else {
        panic!("carved __future__ PYZ body must marshal-load to a module code object");
    };
    assert!(
        matches!(&future_code.name, Object::String { value, .. } | Object::ShortAscii { value, .. } if value == "<module>"),
        "carved __future__ code object co_name must be '<module>', got {:?}",
        future_code.name,
    );

    let loadable: usize = entries
        .iter()
        .filter(|e: &&PyzEntry| body_parses_to_code(&e.bytes))
        .count();
    let code_pct: f64 = 100.0 * loadable as f64 / entries.len() as f64;
    println!(
        "pyinstaller gauntlet: {}/{} carved PYZ entries = {code_pct:.2}% marshal-load to module code objects",
        loadable,
        entries.len(),
    );
    assert!(
        code_pct >= 99.0,
        "essentially every carved PYZ module must marshal-load to a code object; got {code_pct:.2}%",
    );
}

#[test]
fn pyinstaller_gauntlet_inlines_pyz_modules_as_recoverable_pyc_entries() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract real onefile");
    assert!(
        output.pyz_module_count >= 20,
        "extract_archive must unpack the embedded PYZ into its constituent modules inline, \
         not leave a single opaque PYZ.pyz blob; got {} unpacked modules",
        output.pyz_module_count,
    );

    let pyz_module_entries: Vec<&ExtractedEntry> = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| {
            matches!(
                e.toc.entry_type,
                EntryType::PyzModule | EntryType::PyzPackage
            )
        })
        .collect();
    assert_eq!(
        pyz_module_entries.len(),
        output.pyz_module_count,
        "every counted PYZ module must surface as an inline entry ready to write",
    );

    let future_pyc: &ExtractedEntry = pyz_module_entries
        .iter()
        .copied()
        .find(|e: &&ExtractedEntry| e.toc.name == "PYZ.pyz_extracted/__future__.pyc")
        .expect("the stdlib __future__ module must be unpacked from the PYZ to a .pyc under PYZ.pyz_extracted/");
    assert_eq!(
        &future_pyc.data[..4],
        &PY312_MAGIC_LE,
        "an unpacked PYZ module must carry a reconstructed CPython 3.12 pyc header so it feeds straight into py-decompile",
    );
    assert!(
        body_parses_to_code(&future_pyc.data[PY312_PYC_HEADER_LEN..]),
        "the reconstructed __future__.pyc body must marshal-load to a code object",
    );

    let packages: usize = pyz_module_entries
        .iter()
        .filter(|e: &&&ExtractedEntry| e.toc.name.ends_with("/__init__.pyc"))
        .count();
    assert!(
        packages > 0,
        "PYZ packages must be unpacked to <pkg>/__init__.pyc, mirroring the real import layout",
    );
}

#[test]
fn pyinstaller_gauntlet_unpacks_base_library_zip_bootstrap_stdlib() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract real onefile");
    assert!(
        output.base_library_module_count >= 20,
        "the bundled base_library.zip must be unpacked into its bootstrap .pyc modules inline, \
         not left as a single opaque data blob; got {} surfaced modules",
        output.base_library_module_count,
    );

    let base_entries: Vec<&ExtractedEntry> = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| {
            matches!(
                e.toc.entry_type,
                EntryType::BaseLibraryModule | EntryType::BaseLibraryPackage
            )
        })
        .collect();
    assert_eq!(
        base_entries.len(),
        output.base_library_module_count,
        "every counted base_library module must surface as its own inline entry",
    );

    let still_opaque: bool = output
        .entries
        .iter()
        .any(|e: &ExtractedEntry| e.toc.name == "base_library.zip");
    assert!(
        still_opaque,
        "the original base_library.zip data entry must remain (additive-safe surfacing)",
    );

    let loadable: usize = base_entries
        .iter()
        .filter(|e: &&&ExtractedEntry| {
            e.data.len() > PY312_PYC_HEADER_LEN
                && e.data[..4] == PY312_MAGIC_LE
                && body_parses_to_code(&e.data[PY312_PYC_HEADER_LEN..])
        })
        .count();
    let code_pct: f64 = 100.0 * loadable as f64 / base_entries.len() as f64;
    println!(
        "pyinstaller gauntlet: {}/{} base_library.zip modules = {code_pct:.2}% marshal-load to code objects under CPython 3.12",
        loadable,
        base_entries.len(),
    );
    assert!(
        code_pct >= 99.0,
        "essentially every unpacked base_library.zip module must marshal-load to a code object; got {code_pct:.2}%",
    );

    let has_encodings_pkg: bool = base_entries
        .iter()
        .any(|e: &&ExtractedEntry| e.toc.name.ends_with("encodings/__init__.pyc"));
    assert!(
        has_encodings_pkg,
        "the base_library.zip bootstrap must surface the encodings package as encodings/__init__.pyc",
    );
}

#[test]
fn pyinstaller_gauntlet_separates_pyc_carriers_from_bundled_binaries() {
    let output: ExtractOutput = extract_archive(PACKED).expect("extract real onefile");

    let pyc_carriers: usize = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type.is_pyc_carrier())
        .count();
    assert!(
        pyc_carriers >= 3,
        "onefile bundles the app script plus PyInstaller runtime hook modules; expected several pyc carriers, got {pyc_carriers}",
    );

    let binaries: usize = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Binary)
        .count();
    assert!(
        binaries > 0,
        "a real onefile must carry bundled binary dependencies (python312.dll et al.)",
    );

    for carrier in output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type.is_pyc_carrier())
    {
        assert!(
            carrier.data.len() > PY312_PYC_HEADER_LEN && carrier.data[..4] == PY312_MAGIC_LE,
            "pyc carrier '{}' must be reconstructed with a valid 3.12 pyc header",
            carrier.toc.name,
        );
    }

    let bare_pyc: usize = output.bare_pyc_paths.len();
    assert_eq!(
        bare_pyc, pyc_carriers,
        "every pyc carrier must register a recoverable .pyc path",
    );
}
