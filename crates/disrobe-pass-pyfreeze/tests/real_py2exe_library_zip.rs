#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_pyfreeze::py2exe::{Py2exeExtraction, detect_and_extract};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, PyfreezeOutput, detect_bytes, extract};

const BANDS: &[&str] = &[
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];

fn freezers_dir() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("freezers");
    p
}

fn sibling_layout_exe() -> PathBuf {
    freezers_dir()
        .join("py2exe")
        .join("extracted")
        .join("hello.exe")
}

fn out_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0x70CE_0000);
    let purpose: String = format!(
        "disrobe-py2exe-libzip-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

#[test]
fn py2exe_sibling_layout_is_not_misdetected_as_cxfreeze() {
    let exe: PathBuf = sibling_layout_exe();
    if !exe.is_file() {
        eprintln!(
            "[real_py2exe_library_zip] skipped: fixture missing at {}",
            exe.display()
        );
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&exe).expect("read exe");
    let det: Detection = detect_bytes(&bytes, Some(&exe));
    assert_eq!(
        det.kind,
        FreezerKind::Py2exe,
        "a py2exe stub sitting next to a bare sibling library.zip must classify as py2exe via its \
         PYTHONSCRIPT resource, not as cx_Freeze; got {det:?}"
    );
}

#[test]
fn py2exe_recovers_full_module_set_from_sibling_library_zip() {
    let exe: PathBuf = sibling_layout_exe();
    if !exe.is_file() {
        eprintln!("[real_py2exe_library_zip] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&exe).expect("read exe");
    let scratch: disrobe_core::scratch::ScratchDir = out_dir("extract");
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: Py2exeExtraction =
        detect_and_extract(&bytes, &exe, &out).expect("py2exe extraction");

    assert!(
        extraction.library_zip_path.is_some(),
        "py2exe extraction must locate the sibling library.zip"
    );

    let bundled: BTreeSet<String> = extraction
        .bundled_modules
        .iter()
        .map(|e| e.name.clone())
        .collect();
    for band in BANDS {
        let pyc: String = format!("{band}.pyc");
        assert!(
            bundled.contains(&pyc),
            "band `{band}` must be extracted from the sibling library.zip; got {bundled:?}"
        );
    }

    let manifest_names: BTreeSet<String> = extraction
        .manifest
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert!(
        manifest_names.contains("__pythonscript__.pyc"),
        "the PYTHONSCRIPT entry must still be in the manifest"
    );
    for band in BANDS {
        assert!(
            manifest_names.contains(&format!("{band}.pyc")),
            "manifest must enumerate band `{band}`"
        );
    }
    assert!(
        extraction.manifest.entry_count > BANDS.len(),
        "manifest must enumerate the script entry plus all bundled modules, got {}",
        extraction.manifest.entry_count
    );
}

#[test]
fn py2exe_bundled_pyc_are_real_loadable_bytecode() {
    let exe: PathBuf = sibling_layout_exe();
    if !exe.is_file() {
        eprintln!("[real_py2exe_library_zip] skipped: fixture missing");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&exe).expect("read exe");
    let scratch: disrobe_core::scratch::ScratchDir = out_dir("loadable");
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: Py2exeExtraction =
        detect_and_extract(&bytes, &exe, &out).expect("py2exe extraction");

    let mut loaded: usize = 0;
    for ent in &extraction.bundled_modules {
        if !ent.name.ends_with(".pyc") {
            continue;
        }
        let body: Vec<u8> = std::fs::read(&ent.disk_path).expect("read extracted pyc");
        let pyc: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&body)
            .unwrap_or_else(|e| {
                panic!(
                    "extracted py2exe module `{}` must be a real loadable CPython pyc, not garbage: {e}",
                    ent.name
                )
            });
        match pyc.code {
            disrobe_py_marshal::Object::Code(_) => loaded += 1,
            other => panic!(
                "extracted py2exe module `{}` pyc body must marshal-load into a code object, got {other:?}",
                ent.name
            ),
        }
    }
    assert!(
        loaded >= BANDS.len(),
        "every bundled band pyc must marshal-load into a code object via a real (non-disrobe-self) \
         marshal reader; loaded {loaded}, expected at least {}",
        BANDS.len()
    );
}

#[test]
fn py2exe_full_pipeline_extract_recovers_more_than_just_the_script() {
    let exe: PathBuf = sibling_layout_exe();
    if !exe.is_file() {
        eprintln!("[real_py2exe_library_zip] skipped: fixture missing");
        return;
    }
    let scratch: disrobe_core::scratch::ScratchDir = out_dir("pipeline");
    let out: PathBuf = scratch.path().to_path_buf();
    let output: PyfreezeOutput = extract(&exe, &out).expect("pyfreeze extract");
    assert_eq!(output.detection.kind, FreezerKind::Py2exe);
    assert!(
        output.recovery.modules.len() > 1,
        "the py2exe path must now recover the full bundled module set, not only \
         __pythonscript__; recovered {} modules: {:?}",
        output.recovery.modules.len(),
        output
            .recovery
            .modules
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<String>>()
    );
    let recovered: BTreeSet<String> = output
        .recovery
        .modules
        .iter()
        .map(|m| m.name.clone())
        .collect();
    let band_hits: usize = BANDS
        .iter()
        .filter(|b| recovered.contains(&format!("{b}.pyc")))
        .count();
    assert!(
        band_hits >= BANDS.len(),
        "every edge_cases band must be recovered through the py2exe pipeline; hit {band_hits}/{} \
         (recovered={recovered:?})",
        BANDS.len()
    );
}
