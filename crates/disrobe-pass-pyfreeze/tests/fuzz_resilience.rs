#![allow(clippy::expect_used)]
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_pass_pyfreeze::bbfreeze;
use disrobe_pass_pyfreeze::briefcase;
use disrobe_pass_pyfreeze::common::pyc::{PycFingerprint, fingerprint};
use disrobe_pass_pyfreeze::common::read_bounded::{
    prealloc_for, read_to_vec_bounded, read_to_vec_limited,
};
use disrobe_pass_pyfreeze::common::shebang::{self, Shebang};
use disrobe_pass_pyfreeze::common::zip_tail::{self, ZipTailInfo};
use disrobe_pass_pyfreeze::cxfreeze;
use disrobe_pass_pyfreeze::detect::{Detection, detect_bytes};
use disrobe_pass_pyfreeze::error::Result;
use disrobe_pass_pyfreeze::pass::{self, PyfreezeOutput};
use disrobe_pass_pyfreeze::pex;
use disrobe_pass_pyfreeze::py2exe;
use disrobe_pass_pyfreeze::pyoxidizer;
use disrobe_pass_pyfreeze::pyoxidizer::signatures::{
    ExtractedModule, ModuleExtractionError, PackedResourcesParse, extract_modules,
    extract_resources_blob, infer_python_version, is_present, parse_packed_resources, scan,
};
use disrobe_pass_pyfreeze::recover::{
    RecoveredModule, SurfacedNative, classify_bare_pyc, recover_bytecode, recover_bytecode_file,
    recover_raw_marshal, surface_native, surface_native_file, synthesize_pyc,
};
use disrobe_pass_pyfreeze::shiv;
use disrobe_pass_pyfreeze::zipapp;
use disrobe_pass_pyfreeze::{ExtractionQuota, detect_bytes as exported_detect_bytes};
use disrobe_testkit::{BATCH_ENV, CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const READ_BOUND_BYTES: u64 = 4096;
const CASES_PER_INPUT: usize = 64;
const BATCH_SIZE: usize = 256;
const CASE_BUDGET: Duration = Duration::from_millis(60);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PROBE_DOMAIN: u64 = 0x5046_5A17_0001_0001;
const SATURATION_DOMAIN: u64 = 0x5046_5A17_0001_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const MAJOR_SPAN: u8 = 4;
const MINOR_SPAN: u8 = 16;
const OLDEST_MAJOR: u8 = 2;
const PY2EXE_RECOVER_ABI: (u8, u8) = (3, 12);
const SCRATCH_DIRECTORY: &str = "pyfreeze-file-entrypoints";
const SCRATCH_INPUT: &str = "input.bin";
const SCRATCH_OUT: &str = "out";
const WORKER_SCRATCH_TAG: &str = "worker";
const UNMUTATED_SCRATCH_TAG: &str = "unmutated-seeds";
const CONSTRUCTED_SCRATCH_TAG: &str = "constructed-zips";
const PYC_NAME: &str = "fuzz.pyc";
const MARSHAL_NAME: &str = "fuzz.marshal";
const NATIVE_NAME: &str = "fuzz.pyd";

#[derive(Debug)]
struct Scratch {
    directory: PathBuf,
    input: PathBuf,
    out: PathBuf,
}

impl Scratch {
    fn create(base: &Path, tag: &str) -> Self {
        let directory: PathBuf =
            base.join(format!("{SCRATCH_DIRECTORY}-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&directory)
            .expect("the stress worker can create its scratch directory");
        Self {
            input: directory.join(SCRATCH_INPUT),
            out: directory.join(SCRATCH_OUT),
            directory,
        }
    }

    fn fresh_out_dir(&self) -> &Path {
        if self.out.exists() {
            std::fs::remove_dir_all(&self.out)
                .expect("the stress worker can clear its scratch output directory");
        }
        std::fs::create_dir_all(&self.out)
            .expect("the stress worker can create its scratch output directory");
        &self.out
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.directory);
    }
}

fn batch_workspace() -> PathBuf {
    let batch: Option<PathBuf> = std::env::var_os(BATCH_ENV).map(PathBuf::from);
    batch
        .as_deref()
        .and_then(Path::parent)
        .map_or_else(std::env::temp_dir, Path::to_path_buf)
}

fn worker_scratch() -> &'static Scratch {
    static SCRATCH: OnceLock<Scratch> = OnceLock::new();
    SCRATCH.get_or_init(|| Scratch::create(&batch_workspace(), WORKER_SCRATCH_TAG))
}

const fn test_quota() -> ExtractionQuota {
    ExtractionQuota {
        max_entries: 32,
        max_total_uncompressed: 64 * 1024,
        max_per_entry_uncompressed: 16 * 1024,
        max_per_entry_ratio: 32,
        max_aggregate_ratio: 16,
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, body) in entries {
        let name_bytes: &[u8] = name.as_bytes();
        let local_offset: u32 = u32::try_from(out.len())
            .expect("a constructed stored zip stays far inside the 32-bit offset range");
        let compressed_size: u32 = u32::try_from(body.len())
            .expect("a constructed stored zip entry stays far inside the 32-bit size range");
        let name_len: u16 =
            u16::try_from(name_bytes.len()).expect("a constructed zip entry name is short");
        let crc: u32 = crc32(body);

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(body);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed_size.to_le_bytes());
        central.extend_from_slice(&compressed_size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let central_offset: u32 = u32::try_from(out.len())
        .expect("a constructed stored zip stays far inside the 32-bit offset range");
    let central_size: u32 = u32::try_from(central.len())
        .expect("a constructed central directory stays far inside the 32-bit size range");
    let entry_count: u16 =
        u16::try_from(entries.len()).expect("a constructed stored zip holds a handful of entries");
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn pyc_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&[0xa7, 0x0d, 0x0d, 0x0a]);
    bytes.extend_from_slice(&[0u8; 12]);
    bytes.extend_from_slice(b"c\x00\x00\x00");
    bytes
}

fn py2exe_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = b"MZ".to_vec();
    bytes.resize(0x3c, 0);
    bytes.extend_from_slice(&0x40u32.to_le_bytes());
    bytes.extend_from_slice(b"PE\x00\x00PYTHONSCRIPT");
    bytes.extend_from_slice(&0x7856_3412u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(b"app.zip\x00python312.dll\x00");
    bytes
}

fn pyoxidizer_malformed_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"PyOxidizer\x00python312.dll\x00pyembed\x03");
    bytes.push(u8::MAX);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes
}

fn pyoxidizer_v3_seed() -> Vec<u8> {
    let mut blob_index: Vec<u8> = Vec::new();
    for (field, length) in [(0x03u8, 3u64), (0x07u8, 8u64)] {
        blob_index.extend_from_slice(&[0x01, 0x02, field, 0x03]);
        blob_index.extend_from_slice(&length.to_le_bytes());
        blob_index.extend_from_slice(&[0x04, 0x01, 0xff]);
    }
    blob_index.push(0);

    let mut resources_index: Vec<u8> = Vec::new();
    resources_index.extend_from_slice(&[0x01, 0x03]);
    resources_index.extend_from_slice(&3u16.to_le_bytes());
    resources_index.extend_from_slice(&[0x16, 0x07]);
    resources_index.extend_from_slice(&8u32.to_le_bytes());
    resources_index.extend_from_slice(&[0xff, 0x00]);

    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"PyOxidizer\x00python312.dll\x00pyembed\x03");
    bytes.push(2);
    bytes.extend_from_slice(&31u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&12u32.to_le_bytes());
    bytes.extend_from_slice(&blob_index);
    bytes.extend_from_slice(&resources_index);
    bytes.extend_from_slice(b"modBYTECODE");
    bytes
}

fn malformed_zip_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = b"PK\x05\x06".to_vec();
    bytes.extend_from_slice(&[u8::MAX; 18]);
    bytes
}

fn pex_seed() -> Vec<u8> {
    stored_zip(&[
        ("PEX-INFO", br#"{"entry_point":"app:main"}"#),
        ("app.py", b"print('pex')\n"),
    ])
}

fn shiv_seed() -> Vec<u8> {
    stored_zip(&[
        (
            "_bootstrap/environment.json",
            br#"{"entry_point":"app:main"}"#,
        ),
        ("_bootstrap/_bootstrap.py", b"pass\n"),
        ("app.py", b"print('shiv')\n"),
    ])
}

fn zipapp_seed() -> Vec<u8> {
    stored_zip(&[("__main__.py", b"print('zipapp')\n")])
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("bare-pyc", pyc_seed()),
        CorpusEntry::new("py2exe-pe", py2exe_seed()),
        CorpusEntry::new("pyoxidizer-malformed", pyoxidizer_malformed_seed()),
        CorpusEntry::new("pyoxidizer-v3", pyoxidizer_v3_seed()),
        CorpusEntry::new("malformed-zip", malformed_zip_seed()),
        CorpusEntry::new("pex-zip", pex_seed()),
        CorpusEntry::new("shiv-zip", shiv_seed()),
        CorpusEntry::new("zipapp-zip", zipapp_seed()),
        CorpusEntry::new("random-span", vec![0u8; RANDOM_SPAN_BYTES]),
    ]
}

fn saturate(bytes: &[u8], case_seed: u64) -> Vec<u8> {
    let mut rng: XorShift64 = XorShift64::new(case_seed ^ SATURATION_DOMAIN);
    let mut out: Vec<u8> = bytes.to_vec();
    let pick: usize = rng.below_usize(SATURATION_PATTERNS.len().saturating_add(1));
    let Some(&(value, sparsity)): Option<&(u8, u32)> = SATURATION_PATTERNS.get(pick) else {
        let changes: usize = rng.below_usize(MAX_SCATTERED_OVERWRITES);
        for _ in 0..changes {
            let index: usize = rng.below_usize(out.len());
            if let Some(byte) = out.get_mut(index) {
                *byte = rng.next_byte();
            }
        }
        return out;
    };
    for byte in &mut out {
        if rng.next_u64().trailing_zeros() >= sparsity {
            *byte = value;
        }
    }
    out
}

fn exercise_byte_entrypoints(bytes: &[u8], rng: &mut XorShift64) {
    let major: u8 = OLDEST_MAJOR.saturating_add(rng.next_byte() % MAJOR_SPAN);
    let minor: u8 = rng.next_byte() % MINOR_SPAN;
    let declared_size: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut bounded: Cursor<&[u8]> = Cursor::new(bytes);
    let mut limited: Cursor<&[u8]> = Cursor::new(bytes);

    let _: Detection = detect_bytes(bytes, None);
    let _: Detection = exported_detect_bytes(bytes, None);
    let _: Result<RecoveredModule> = recover_bytecode(PYC_NAME, bytes);
    let _: Result<RecoveredModule> = recover_raw_marshal(MARSHAL_NAME, bytes, major, minor);
    let _: Result<Vec<u8>> = synthesize_pyc(bytes, major, minor);
    let _: Result<SurfacedNative> = surface_native(NATIVE_NAME, bytes);
    let _: Option<PycFingerprint> = fingerprint(bytes);
    let _: Option<(u8, u8)> = classify_bare_pyc(bytes);
    let _: Option<Shebang> = shebang::parse(bytes);
    let _: bool = shebang::parse(bytes)
        .is_some_and(|header: Shebang| shebang::looks_like_python_runner(&header.line));
    let _: Result<ZipTailInfo> = zip_tail::locate(bytes);
    let _: bool = zip_tail::is_likely_trailing_zip(bytes);
    let _: usize = prealloc_for(declared_size);
    let _: std::io::Result<Vec<u8>> = read_to_vec_bounded(&mut bounded, declared_size);
    let _: std::io::Result<Vec<u8>> =
        read_to_vec_limited(&mut limited, declared_size, READ_BOUND_BYTES);

    let _: bool = py2exe::pe::looks_like_pe(bytes);
    let _: Option<(u8, u8)> = py2exe::pe::sniff_python_version(bytes);
    let _: Result<Vec<u8>> = py2exe::pe::extract_pythonscript_resource(bytes);
    let _: Result<Vec<u8>> = py2exe::overlay::extract_overlay_zip(bytes);
    let _: Result<py2exe::ScriptInfo> = py2exe::scriptinfo::parse(bytes);

    let markers: Vec<String> = scan(bytes);
    let _: bool = is_present(&markers);
    let _: (Option<u8>, Option<u8>, Option<String>) = infer_python_version(bytes);
    let blob: Option<&[u8]> = extract_resources_blob(bytes);
    let _: Option<PackedResourcesParse> = parse_packed_resources(bytes);
    let _: std::result::Result<Vec<ExtractedModule>, ModuleExtractionError> =
        extract_modules(bytes);
    if let Some(blob) = blob {
        let _: Option<PackedResourcesParse> = parse_packed_resources(blob);
        let _: std::result::Result<Vec<ExtractedModule>, ModuleExtractionError> =
            extract_modules(blob);
    }
    let _: bool = pyoxidizer::looks_like_pyoxidizer(bytes);
    let _: Result<pex::pex_info::PexInfo> = pex::pex_info::parse(bytes);
    let _: Result<shiv::environment::ShivEnvironment> = shiv::environment::parse(bytes);
}

fn exercise_file_entrypoints(bytes: &[u8], scratch: &Scratch) {
    let out_dir: &Path = scratch.fresh_out_dir();
    std::fs::write(&scratch.input, bytes)
        .expect("the stress worker can write its scratch input file");
    let source: &Path = scratch.input.as_path();
    let quota: ExtractionQuota = test_quota();

    let _: Result<Detection> = pass::detect(source);
    let _: Result<PyfreezeOutput> = pass::extract(source, out_dir);
    let _: Option<bbfreeze::layout::BbfreezeLayout> = bbfreeze::layout::probe(source);
    let _: Result<bbfreeze::BbfreezeExtraction> = bbfreeze::detect_and_extract(source, out_dir);
    let _: bool = briefcase::looks_like_briefcase(source);
    let _: Result<briefcase::layout::BriefcaseLayout> = briefcase::layout::probe(source);
    let _: Result<Vec<briefcase::layout::BriefcaseSourceEntry>> =
        briefcase::layout::walk_python_sources(out_dir);
    let _: Result<briefcase::BriefcaseExtraction> = briefcase::detect_and_extract(source);
    let _: bool = cxfreeze::layout::could_be_cxfreeze(source);
    let _: Result<cxfreeze::layout::CxFreezeLayout> = cxfreeze::layout::probe(source);
    let cxfreeze_extraction: Result<cxfreeze::CxFreezeExtraction> =
        cxfreeze::detect_and_extract(source, out_dir);
    if let Ok(extraction) = cxfreeze_extraction {
        let _: cxfreeze::CxFreezeRecovery = extraction.recover();
        let _: Vec<SurfacedNative> = extraction.sibling_native_extensions();
    }
    let _: Result<Vec<cxfreeze::library_zip::ExtractedEntry>> =
        cxfreeze::library_zip::extract_all_with_quota(bytes, out_dir, quota);
    let _: Result<Vec<cxfreeze::library_zip::ExtractedEntry>> =
        cxfreeze::library_zip::extract_all(bytes, out_dir);
    let _: Result<py2exe::library::BundledModules> =
        py2exe::library::extract_bundled_modules(source, Some(bytes), out_dir);
    let py2exe_extraction: Result<py2exe::Py2exeExtraction> =
        py2exe::detect_and_extract(bytes, source, out_dir);
    if let Ok(extraction) = py2exe_extraction {
        let _: Result<RecoveredModule> =
            extraction.recover_main(PY2EXE_RECOVER_ABI.0, PY2EXE_RECOVER_ABI.1);
    }
    let _: Result<pyoxidizer::PyOxidizerExtraction> =
        pyoxidizer::detect_and_extract(bytes, source, out_dir);
    let _: Result<pex::PexExtraction> =
        pex::detect_and_extract_with_quota(bytes, source, out_dir, quota);
    let _: Result<pex::PexExtraction> = pex::detect_and_extract(bytes, source, out_dir);
    let _: Result<shiv::ShivExtraction> =
        shiv::detect_and_extract_with_quota(bytes, source, out_dir, quota);
    let _: Result<shiv::ShivExtraction> = shiv::detect_and_extract(bytes, source, out_dir);
    let _: Result<zipapp::ZipappExtraction> =
        zipapp::detect_and_extract_with_quota(bytes, source, out_dir, quota);
    let _: Result<zipapp::ZipappExtraction> = zipapp::detect_and_extract(bytes, source, out_dir);
    let _: Result<RecoveredModule> = recover_bytecode_file(PYC_NAME, source);
    let _: Result<SurfacedNative> = surface_native_file(NATIVE_NAME, source);
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, Pass};
    use disrobe_pass_pyfreeze::chain_detector::{PyfreezeDetector, PyfreezePass};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _: Option<disrobe_core::chain::DetectVerdict> = PyfreezeDetector.detect(&context);
    let _: disrobe_core::error::Result<Artifact> = PyfreezePass.run(&artifact);
    let _: disrobe_core::error::Result<Vec<disrobe_core::chain::detection::ChildArtifact>> =
        PyfreezePass.extract_children(&artifact);
}

fn probe(bytes: &[u8], scratch: &Scratch, rng: &mut XorShift64) {
    exercise_byte_entrypoints(bytes, rng);
    exercise_file_entrypoints(bytes, scratch);
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
}

fn check(case: &StressCase<'_>) {
    let scratch: &Scratch = worker_scratch();
    let mut rng: XorShift64 = XorShift64::new(case.case_seed() ^ PROBE_DOMAIN);
    probe(case.bytes(), scratch, &mut rng);
    probe(&saturate(case.bytes(), case.case_seed()), scratch, &mut rng);
}

fn config() -> StressConfig {
    StressConfig {
        cases_per_input: CASES_PER_INPUT,
        batch_size: BATCH_SIZE,
        case_budget: CASE_BUDGET,
        suite_budget: SUITE_BUDGET,
        ..StressConfig::default()
    }
}

mod resilience {
    disrobe_testkit::stress_suite!(
        check: super::check,
        corpus: super::corpus,
        config: super::config
    );
}

#[test]
fn the_saturation_probe_rewrites_the_bytes_it_is_handed_and_replays_from_its_seed() {
    const SAMPLE: usize = 512;
    let original: Vec<u8> = vec![0x33u8; SAMPLE];
    let mut untouched: usize = 0;
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    for case_seed in 0..SAMPLE as u64 {
        let probed: Vec<u8> = saturate(&original, case_seed);
        assert_eq!(probed, saturate(&original, case_seed));
        if probed == original {
            untouched = untouched.saturating_add(1);
        }
        if !distinct.contains(&probed) {
            distinct.push(probed);
        }
    }
    assert!(
        untouched < SAMPLE / 16,
        "{untouched} of {SAMPLE} probe outputs came back unchanged"
    );
    assert!(
        distinct.len() > SAMPLE / 2,
        "only {} distinct probe outputs",
        distinct.len()
    );
}

#[test]
fn every_unmutated_seed_finishes() {
    let scratch: Scratch = Scratch::create(&std::env::temp_dir(), UNMUTATED_SCRATCH_TAG);
    for entry in corpus() {
        let mut rng: XorShift64 = XorShift64::new(PROBE_DOMAIN);
        probe(entry.bytes(), &scratch, &mut rng);
    }
}

#[test]
fn the_constructed_stored_zips_extract_the_entries_the_seeds_claim() {
    let scratch: Scratch = Scratch::create(&std::env::temp_dir(), CONSTRUCTED_SCRATCH_TAG);
    let source: &Path = scratch.input.as_path();

    let pex_bytes: Vec<u8> = pex_seed();
    assert!(
        zip_tail::is_likely_trailing_zip(&pex_bytes),
        "a constructed stored zip must read as a zip, or every zip-shaped seed is silently inert"
    );
    let tail: ZipTailInfo =
        zip_tail::locate(&pex_bytes).expect("the constructed pex zip has a locatable tail");
    assert_eq!(tail.archive_start_offset, 0);
    std::fs::write(source, &pex_bytes).expect("the scratch input file is writable");
    let pex_extraction: pex::PexExtraction = pex::detect_and_extract_with_quota(
        &pex_bytes,
        source,
        scratch.fresh_out_dir(),
        test_quota(),
    )
    .expect("the constructed pex zip extracts");
    assert_eq!(
        pex_extraction.pex_info.entry_point.as_deref(),
        Some("app:main")
    );
    assert!(!pex_extraction.extracted.is_empty());

    let shiv_bytes: Vec<u8> = shiv_seed();
    std::fs::write(source, &shiv_bytes).expect("the scratch input file is writable");
    let shiv_extraction: shiv::ShivExtraction = shiv::detect_and_extract_with_quota(
        &shiv_bytes,
        source,
        scratch.fresh_out_dir(),
        test_quota(),
    )
    .expect("the constructed shiv zip extracts");
    assert_eq!(
        shiv_extraction.environment.entry_point.as_deref(),
        Some("app:main")
    );

    let zipapp_bytes: Vec<u8> = zipapp_seed();
    std::fs::write(source, &zipapp_bytes).expect("the scratch input file is writable");
    let zipapp_extraction: zipapp::ZipappExtraction = zipapp::detect_and_extract_with_quota(
        &zipapp_bytes,
        source,
        scratch.fresh_out_dir(),
        test_quota(),
    )
    .expect("the constructed zipapp extracts");
    assert!(
        zipapp_extraction
            .extracted
            .iter()
            .any(|entry: &zipapp::ExtractedEntry| entry.name == "__main__.py")
    );
}
