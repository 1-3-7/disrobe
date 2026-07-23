use std::io::{Cursor, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

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

const MAX_INPUT_BYTES: usize = 4096;
const MAX_INPUT_BYTES_U64: u64 = 4096;
const RANDOM_CASES: usize = 96;
const MUTATIONS_PER_SEED: usize = 32;
const CASES_PER_BATCH: usize = 16;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const MAX_BATCH_BYTES_U64: u64 = 65_600;
const BATCH_BUDGET: Duration = Duration::from_secs(5);
const TEST_BUDGET: Duration = Duration::from_mins(1);
const BATCH_PATH_ENV: &str = "DISROBE_PYFREEZE_FUZZ_BATCH";
const WORKSPACE_PATH_ENV: &str = "DISROBE_PYFREEZE_FUZZ_WORKSPACE";

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut value: u64 = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let bound_u64: u64 = u64::try_from(bound).map_or(u64::MAX, |value: u64| value);
        let value: u64 = self.next_u64() % bound_u64;
        usize::try_from(value).map_or(0, |value: usize| value)
    }

    const fn next_byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }
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
        let Some(local_offset): Option<u32> = u32::try_from(out.len()).ok() else {
            return Vec::new();
        };
        let Some(compressed_size): Option<u32> = u32::try_from(body.len()).ok() else {
            return Vec::new();
        };
        let Some(name_len): Option<u16> = u16::try_from(name_bytes.len()).ok() else {
            return Vec::new();
        };
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
    let Some(central_offset): Option<u32> = u32::try_from(out.len()).ok() else {
        return Vec::new();
    };
    let Some(central_size): Option<u32> = u32::try_from(central.len()).ok() else {
        return Vec::new();
    };
    let Some(entry_count): Option<u16> = u16::try_from(entries.len()).ok() else {
        return Vec::new();
    };
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

fn structured_seeds() -> Vec<Vec<u8>> {
    let pex: Vec<u8> = stored_zip(&[
        ("PEX-INFO", br#"{"entry_point":"app:main"}"#),
        ("app.py", b"print('pex')\n"),
    ]);
    let shiv: Vec<u8> = stored_zip(&[
        (
            "_bootstrap/environment.json",
            br#"{"entry_point":"app:main"}"#,
        ),
        ("_bootstrap/_bootstrap.py", b"pass\n"),
        ("app.py", b"print('shiv')\n"),
    ]);
    let zipapp: Vec<u8> = stored_zip(&[("__main__.py", b"print('zipapp')\n")]);
    vec![
        Vec::new(),
        pyc_seed(),
        py2exe_seed(),
        pyoxidizer_malformed_seed(),
        pyoxidizer_v3_seed(),
        malformed_zip_seed(),
        pex,
        shiv,
        zipapp,
    ]
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let seed_len: usize = seed.len().min(MAX_INPUT_BYTES);
    let mut out: Vec<u8> = seed[..seed_len].to_vec();
    match rng.next_u64() % 7 {
        0 => {
            let index: usize = rng.next_usize(out.len());
            if let Some(byte) = out.get_mut(index) {
                *byte ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => {
            let len: usize = rng.next_usize(out.len());
            out.truncate(len);
        }
        2 => {
            let changes: usize = rng.next_usize(32);
            for _ in 0..changes {
                let index: usize = rng.next_usize(out.len());
                if let Some(byte) = out.get_mut(index) {
                    *byte = rng.next_byte();
                }
            }
        }
        3 => {
            for byte in &mut out {
                if rng.next_u64().trailing_zeros() >= 2 {
                    *byte = u8::MAX;
                }
            }
        }
        4 => {
            let extra: usize = rng.next_usize(64);
            for _ in 0..extra {
                if out.len() == MAX_INPUT_BYTES {
                    break;
                }
                out.push(rng.next_byte());
            }
        }
        5 => {
            for byte in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *byte = 0;
                }
            }
        }
        _ => {
            let len: usize = rng.next_usize(MAX_INPUT_BYTES);
            let mut random: Vec<u8> = Vec::with_capacity(len);
            for _ in 0..len {
                random.push(rng.next_byte());
            }
            out = random;
        }
    }
    out
}

fn exercise_byte_entrypoints(bytes: &[u8], rng: &mut Xorshift64) {
    let major: u8 = 2u8.saturating_add(rng.next_byte() % 4);
    let minor: u8 = rng.next_byte() % 16;
    let declared_size: u64 = u64::try_from(bytes.len()).map_or(0, |value: u64| value);
    let mut bounded: Cursor<&[u8]> = Cursor::new(bytes);
    let mut limited: Cursor<&[u8]> = Cursor::new(bytes);

    let _: Detection = detect_bytes(bytes, None);
    let _: Detection = exported_detect_bytes(bytes, None);
    let _: Result<RecoveredModule> = recover_bytecode("fuzz.pyc", bytes);
    let _: Result<RecoveredModule> = recover_raw_marshal("fuzz.marshal", bytes, major, minor);
    let _: Result<Vec<u8>> = synthesize_pyc(bytes, major, minor);
    let _: Result<SurfacedNative> = surface_native("fuzz.pyd", bytes);
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
        read_to_vec_limited(&mut limited, declared_size, MAX_INPUT_BYTES_U64);

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

fn exercise_file_entrypoints(bytes: &[u8], source: &Path, out_dir: &Path) -> std::io::Result<()> {
    std::fs::write(source, bytes)?;
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
        let _: Result<RecoveredModule> = extraction.recover_main(3, 12);
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
    let _: Result<RecoveredModule> = recover_bytecode_file("fuzz.pyc", source);
    let _: Result<SurfacedNative> = surface_native_file("fuzz.pyd", source);
    Ok(())
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

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn create() -> std::io::Result<Self> {
        for _ in 0..1024 {
            let path: PathBuf = workspace_dir();
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to create unique pyfreeze fuzz workspace",
        ))
    }

    fn child(&self, index: usize) -> std::io::Result<ChildWorkspace> {
        let path: PathBuf = self.path.join(format!("worker-{index}"));
        std::fs::create_dir(&path)?;
        Ok(ChildWorkspace { path })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.path);
    }
}

struct ChildWorkspace {
    path: PathBuf,
}

impl Drop for ChildWorkspace {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.path);
    }
}

fn workspace_dir() -> PathBuf {
    let sequence: u64 = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "disrobe-pyfreeze-fuzz-{}-{sequence}",
        std::process::id()
    ))
}

fn run_case(
    bytes: &[u8],
    rng: &mut Xorshift64,
    source: &Path,
    out_dir: &Path,
) -> std::io::Result<()> {
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir)?;
    }
    std::fs::create_dir_all(out_dir)?;
    exercise_byte_entrypoints(bytes, rng);
    exercise_file_entrypoints(bytes, source, out_dir)?;
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
    Ok(())
}

fn build_cases() -> Vec<Vec<u8>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5046_5A17_0001_0002);
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for _ in 0..RANDOM_CASES {
        let len: usize = rng.next_usize(MAX_INPUT_BYTES);
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.next_byte());
        }
        cases.push(bytes);
    }
    let seeds: Vec<Vec<u8>> = structured_seeds();
    for seed in &seeds {
        cases.push(seed.clone());
    }
    for seed in &seeds {
        for _ in 0..MUTATIONS_PER_SEED {
            cases.push(mutate(seed, &mut rng));
        }
    }
    cases
}

fn write_batch(path: &Path, cases: &[Vec<u8>]) -> std::io::Result<()> {
    let mut bytes: Vec<u8> = Vec::new();
    for case in cases {
        let len: u32 = u32::try_from(case.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "fuzz case length does not fit u32",
            )
        })?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(case);
    }
    std::fs::write(path, bytes)
}

fn read_batch(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let file: std::fs::File = std::fs::File::open(path)?;
    let mut reader: std::io::Take<std::fs::File> = file.take(MAX_BATCH_BYTES_U64 + 1);
    let mut bytes: Vec<u8> = Vec::with_capacity(MAX_BATCH_BYTES);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fuzz batch exceeds byte limit",
        ));
    }
    let mut cursor: usize = 0;
    let mut cases: Vec<Vec<u8>> = Vec::with_capacity(CASES_PER_BATCH);
    while cursor < bytes.len() {
        if cases.len() == CASES_PER_BATCH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch exceeds case limit",
            ));
        }
        let length_end: usize = cursor.checked_add(4).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch length cursor overflow",
            )
        })?;
        let length_bytes: [u8; 4] = bytes
            .get(cursor..length_end)
            .and_then(|slice: &[u8]| slice.try_into().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated fuzz batch length",
                )
            })?;
        let declared_len: u32 = u32::from_le_bytes(length_bytes);
        let case_len: usize = usize::try_from(declared_len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch length does not fit usize",
            )
        })?;
        if case_len > MAX_INPUT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch case exceeds input limit",
            ));
        }
        let case_end: usize = length_end.checked_add(case_len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch case end overflow",
            )
        })?;
        let case: Vec<u8> = bytes
            .get(length_end..case_end)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated fuzz batch case",
                )
            })?
            .to_vec();
        cases.push(case);
        cursor = case_end;
    }
    Ok(cases)
}

fn run_batch(
    path: &Path,
    workspace: &Path,
    batch_index: usize,
    remaining_budget: Duration,
) -> std::io::Result<()> {
    let executable: PathBuf = std::env::current_exe()?;
    let batch_budget: Duration = BATCH_BUDGET.min(remaining_budget);
    let mut child: std::process::Child = Command::new(executable)
        .args(["--exact", "fuzz_resilience_worker", "--nocapture"])
        .env(BATCH_PATH_ENV, path)
        .env(WORKSPACE_PATH_ENV, workspace)
        .stdout(Stdio::null())
        .spawn()?;
    let started: Instant = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "fuzz batch {batch_index} exited with {status}"
            )));
        }
        if started.elapsed() > batch_budget {
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error),
            }
            let _: ExitStatus = child.wait()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("fuzz batch {batch_index} exceeded {batch_budget:?}"),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn fuzz_resilience_worker() -> std::io::Result<()> {
    let Some(batch_path): Option<std::ffi::OsString> = std::env::var_os(BATCH_PATH_ENV) else {
        return Ok(());
    };
    let workspace: PathBuf = std::env::var_os(WORKSPACE_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing fuzz worker workspace",
            )
        })?;
    let cases: Vec<Vec<u8>> = read_batch(Path::new(&batch_path))?;
    let source: PathBuf = workspace.join("input.bin");
    let out_dir: PathBuf = workspace.join("out");
    for (case_index, bytes) in cases.iter().enumerate() {
        let seed: u64 = u64::try_from(case_index).map_or(0, |value: u64| value);
        let mut rng: Xorshift64 = Xorshift64::new(0x5046_5A17_0001_0002 ^ seed);
        run_case(bytes, &mut rng, &source, &out_dir)?;
    }
    Ok(())
}

#[test]
fn bounded_public_parse_entrypoints_accept_malformed_inputs_without_panicking()
-> std::io::Result<()> {
    let started: Instant = Instant::now();
    let workspace: TempWorkspace = TempWorkspace::create()?;
    let cases: Vec<Vec<u8>> = build_cases();
    for (batch_index, batch) in cases.chunks(CASES_PER_BATCH).enumerate() {
        let elapsed: Duration = started.elapsed();
        let remaining_budget: Duration = TEST_BUDGET.checked_sub(elapsed).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("fuzz suite exceeded {TEST_BUDGET:?}"),
            )
        })?;
        let batch_path: PathBuf = workspace.path.join(format!("batch-{batch_index}.bin"));
        let child_workspace: ChildWorkspace = workspace.child(batch_index)?;
        write_batch(&batch_path, batch)?;
        run_batch(
            &batch_path,
            &child_workspace.path,
            batch_index,
            remaining_budget,
        )?;
    }

    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed <= TEST_BUDGET,
        "bounded parser suite exceeded {TEST_BUDGET:?}: {elapsed:?}"
    );
    Ok(())
}
