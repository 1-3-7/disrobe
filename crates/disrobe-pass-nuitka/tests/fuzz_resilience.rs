#![allow(clippy::expect_used)]
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_pass_nuitka::{
    NuitkaConstants, StreamedEntry, build_manifest, build_manifest_from_file, classify,
    classify_in_file, constants_unparsable, decode_build_constants, decode_bytecode_table,
    decode_const_file, decompile_binary, decompile_bytes, decompile_const_bytes, demangle_function,
    detect_authenticode, detect_in_bytes, detect_in_file, detect_nuitka_version,
    disassemble_module_stats, disassemble_module_to_file, disassemble_module_to_vec,
    extract_for_classification, extract_onefile, extract_onefile_streaming, extract_variant,
    lift_body, lift_native_bodies, locate_onefile_payload, map_names, parse_c_module,
    parse_c_module_with_python_abi, parse_constant_manifest, parse_constant_manifest_from_file,
    parse_constants, parse_exact_version_from_constants_c, reconstruct_skeleton,
    recover_frozen_bytecode, scan_build_info, scan_c_source_markers, scan_constants_blob,
    scan_plugins, scan_symbols,
};
use disrobe_testkit::{BATCH_ENV, CorpusEntry, StressCase, StressConfig, XorShift64};

const RANDOM_SPAN_BYTES: usize = 4096;
const CASES_PER_INPUT: usize = 128;
const BATCH_SIZE: usize = 256;
const CASE_BUDGET: Duration = Duration::from_millis(60);
const SUITE_BUDGET: Duration = Duration::from_mins(3);

const PROBE_DOMAIN: u64 = 0x4E75_6974_6B61_0001;
const SATURATION_DOMAIN: u64 = 0x4E75_6974_6B61_0002;
const SATURATION_PATTERNS: [(u8, u32); 2] = [(u8::MAX, 2), (0, 3)];
const MAX_SCATTERED_OVERWRITES: usize = 32;
const NAME_SAMPLE_LIMIT: usize = 64;
const PYTHON_ABI: (u8, u8) = (3, 14);
const SCRATCH_DIRECTORY: &str = "nuitka-file-entrypoints";
const SCRATCH_INPUT: &str = "input.bin";
const SCRATCH_DISASSEMBLY: &str = "native.asm";
const MODULE_NAME: &str = "fuzz";
const CONST_FILE_NAME: &str = "fuzz.const";

type EntrySink = dyn for<'a> FnMut(&StreamedEntry<'a>) -> std::io::Result<()>;

#[derive(Debug)]
struct Scratch {
    directory: PathBuf,
    input: PathBuf,
    disassembly: PathBuf,
}

impl Scratch {
    fn create(base: &Path) -> Self {
        let directory: PathBuf = base.join(format!("{SCRATCH_DIRECTORY}-{}", std::process::id()));
        std::fs::create_dir_all(&directory)
            .expect("the stress worker can create its scratch directory");
        Self {
            input: directory.join(SCRATCH_INPUT),
            disassembly: directory.join(SCRATCH_DISASSEMBLY),
            directory,
        }
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
    SCRATCH.get_or_init(|| Scratch::create(&batch_workspace()))
}

fn onefile_stored_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"KAX");
    bytes.extend_from_slice(&u16::from(b'x').to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes
}

fn onefile_compressed_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"KAY");
    bytes.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]);
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes
}

fn pe_section_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 0x40];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes.resize(0x98, 0);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    bytes[0x98 - 8..0x98 - 6].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes
}

fn elf_section_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[58..60].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[60..62].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes
}

fn constants_stream_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"module");
    bytes.push(0);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&u16::MAX.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0xff, 128));
    bytes.extend_from_slice(b".bytecode");
    bytes.push(0);
    bytes.extend(std::iter::repeat_n(0x80, 64));
    bytes
}

fn deeply_nested_c_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"impl_f() { return ");
    bytes.extend(std::iter::repeat_n(b'(', 1024));
    bytes.extend_from_slice(b"value");
    bytes.extend(std::iter::repeat_n(b')', 1024));
    bytes.extend_from_slice(b"; }");
    bytes
}

fn corpus() -> Vec<CorpusEntry> {
    vec![
        CorpusEntry::new("empty", Vec::<u8>::new()),
        CorpusEntry::new("onefile-stored", onefile_stored_seed()),
        CorpusEntry::new("onefile-compressed", onefile_compressed_seed()),
        CorpusEntry::new("pe-section", pe_section_seed()),
        CorpusEntry::new("elf-section", elf_section_seed()),
        CorpusEntry::new("constants-stream", constants_stream_seed()),
        CorpusEntry::new("deeply-nested-c", deeply_nested_c_seed()),
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
    let constants: NuitkaConstants = parse_constants(bytes);
    let names: Vec<String> = constants
        .modules
        .iter()
        .flat_map(|module| module.strings.iter().cloned())
        .take(NAME_SAMPLE_LIMIT)
        .collect();
    let source: String = String::from_utf8_lossy(bytes).into_owned();
    let payload_offset: usize = rng.below_usize(bytes.len().saturating_add(8));
    let constant_files: [(String, Vec<u8>, String); 1] = [(
        CONST_FILE_NAME.to_owned(),
        bytes.to_vec(),
        MODULE_NAME.to_owned(),
    )];
    let mut sink: Box<EntrySink> = Box::new(|_entry: &StreamedEntry<'_>| Ok(()));

    let _ = detect_in_bytes(bytes);
    let _ = constants_unparsable(bytes);
    let _ = scan_constants_blob(bytes);
    let _ = parse_constant_manifest(bytes);
    let _ = scan_c_source_markers(bytes);
    let _ = scan_build_info(bytes);
    let _ = scan_plugins(bytes);
    let _ = scan_symbols(bytes);
    let _ = detect_authenticode(bytes);
    let _ = locate_onefile_payload(bytes);
    let classification: disrobe_pass_nuitka::Result<disrobe_pass_nuitka::VariantClassification> =
        classify(bytes);
    if let Ok(classification) = &classification {
        let _ = extract_for_classification(bytes, classification);
    }
    let _ = extract_variant(bytes);
    let _ = build_manifest(bytes);
    let _ = decode_const_file(bytes, CONST_FILE_NAME, MODULE_NAME);
    let _ = decode_build_constants(&constant_files);
    let _ = decode_bytecode_table(bytes, None);
    let _ = recover_frozen_bytecode(bytes, None);
    let _ = disassemble_module_stats(MODULE_NAME, bytes);
    let _ = disassemble_module_to_vec(MODULE_NAME, bytes);
    let _ = lift_native_bodies(bytes, &constants);
    let _ = reconstruct_skeleton(&constants);
    let _ = map_names(MODULE_NAME, bytes, &names);
    for name in &names {
        let _ = demangle_function(name);
    }
    let _ = decompile_bytes(bytes);
    let _ = decompile_const_bytes(bytes, CONST_FILE_NAME, MODULE_NAME);
    let _ = detect_nuitka_version(bytes, Some(bytes), None);
    let _ = parse_exact_version_from_constants_c(bytes);
    let _ = extract_onefile(bytes, payload_offset);
    let _ = extract_onefile_streaming(bytes, payload_offset, &mut sink);
    let _ = parse_c_module(&source);
    let _ = parse_c_module_with_python_abi(&source, PYTHON_ABI);
    let _ = lift_body(
        &source,
        &names,
        &disrobe_pass_nuitka::ConstantsPool::default(),
    );
}

fn exercise_file_entrypoints(bytes: &[u8], scratch: &Scratch) {
    std::fs::write(&scratch.input, bytes)
        .expect("the stress worker can write its scratch input file");
    let _ = detect_in_file(&scratch.input);
    let _ = parse_constant_manifest_from_file(&scratch.input);
    let _ = build_manifest_from_file(&scratch.input);
    let _ = classify_in_file(&scratch.input);
    let _ = decompile_binary(&scratch.input);
    let _ = disassemble_module_to_file(MODULE_NAME, bytes, &scratch.disassembly);
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, Pass};
    use disrobe_pass_nuitka::chain_detector::{NuitkaDetector, NuitkaPass};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _ = NuitkaDetector.detect(&context);
    let _ = NuitkaPass.run(&artifact);
    let _ = NuitkaPass.extract_children(&artifact);
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
fn every_unmutated_seed_including_the_deeply_nested_c_body_finishes() {
    let scratch: Scratch = Scratch::create(&std::env::temp_dir());
    for entry in corpus() {
        let mut rng: XorShift64 = XorShift64::new(PROBE_DOMAIN);
        probe(entry.bytes(), &scratch, &mut rng);
    }
}
