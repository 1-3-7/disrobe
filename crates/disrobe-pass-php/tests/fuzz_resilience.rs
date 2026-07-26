use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_pass_php::bcompiler;
use disrobe_pass_php::decompile;
use disrobe_pass_php::encoder;
use disrobe_pass_php::protectors;
use disrobe_pass_php::{
    AesOutcome, AuthorizationToken, ContainerSurface, EncoderFamily, KeyScan, LoaderReport,
    OpArray, PeelOptions, PeelReport, PharArchive, PhpDetection, RecoveryReport, Result, build_cfg,
    decompile_oparray, deflatten, detect_php, extract_phar_entry, format_php, parse_oparray,
    parse_phar, peel_eval_chain, peel_modern_loader, recover_php, restructure,
    reverse_ioncube_container, reverse_sourceguardian_container, scan_key, signature_scan,
    surface_zend_guard, synthetic_transport_surface_ioncube,
    synthetic_transport_surface_sourceguardian, tokenize,
};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_CASES: usize = 48;
const MUTATIONS_PER_SEED: usize = 16;
const CASES_PER_BATCH: usize = 16;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const MAX_BATCH_BYTES_U64: u64 = MAX_BATCH_BYTES as u64;
const BATCH_BUDGET: Duration = Duration::from_secs(5);
const TEST_BUDGET: Duration = Duration::from_secs(45);
const BATCH_PATH_ENV: &str = "DISROBE_PHP_FUZZ_BATCH";
const BATCH_INDEX_ENV: &str = "DISROBE_PHP_FUZZ_BATCH_INDEX";

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

fn phar_seed() -> Vec<u8> {
    let mut manifest: Vec<u8> = Vec::new();
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0x0011u16.to_be_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    manifest.extend_from_slice(&0u32.to_le_bytes());
    let mut bytes: Vec<u8> = b"<?php __HALT_COMPILER(); ?>".to_vec();
    bytes.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&manifest);
    bytes
}

fn bcg_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = b"BCG\x00".to_vec();
    bytes.push(8);
    bytes.push(0);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes
}

fn structured_seeds() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        include_bytes!("fixtures/php_real_chains/clean_control.php").to_vec(),
        include_bytes!("fixtures/php_real_chains/s_doubleb64.php").to_vec(),
        include_bytes!("fixtures/protector_oparray/hello.dzoa").to_vec(),
        phar_seed(),
        bcg_seed(),
        b"<?php //004F\nAAAA\n".to_vec(),
        b"<?php sg_load('AAAA');\n".to_vec(),
        b"<?php @Zend;\n3\x00Zk3yZk3ypayload".to_vec(),
    ]
}

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed[..seed.len().min(MAX_INPUT_BYTES)].to_vec();
    match rng.next_u64() % 7 {
        0 => {
            let index: usize = rng.next_usize(out.len());
            if let Some(byte) = out.get_mut(index) {
                *byte ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => out.truncate(rng.next_usize(out.len())),
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
            let additions: usize = rng.next_usize(64);
            for _ in 0..additions {
                if out.len() == MAX_INPUT_BYTES {
                    break;
                }
                out.push(rng.next_byte());
            }
        }
        5 => {
            for byte in &mut out {
                if rng.next_u64().trailing_zeros() >= 3 {
                    *byte = b'\n';
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

fn exercise_entrypoints(bytes: &[u8], rng: &mut Xorshift64) {
    let authorization: Option<AuthorizationToken> = Some(AuthorizationToken::user_attested());
    let mut iv: [u8; 16] = [0u8; 16];
    for byte in &mut iv {
        *byte = rng.next_byte();
    }

    let _: Result<bcompiler::BcgHeader> = bcompiler::read_header(bytes);
    let parsed_oparray: Result<OpArray> = parse_oparray(bytes);
    if let Ok(oparray) = parsed_oparray {
        let _: disrobe_pass_php::Cfg = build_cfg(&oparray.ops);
        let _: disrobe_pass_php::Decompilation = decompile_oparray(&oparray);
    }
    let _: Result<OpArray> = decompile::parse_oparray(bytes);
    let _: PhpDetection = detect_php(bytes);
    let _: Result<disrobe_pass_php::DeflattenReport> = deflatten(bytes);
    let _: Result<disrobe_pass_php::RestructureReport> = restructure(bytes);
    let _: Result<Vec<disrobe_pass_php::Token<'_>>> = tokenize(bytes);
    let _: disrobe_pass_php::ScanReport = signature_scan(bytes);
    let _: Option<LoaderReport> = peel_modern_loader(bytes, rng.next_u64() as u32);
    let _: Result<PeelReport> = peel_eval_chain(bytes, PeelOptions::default());
    let _: Result<RecoveryReport> = recover_php(bytes, authorization);
    let _: String = format_php(&String::from_utf8_lossy(bytes));

    for family in [
        EncoderFamily::IonCube,
        EncoderFamily::SourceGuardian,
        EncoderFamily::ZendGuard,
    ] {
        let _: KeyScan = scan_key(bytes, family);
    }
    let _: Vec<u8> = disrobe_pass_php::xor_decrypt(bytes, b"fuzz-key");
    let _: AesOutcome = disrobe_pass_php::aes_cbc_decrypt(bytes, b"0123456789abcdef", &iv);

    let _: Option<encoder::EncoderDetection> = encoder::ioncube::detect(bytes);
    let _: Option<encoder::EncoderDetection> = encoder::sourceguardian::detect(bytes);
    let _: Option<encoder::EncoderDetection> = encoder::zend_guard::detect(bytes);
    let _: Result<encoder::DecodeOutcome> = encoder::ioncube::decode(bytes, authorization);
    let _: Result<encoder::DecodeOutcome> = encoder::sourceguardian::decode(bytes, authorization);
    let _: Result<encoder::DecodeOutcome> = encoder::zend_guard::decode(bytes, authorization);
    let _: Result<ContainerSurface> = reverse_ioncube_container(bytes, 0);
    let _: Result<ContainerSurface> = reverse_sourceguardian_container(bytes);
    let _: Result<ContainerSurface> = surface_zend_guard(bytes);
    let _: Result<ContainerSurface> = synthetic_transport_surface_ioncube(bytes, 0);
    let _: Result<ContainerSurface> = synthetic_transport_surface_sourceguardian(bytes);

    let _: Option<(protectors::ioncube::IonCubeEra, usize)> = protectors::ioncube::detect(bytes);
    let _: Option<usize> = protectors::ioncube::detect_loader_only(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::ioncube::analyze(bytes);
    let _: Option<(protectors::sourceguardian::SourceGuardianEra, usize)> =
        protectors::sourceguardian::detect(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::sourceguardian::analyze(bytes);
    let _: Option<(protectors::zend_guard::ZendGuardEra, usize, usize)> =
        protectors::zend_guard::detect(bytes);
    let _: Option<usize> = protectors::zend_guard::detect_loader_only(bytes);
    let _: Result<protectors::ProtectorDetection> = protectors::zend_guard::analyze(bytes);
    let _: Vec<String> = protectors::extract_envelope_strings(bytes, rng.next_usize(32));

    let parsed_phar: Result<PharArchive> = parse_phar(bytes);
    if let Ok(archive) = parsed_phar {
        let name: Option<&String> = archive.entries.keys().next();
        if let Some(name) = name {
            let _: Result<Vec<u8>> = extract_phar_entry(&archive, bytes, name);
        }
    }

    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
    use disrobe_pass_php::chain_detector::{PhpDetectorImpl, PhpPass};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let detector: PhpDetectorImpl = PhpDetectorImpl;
    let pass: PhpPass = PhpPass;
    let _: Option<DetectVerdict> = detector.detect(&context);
    let _: disrobe_core::error::Result<Artifact> = pass.run(&artifact);
    let _: disrobe_core::error::Result<Vec<disrobe_core::chain::ChildArtifact>> =
        pass.extract_children(&artifact);
}

fn build_cases() -> Vec<Vec<u8>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5048_505F_465A_0008);
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
            "unable to create unique php fuzz workspace",
        ))
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.path);
    }
}

fn workspace_dir() -> PathBuf {
    let sequence: u64 = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "disrobe-php-fuzz-{}-{sequence}",
        std::process::id()
    ))
}

fn write_batch(path: &Path, cases: &[Vec<u8>]) -> std::io::Result<()> {
    let mut file: std::fs::File = std::fs::File::create(path)?;
    for case in cases {
        let len: u32 = u32::try_from(case.len()).map_err(|_: std::num::TryFromIntError| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "fuzz case length does not fit u32",
            )
        })?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(case)?;
    }
    Ok(())
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
        let case_len: usize = usize::try_from(u32::from_le_bytes(length_bytes)).map_err(
            |_: std::num::TryFromIntError| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fuzz batch length does not fit usize",
                )
            },
        )?;
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

fn run_batch(path: &Path, batch_index: usize, remaining_budget: Duration) -> std::io::Result<()> {
    let executable: PathBuf = std::env::current_exe()?;
    let batch_budget: Duration = BATCH_BUDGET.min(remaining_budget);
    let mut child: std::process::Child = Command::new(executable)
        .args(["--exact", "fuzz_resilience_worker", "--nocapture"])
        .env(BATCH_PATH_ENV, path)
        .env(BATCH_INDEX_ENV, batch_index.to_string())
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
fn out_of_range_ioncube_marker_offsets_return_typed_errors() {
    let bytes: &[u8] = b"<?php //004F\n";
    let offset: usize = bytes.len().saturating_add(1);
    let reverse: Result<ContainerSurface> = reverse_ioncube_container(bytes, offset);
    let synthetic: Result<ContainerSurface> = synthetic_transport_surface_ioncube(bytes, offset);
    assert!(matches!(
        reverse,
        Err(disrobe_pass_php::Error::ContainerBadFraming {
            family: "ionCube",
            reason: "marker offset exceeds envelope length",
        })
    ));
    assert!(matches!(
        synthetic,
        Err(disrobe_pass_php::Error::ContainerBadFraming {
            family: "ionCube",
            reason: "marker offset exceeds envelope length",
        })
    ));
}

#[test]
fn fuzz_resilience_worker() -> std::io::Result<()> {
    let Some(batch_path): Option<std::ffi::OsString> = std::env::var_os(BATCH_PATH_ENV) else {
        return Ok(());
    };
    let cases: Vec<Vec<u8>> = read_batch(Path::new(&batch_path))?;
    let batch_index: Option<usize> = std::env::var(BATCH_INDEX_ENV)
        .ok()
        .and_then(|value: String| value.parse().ok());
    for (case_index, bytes) in cases.iter().enumerate() {
        let index: u64 = u64::try_from(case_index).map_or(0, |value: u64| value);
        let batch: u64 = batch_index.map_or(0, |value: usize| value as u64);
        let mut rng: Xorshift64 = Xorshift64::new(0x5048_505F_465A_0008 ^ batch ^ index);
        exercise_entrypoints(bytes, &mut rng);
    }
    Ok(())
}

#[test]
fn bounded_public_parse_entrypoints_finish_without_panicking() -> std::io::Result<()> {
    let started: Instant = Instant::now();
    let workspace: TempWorkspace = TempWorkspace::create()?;
    let cases: Vec<Vec<u8>> = build_cases();
    for (batch_index, batch) in cases.chunks(CASES_PER_BATCH).enumerate() {
        let remaining_budget: Duration =
            TEST_BUDGET.checked_sub(started.elapsed()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("fuzz suite exceeded {TEST_BUDGET:?}"),
                )
            })?;
        let batch_path: PathBuf = workspace.path.join(format!("batch-{batch_index}.bin"));
        write_batch(&batch_path, batch)?;
        run_batch(&batch_path, batch_index, remaining_budget)?;
    }
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed <= TEST_BUDGET,
        "bounded parser suite exceeded {TEST_BUDGET:?}: {elapsed:?}"
    );
    Ok(())
}
