use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_pass_py_deob::{
    ast_eval, auto_deobfuscate, cleanup_source, decode_hyperion_v2v3_inner,
    decode_hyperion_v2v3_inner_with_version, detect, detect_hyperion_v2v3, detect_marshal,
    format_python, iter_passes, looks_obfuscated, peel, peel_hyperion_v2v3_all_layers,
    peel_hyperion_v2v3_layer, peel_with_pyver, recover_marshal_source, recover_pyc_zipper,
    unidentified_guidance,
};
use disrobe_py_marshal::PyVersion;

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_CASES: usize = 32;
const MUTATIONS_PER_SEED: usize = 8;
const CASES_PER_BATCH: usize = 8;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const BATCH_BUDGET: Duration = Duration::from_secs(4);
const TEST_BUDGET: Duration = Duration::from_secs(45);
const BATCH_PATH_ENV: &str = "DISROBE_PY_DEOB_FUZZ_BATCH";
const WORKSPACE_PATH_ENV: &str = "DISROBE_PY_DEOB_FUZZ_WORKSPACE";
const WORKER_TOKEN_ENV: &str = "DISROBE_PY_DEOB_FUZZ_TOKEN";
const WORKER_TOKEN_FILE: &str = "worker-token";
const PROGRESS_FILE: &str = "case-progress";
const COMPLETION_FILE: &str = "worker-complete";

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

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = manifest_dir.parent().and_then(Path::parent) else {
        return PathBuf::new();
    };
    workspace_root
        .join("corpus")
        .join("python")
        .join("obfuscators")
}

fn real_seed(path: &[&str]) -> std::io::Result<Vec<u8>> {
    let source_path: PathBuf = path
        .iter()
        .fold(corpus_root(), |root: PathBuf, part: &&str| root.join(part));
    let mut bytes: Vec<u8> = std::fs::read(source_path)?;
    bytes.truncate(MAX_INPUT_BYTES);
    Ok(bytes)
}

fn structured_seeds() -> std::io::Result<Vec<Vec<u8>>> {
    let mut pyc_header: Vec<u8> = vec![0u8; 16];
    pyc_header[..4].copy_from_slice(&[0x50, 0x0d, 0x0d, 0x0a]);
    Ok(vec![
        Vec::new(),
        b"print('fuzz')\n".to_vec(),
        b"exec(marshal.loads(b'\\xff\\xff\\xff\\xff'))\n".to_vec(),
        pyc_header,
        real_seed(&["berserker", "real_sample.py"])?,
        real_seed(&["blankobf", "real_edge_cases_3_8_r1.py"])?,
        real_seed(&["kramer", "gauntlet", "real_gauntlet_kramer.py"])?,
        real_seed(&["patchwork", "real_hello_world.py"])?,
    ])
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
            let length: usize = rng.next_usize(out.len());
            out.truncate(length);
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
                    *byte = 0;
                }
            }
        }
        _ => {
            let length: usize = rng.next_usize(MAX_INPUT_BYTES.saturating_add(1));
            let mut random: Vec<u8> = Vec::with_capacity(length);
            for _ in 0..length {
                random.push(rng.next_byte());
            }
            out = random;
        }
    }
    out
}

fn consume<T>(_: T) {}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, ObfuscatorCatalog, Pass};
    use disrobe_pass_py_deob::chain_detector::{PY_DEOB_PASS, PyDeobDetector};

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let detector: PyDeobDetector = PyDeobDetector;
    consume(Detector::detect(&detector, &context));
    consume(ObfuscatorCatalog::detect(&detector, &context));
    consume(PY_DEOB_PASS.run(&artifact));
    consume(PY_DEOB_PASS.extract_children(&artifact));
}

fn exercise_entrypoints(bytes: &[u8]) {
    let source: String = String::from_utf8_lossy(bytes).into_owned();
    consume(detect(bytes));
    consume(auto_deobfuscate(bytes, None));
    consume(looks_obfuscated(bytes));
    consume(unidentified_guidance(bytes));
    consume(peel(bytes));
    consume(peel_with_pyver(bytes, None));
    consume(detect_hyperion_v2v3(bytes));
    consume(peel_hyperion_v2v3_all_layers(bytes, 8));
    consume(peel_hyperion_v2v3_layer(bytes));
    consume(decode_hyperion_v2v3_inner(bytes));
    consume(decode_hyperion_v2v3_inner_with_version(
        bytes,
        PyVersion::PY311,
    ));
    consume(detect_marshal(bytes));
    consume(recover_marshal_source(bytes, None));
    consume(recover_pyc_zipper(bytes));
    consume(cleanup_source(&source));
    consume(ast_eval::evaluate_source(&source));
    consume(format_python(&source));
    consume(disrobe_pass_py_deob::obfuscators::kramer::try_recover_payload_bytes(bytes));
    let report: disrobe_pass_py_deob::obfuscators::pyminifier_variants::VariantReport =
        disrobe_pass_py_deob::obfuscators::pyminifier_variants::classify(&source);
    consume(
        disrobe_pass_py_deob::obfuscators::pyminifier_variants::decompress(&source, report.kind),
    );
    for pass in iter_passes() {
        consume(pass.detect(bytes));
        consume(pass.peel(bytes));
    }
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempWorkspace {
    path: PathBuf,
    retain: bool,
}

impl TempWorkspace {
    fn create() -> std::io::Result<Self> {
        for _ in 0..256 {
            let path: PathBuf = workspace_dir();
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        retain: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to create unique py-deob fuzz workspace",
        ))
    }

    fn child(&self, index: usize) -> std::io::Result<ChildWorkspace> {
        let path: PathBuf = self.path.join(format!("worker-{index}"));
        std::fs::create_dir(&path)?;
        let sequence: u64 = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let token: String = format!("{}-{index}-{sequence}", std::process::id());
        std::fs::write(path.join(WORKER_TOKEN_FILE), &token)?;
        Ok(ChildWorkspace { path, token })
    }

    const fn retain(&mut self) {
        self.retain = true;
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        if !self.retain {
            let _: std::io::Result<()> = std::fs::remove_dir_all(&self.path);
        }
    }
}

struct ChildWorkspace {
    path: PathBuf,
    token: String,
}

fn workspace_dir() -> PathBuf {
    let sequence: u64 = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "disrobe-py-deob-fuzz-{}-{sequence}",
        std::process::id()
    ))
}

fn build_cases() -> std::io::Result<Vec<Vec<u8>>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5059_4445_4f42_0009);
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for _ in 0..RANDOM_CASES {
        let length: usize = rng.next_usize(MAX_INPUT_BYTES.saturating_add(1));
        let mut bytes: Vec<u8> = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rng.next_byte());
        }
        cases.push(bytes);
    }
    let seeds: Vec<Vec<u8>> = structured_seeds()?;
    for seed in &seeds {
        cases.push(seed.clone());
    }
    for seed in &seeds {
        for _ in 0..MUTATIONS_PER_SEED {
            cases.push(mutate(seed, &mut rng));
        }
    }
    Ok(cases)
}

fn write_batch(path: &Path, cases: &[Vec<u8>]) -> std::io::Result<()> {
    let mut bytes: Vec<u8> = Vec::new();
    for case in cases {
        let length: u32 = u32::try_from(case.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "fuzz case length does not fit u32",
            )
        })?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(case);
    }
    std::fs::write(path, bytes)
}

fn read_batch(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let file: std::fs::File = std::fs::File::open(path)?;
    let max_batch_bytes: u64 = u64::try_from(MAX_BATCH_BYTES).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fuzz batch limit does not fit u64",
        )
    })?;
    let mut reader: std::io::Take<std::fs::File> = file.take(max_batch_bytes.saturating_add(1));
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
        let case_length: usize =
            usize::try_from(u32::from_le_bytes(length_bytes)).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fuzz batch length does not fit usize",
                )
            })?;
        if case_length > MAX_INPUT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fuzz batch case exceeds input limit",
            ));
        }
        let case_end: usize = length_end.checked_add(case_length).ok_or_else(|| {
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

fn worker_progress(workspace: &Path) -> String {
    let progress_path: PathBuf = workspace.join(PROGRESS_FILE);
    match std::fs::read_to_string(progress_path) {
        Ok(progress) if !progress.is_empty() => progress,
        Ok(_) | Err(_) => "no case progress recorded".to_owned(),
    }
}

fn verify_worker_completion(
    workspace: &ChildWorkspace,
    expected_case_count: usize,
) -> std::io::Result<()> {
    let completion_path: PathBuf = workspace.path.join(COMPLETION_FILE);
    let completion: String = std::fs::read_to_string(completion_path)?;
    let expected: String = format!("{}\n{expected_case_count}", workspace.token);
    if completion == expected {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "fuzz worker completion record did not match the batch",
    ))
}

fn run_batch(
    path: &Path,
    workspace: &ChildWorkspace,
    batch_index: usize,
    expected_case_count: usize,
    remaining_budget: Duration,
) -> std::io::Result<()> {
    let executable: PathBuf = std::env::current_exe()?;
    let batch_budget: Duration = BATCH_BUDGET.min(remaining_budget);
    let mut child: std::process::Child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "fuzz_resilience_worker",
            "--nocapture",
        ])
        .env(BATCH_PATH_ENV, path)
        .env(WORKSPACE_PATH_ENV, &workspace.path)
        .env(WORKER_TOKEN_ENV, &workspace.token)
        .env_remove("DISROBE_DEBUG")
        .env_remove("DISROBE_DEBUG_FORMAT")
        .env_remove("DISROBE_DEBUG_COLOR")
        .env_remove("DISROBE_PY_DEOB_DEBUG")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let started: Instant = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                verify_worker_completion(workspace, expected_case_count)?;
                return Ok(());
            }
            let progress: String = worker_progress(&workspace.path);
            return Err(std::io::Error::other(format!(
                "fuzz batch {batch_index} exited with {status} after {progress}"
            )));
        }
        if started.elapsed() > batch_budget {
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error),
            }
            let _: ExitStatus = child.wait()?;
            let progress: String = worker_progress(&workspace.path);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("fuzz batch {batch_index} exceeded {batch_budget:?} after {progress}"),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_bounded_child_batches(cases: &[Vec<u8>]) -> std::io::Result<()> {
    let started: Instant = Instant::now();
    let mut workspace: TempWorkspace = TempWorkspace::create()?;
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
        let result: std::io::Result<()> = run_batch(
            &batch_path,
            &child_workspace,
            batch_index,
            batch.len(),
            remaining_budget,
        );
        if let Err(error) = result {
            let retained_path: PathBuf = workspace.path.clone();
            workspace.retain();
            return Err(std::io::Error::other(format!(
                "fuzz batch {batch_index} retained at {}: {error}",
                retained_path.display()
            )));
        }
    }
    let elapsed: Duration = started.elapsed();
    if elapsed > TEST_BUDGET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("fuzz suite exceeded {TEST_BUDGET:?}: {elapsed:?}"),
        ));
    }
    Ok(())
}

#[test]
#[ignore = "runs only through the parent fuzz protocol"]
fn fuzz_resilience_worker() -> std::io::Result<()> {
    let batch_path: PathBuf = std::env::var_os(BATCH_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing fuzz worker batch path",
            )
        })?;
    let workspace: PathBuf = std::env::var_os(WORKSPACE_PATH_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing fuzz worker workspace",
            )
        })?;
    let token: String = std::env::var(WORKER_TOKEN_ENV).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing fuzz worker token",
        )
    })?;
    let token_path: PathBuf = workspace.join(WORKER_TOKEN_FILE);
    let expected_token: String = std::fs::read_to_string(token_path)?;
    if token != expected_token {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fuzz worker token did not match its workspace",
        ));
    }
    let cases: Vec<Vec<u8>> = read_batch(&batch_path)?;
    for (case_index, bytes) in cases.iter().enumerate() {
        let fingerprint: u64 = bytes
            .iter()
            .fold(0xcbf2_9ce4_8422_2325, |hash: u64, byte: &u8| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            });
        std::fs::write(
            workspace.join(PROGRESS_FILE),
            format!("case {case_index} ({fingerprint:016x})"),
        )?;
        exercise_entrypoints(bytes);
    }
    std::fs::write(
        workspace.join(COMPLETION_FILE),
        format!("{token}\n{}", cases.len()),
    )?;
    Ok(())
}

#[test]
fn bounded_public_py_deob_parse_entrypoints_accept_malformed_inputs_without_panicking()
-> std::io::Result<()> {
    let cases: Vec<Vec<u8>> = build_cases()?;
    run_bounded_child_batches(&cases)
}
