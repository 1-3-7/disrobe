#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_pass_pickle::{
    AnalysisOptions, Disassembly, PickleValue, Result, Session, VmTrace, analyze_all, analyze_deep,
    analyze_polyglot, analyze_safety, analyze_with_options, analyze_with_policy, detect_model,
    disassemble, execute, execute_full, extract_ml, looks_like_pickle, needs_memo_table,
    reconstruct, render_disasm, to_python,
};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_CASES: usize = 4_000;
const MUTATIONS_PER_SEED: usize = 2_000;
const CASES_PER_BATCH: usize = 2_048;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const BATCH_BUDGET: Duration = Duration::from_mins(1);
const TEST_BUDGET: Duration = Duration::from_mins(10);
const BATCH_PATH_ENV: &str = "DISROBE_PICKLE_FUZZ_BATCH";
const WORKSPACE_PATH_ENV: &str = "DISROBE_PICKLE_FUZZ_WORKSPACE";
const WORKER_TOKEN_ENV: &str = "DISROBE_PICKLE_FUZZ_TOKEN";
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

fn deeply_nested_value_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0x80, 0x02, b'N'];
    bytes.extend(std::iter::repeat_n(0x85, 1024));
    bytes.push(b'.');
    bytes
}

fn structured_seeds() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"\x80\x02K\x07.".to_vec(),
        b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01a\x94.".to_vec(),
        b"(lp0\nI1\naI2\na.".to_vec(),
        b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00}\x94.".to_vec(),
        b"]q\x00(K\x01K\x02K\x03e.".to_vec(),
        b"\x80\x03cbuiltins\nexec\nq\x00X\x04\x00\x00\x00pass\x85\x86.".to_vec(),
        b"\x80\x02}q\x00(U\x01aq\x01K\x01u.".to_vec(),
        b"c__main__\nfoo\n(t\x81.".to_vec(),
        b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94.".to_vec(),
        deeply_nested_value_seed(),
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

fn exercise_entrypoints(bytes: &[u8]) {
    consume(looks_like_pickle(bytes));
    consume(analyze_polyglot(bytes));
    consume(detect_model(bytes));
    consume(extract_ml(bytes));
    consume(analyze_all(bytes));

    let disassembly: Result<Disassembly> = disassemble(bytes);
    if let Ok(disassembly) = disassembly {
        consume(render_disasm(&disassembly));

        let trace: Result<VmTrace> = execute(&disassembly);
        if let Ok(trace) = trace {
            let options: AnalysisOptions = AnalysisOptions::default();
            consume(to_python(&trace.result));
            consume(analyze_safety(&trace));
            consume(analyze_deep(&trace));
            consume(analyze_with_options(&trace, &options));
            consume(analyze_with_policy(&trace, &options.policy));
            consume(needs_memo_table(&trace.result));
        }

        let full: Result<(VmTrace, BTreeMap<u64, PickleValue>)> = execute_full(&disassembly);
        if let Ok((trace, memo)) = full {
            consume(reconstruct(&trace.result, &memo, trace.root_memo_key));
        }

        let mut session: Session = Session::new();
        consume(session.run(&disassembly));
    }
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
            "unable to create unique pickle fuzz workspace",
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
        "disrobe-pickle-fuzz-{}-{sequence}",
        std::process::id()
    ))
}

fn build_cases() -> Vec<Vec<u8>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5049_434b_4c45_0010);
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for _ in 0..RANDOM_CASES {
        let length: usize = rng.next_usize(MAX_INPUT_BYTES.saturating_add(1));
        let mut bytes: Vec<u8> = Vec::with_capacity(length);
        for _ in 0..length {
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
        .env_remove("DISROBE_PICKLE_DEBUG")
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
fn bounded_public_pickle_parse_entrypoints_accept_malformed_inputs_without_panicking()
-> std::io::Result<()> {
    let cases: Vec<Vec<u8>> = build_cases();
    run_bounded_child_batches(&cases)
}
