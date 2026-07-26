use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_pass_webview::{
    CarveConfig, CarveReport, RecoveredAsset, Result, WebviewFamily, carve, carve_report,
    carve_with_config, detect_family,
};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_CASES: usize = 48;
const MUTATIONS_PER_SEED: usize = 24;
const CASES_PER_BATCH: usize = 16;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const MAX_BATCH_BYTES_U64: u64 = MAX_BATCH_BYTES as u64;
const BATCH_BUDGET: Duration = Duration::from_secs(5);
const TEST_BUDGET: Duration = Duration::from_secs(45);
const BATCH_PATH_ENV: &str = "DISROBE_WEBVIEW_FUZZ_BATCH";
const BATCH_INDEX_ENV: &str = "DISROBE_WEBVIEW_FUZZ_BATCH_INDEX";

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

fn asar_seed() -> Vec<u8> {
    let json: &[u8] = br#"{"files":{"index.html":{"size":2,"offset":"0"}}}"#;
    let json_len: u32 = json.len() as u32;
    let aligned: u32 = json_len.div_ceil(4) * 4;
    let payload_size: u32 = aligned + 4;
    let header_buf_len: u32 = payload_size + 4;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&header_buf_len.to_le_bytes());
    bytes.extend_from_slice(&payload_size.to_le_bytes());
    bytes.extend_from_slice(&json_len.to_le_bytes());
    bytes.extend_from_slice(json);
    bytes.extend(std::iter::repeat_n(0u8, (aligned - json_len) as usize));
    bytes.extend_from_slice(b"ok");
    bytes
}

fn structured_seeds() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        asar_seed(),
        b"tauri://localhost".to_vec(),
        b"wails://runtime".to_vec(),
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        b"{\"files\":\"truncated".to_vec(),
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
    let config: CarveConfig = CarveConfig {
        max_scan_candidates: rng.next_usize(64),
        max_depth: rng.next_usize(128),
        max_table_probes: rng.next_u64() % 100_000,
        ..CarveConfig::default()
    };

    let _: Option<WebviewFamily> = detect_family(bytes);
    let _: Result<Vec<RecoveredAsset>> = carve(bytes);
    let _: Result<CarveReport> = carve_report(bytes);
    let _: Result<CarveReport> = carve_with_config(bytes, &config);
}

fn build_cases() -> Vec<Vec<u8>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5745_4256_465A_0008);
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
            "unable to create unique webview fuzz workspace",
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
        "disrobe-webview-fuzz-{}-{sequence}",
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

fn confirm_batch_ran(path: &Path, batch_index: usize, expected: usize) -> std::io::Result<()> {
    let marker: PathBuf = path.with_extension("done");
    let recorded: String = std::fs::read_to_string(&marker).map_err(|error: std::io::Error| {
        std::io::Error::other(format!(
            "fuzz batch {batch_index} exited cleanly without recording a completion marker, so the worker never ran its cases: {error}"
        ))
    })?;
    let processed: usize = recorded.trim().parse().map_err(|_| {
        std::io::Error::other(format!(
            "fuzz batch {batch_index} recorded an unreadable case count `{recorded}`"
        ))
    })?;
    if processed != expected {
        return Err(std::io::Error::other(format!(
            "fuzz batch {batch_index} processed {processed} cases but the batch held {expected}"
        )));
    }
    Ok(())
}

fn run_batch(
    path: &Path,
    batch_index: usize,
    expected: usize,
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
        .env(BATCH_INDEX_ENV, batch_index.to_string())
        .stdout(Stdio::null())
        .spawn()?;
    let started: Instant = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return confirm_batch_ran(path, batch_index, expected);
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
#[ignore = "runs only through the parent fuzz protocol"]
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
        let mut rng: Xorshift64 = Xorshift64::new(0x5745_4256_465A_0008 ^ batch ^ index);
        exercise_entrypoints(bytes, &mut rng);
    }
    std::fs::write(
        Path::new(&batch_path).with_extension("done"),
        cases.len().to_string(),
    )?;
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
        run_batch(&batch_path, batch_index, batch.len(), remaining_budget)?;
    }
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed <= TEST_BUDGET,
        "bounded parser suite exceeded {TEST_BUDGET:?}: {elapsed:?}"
    );
    Ok(())
}
