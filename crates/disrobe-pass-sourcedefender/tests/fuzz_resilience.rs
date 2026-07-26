use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use disrobe_core::provenance::ProvenanceHeader;
use disrobe_pass_sourcedefender::{
    ContainerVariant, DecoratorStripReport, DecryptedPye, DerivedKey, InlinedBlock,
    InlinedExtractOptions, InlinedExtraction, LayeredRecovery, ModernGcmFraming,
    ParsedPyeArrayEnvelope, PyeEnvelope, PyeFrame, Result, SourceRecoverOpts, SourceRecoverOutput,
    apply_aes_ctr, ascii85_decode, base85_decode_rfc1924, basename_of, classify_container,
    decode_armored_line, decrypt_frame, decrypt_modern_gcm_with_key, decrypt_pye,
    decrypt_pye_to_source, decrypt_pye_with_key, derive_aes_key, extract_inlined,
    frame_modern_gcm_body, hex_decode, hex_encode, locate_inlined_blocks, parse_array_envelope,
    parse_msgpack_envelope, parse_pye_frame, python_decoded_header, recover_from_marshal_bytes,
    recover_from_plaintext, recover_layered, recover_layered_with_modern_key,
    render_decoded_with_header, strip_extension, strip_sourcedefender_decorators,
};

const MAX_INPUT_BYTES: usize = 4096;
const RANDOM_CASES: usize = 96;
const MUTATIONS_PER_SEED: usize = 32;
const CASES_PER_BATCH: usize = 16;
const MAX_BATCH_BYTES: usize = CASES_PER_BATCH * (MAX_INPUT_BYTES + 4);
const MAX_BATCH_BYTES_U64: u64 = 65_600;
const BATCH_BUDGET: Duration = Duration::from_secs(5);
const TEST_BUDGET: Duration = Duration::from_mins(1);
const BATCH_PATH_ENV: &str = "DISROBE_SOURCEDEFENDER_FUZZ_BATCH";
const BATCH_INDEX_ENV: &str = "DISROBE_SOURCEDEFENDER_FUZZ_BATCH_INDEX";

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

fn legacy_frame_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"--BEGIN SOURCEDEFENDER FILE---\n");
    bytes.extend_from_slice(b"invalid-iv-armor\n");
    bytes.extend_from_slice(b"00000000000000000000000000000000\n");
    bytes.extend_from_slice(b"---END SOURCEDEFENDER FILE----\n");
    bytes
}

fn modern_frame_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"--BEGIN PYE FILE---\n");
    bytes.extend_from_slice(b"00112233445566778899AABBCCDDEEFF\n");
    bytes.extend_from_slice(b"---END PYE FILE----\n");
    bytes
}

fn msgpack_map_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0xdf);
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    bytes
}

fn msgpack_array_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(0x91);
    bytes.push(0xc6);
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    bytes
}

fn msgpack_nesting_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend(std::iter::repeat_n(0x91u8, 96));
    bytes.push(0xc0);
    bytes
}

fn valid_msgpack_seed() -> Vec<u8> {
    let value: rmpv::Value = rmpv::Value::Map(vec![(
        rmpv::Value::String("original_code".into()),
        rmpv::Value::String("value = 1\n".into()),
    )]);
    let mut bytes: Vec<u8> = Vec::new();
    if rmpv::encode::write_value(&mut bytes, &value).is_err() {
        return Vec::new();
    }
    bytes
}

fn inlined_seed() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"__sd_filename__ = 'fuzz'\n");
    bytes.extend_from_slice(b"--BEGIN SOURCEDEFENDER FILE---\n");
    bytes.extend_from_slice(b"armored-but-invalid\n");
    bytes.extend_from_slice(b"---END SOURCEDEFENDER FILE----\n");
    bytes
}

fn structured_seeds() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        legacy_frame_seed(),
        modern_frame_seed(),
        msgpack_map_seed(),
        msgpack_array_seed(),
        msgpack_nesting_seed(),
        valid_msgpack_seed(),
        inlined_seed(),
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
        1 => {
            out.truncate(rng.next_usize(out.len()));
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

fn exercise_byte_entrypoints(bytes: &[u8], rng: &mut Xorshift64) {
    let mut key_bytes: [u8; 32] = [0u8; 32];
    for key_byte in &mut key_bytes {
        *key_byte = rng.next_byte();
    }
    let key: DerivedKey = DerivedKey(key_bytes);
    let options: SourceRecoverOpts = SourceRecoverOpts::default();
    let framing: ModernGcmFraming = frame_modern_gcm_body(bytes);
    let truncated: &[u8] = bytes
        .get(..bytes.len() / 2)
        .map_or(bytes, |slice: &[u8]| slice);

    let _: Result<Vec<u8>> = base85_decode_rfc1924(bytes);
    let _: Result<Vec<u8>> = ascii85_decode(bytes);
    let _: Result<Vec<u8>> = decode_armored_line(bytes);
    let _: Result<Vec<u8>> = hex_decode(bytes);
    let _: String = hex_encode(bytes);
    let _: Result<PyeEnvelope> = parse_msgpack_envelope(bytes);
    let _: Result<ParsedPyeArrayEnvelope> = parse_array_envelope(bytes);
    let _: Option<ContainerVariant> = classify_container(bytes);
    let _: Result<DecryptedPye> = decrypt_pye(bytes, "fuzz.pye");
    let _: Result<DecryptedPye> = decrypt_pye_with_key(bytes, "fuzz.pye", &key);
    let _: Result<Vec<u8>> = decrypt_modern_gcm_with_key(&framing, bytes, &key_bytes);
    let _: Result<Vec<u8>> = decrypt_modern_gcm_with_key(&framing, truncated, &key_bytes);
    let _: Result<LayeredRecovery> = recover_layered(bytes, "fuzz.pye");
    let _: Result<LayeredRecovery> = recover_layered_with_modern_key(bytes, "fuzz.pye", &key_bytes);
    let _: Result<SourceRecoverOutput> = decrypt_pye_to_source(bytes, "fuzz.pye", options);
    let _: Result<SourceRecoverOutput> = recover_from_plaintext(bytes, None, options);
    let _: Result<SourceRecoverOutput> = recover_from_marshal_bytes(bytes, None, None, options);

    if let Ok(text) = core::str::from_utf8(bytes) {
        let _: Result<disrobe_pass_sourcedefender::PyeFrame> = parse_pye_frame(text);
        let _: Result<Vec<InlinedBlock>> = locate_inlined_blocks(text);
        let _: Result<InlinedExtraction> =
            extract_inlined(text, "fuzz.py", InlinedExtractOptions::default());
        let _: Result<InlinedExtraction> = extract_inlined(
            text,
            "fuzz.py",
            InlinedExtractOptions {
                require_known_basename: true,
            },
        );
        let _: DecoratorStripReport = strip_sourcedefender_decorators(text);
        let _: &str = basename_of(text);
        let _: &str = strip_extension(text);
        let _: Result<DerivedKey> = derive_aes_key(text);
        let _: String = render_decoded_with_header(text, Duration::from_millis(1), "3.14");
        let _: ProvenanceHeader = python_decoded_header(Duration::from_millis(1), "3.14");
    }
}

fn exercise_constructed_decrypt_path() {
    let Some(key): Option<DerivedKey> = derive_aes_key("fuzz").ok() else {
        return;
    };
    let iv: [u8; 16] = [0xA5; 16];
    let mut ciphertext: Vec<u8> = valid_msgpack_seed();
    apply_aes_ctr(&mut ciphertext, key.as_bytes(), &iv);
    let frame: PyeFrame = PyeFrame { iv, ciphertext };
    let decrypted: DecryptedPye = decrypt_frame(&frame, &key, "fuzz.pye");
    assert!(decrypted.envelope.is_some());
    let recovered: Result<SourceRecoverOutput> = recover_from_plaintext(
        &decrypted.plaintext_msgpack,
        decrypted.envelope.as_ref(),
        SourceRecoverOpts::default(),
    );
    assert!(recovered.is_ok());
}

#[cfg(feature = "chain")]
fn exercise_chain_entrypoints(bytes: &[u8]) {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::{DetectContext, Detector, Pass};
    use disrobe_pass_sourcedefender::chain_detector::{
        SOURCEDEFENDER_PASS, SourceDefenderDetector,
    };

    let context: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let _: Option<disrobe_core::chain::DetectVerdict> = SourceDefenderDetector.detect(&context);
    let _: disrobe_core::error::Result<Artifact> = SOURCEDEFENDER_PASS.run(&artifact);
    let _: disrobe_core::error::Result<Artifact> =
        SOURCEDEFENDER_PASS.run_with_path(&artifact, Some("fuzz.pye"));
}

fn exercise_entrypoints(bytes: &[u8], rng: &mut Xorshift64) {
    exercise_byte_entrypoints(bytes, rng);
    #[cfg(feature = "chain")]
    exercise_chain_entrypoints(bytes);
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
            "unable to create unique sourcedefender fuzz workspace",
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
        "disrobe-sourcedefender-fuzz-{}-{sequence}",
        std::process::id()
    ))
}

fn build_cases() -> Vec<Vec<u8>> {
    let mut rng: Xorshift64 = Xorshift64::new(0x5344_465A_0001_0002);
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
    let mut file: std::fs::File = std::fs::File::create(path)?;
    for case in cases {
        let len: u32 = u32::try_from(case.len()).map_err(|_| {
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
        let case_len: usize = usize::try_from(u32::from_le_bytes(length_bytes)).map_err(|_| {
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
        .args(["--exact", "fuzz_resilience_worker", "--nocapture"])
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
fn fuzz_resilience_worker() -> std::io::Result<()> {
    let Some(batch_path): Option<std::ffi::OsString> = std::env::var_os(BATCH_PATH_ENV) else {
        return Ok(());
    };
    let cases: Vec<Vec<u8>> = read_batch(Path::new(&batch_path))?;
    let batch_index: Option<usize> = std::env::var(BATCH_INDEX_ENV)
        .ok()
        .and_then(|value: String| value.parse().ok());
    if batch_index == Some(0) {
        exercise_constructed_decrypt_path();
    }
    for (case_index, bytes) in cases.iter().enumerate() {
        let index: u64 = u64::try_from(case_index).map_or(0, |value: u64| value);
        let mut rng: Xorshift64 = Xorshift64::new(0x5344_465A_0001_0002 ^ index);
        exercise_entrypoints(bytes, &mut rng);
    }
    std::fs::write(
        Path::new(&batch_path).with_extension("done"),
        cases.len().to_string(),
    )?;
    Ok(())
}

#[test]
fn malformed_length_markers_return_errors() {
    let legacy: Vec<u8> = legacy_frame_seed();
    let map: Vec<u8> = msgpack_map_seed();
    let array: Vec<u8> = msgpack_array_seed();
    let options: SourceRecoverOpts = SourceRecoverOpts::default();

    assert!(decode_armored_line(b"").is_err());
    assert!(parse_pye_frame("").is_err());
    assert!(parse_msgpack_envelope(&map).is_err());
    assert!(parse_array_envelope(&array).is_err());
    assert!(decrypt_pye(&legacy, "fuzz.pye").is_err());
    assert!(recover_layered(&legacy, "fuzz.pye").is_err());
    assert!(recover_from_marshal_bytes(&[], None, None, options).is_err());
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
