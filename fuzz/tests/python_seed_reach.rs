use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use disrobe_fuzz::python_bytecode;
use disrobe_fuzz::seed_reach::{
    IsolatedReplayError, ReplayObservations, ReplayOptions, ReplayTarget, ReplayTrace,
    SeedContract, SeedReachError, SeedReplayFragment, TargetReplay, assemble_target_replay,
    replay_target, replay_target_seed, replay_target_with_options, run_isolated_replay,
};
use disrobe_py_marshal::{
    CaptureError, Captured, capture_observations, dump_reftable, load_with_reftable,
    pyversion_from_magic, read_pyc,
};

#[derive(Debug)]
struct AlternativeReferenceRouteReplay {
    capture: Captured<()>,
}

impl ReplayTrace for AlternativeReferenceRouteReplay {
    fn observations(&self) -> ReplayObservations<'_> {
        ReplayObservations::Python(self.capture.observations())
    }
}

fn replay_without_dump_reftable(
    data: &[u8],
) -> Result<AlternativeReferenceRouteReplay, CaptureError> {
    let capture: Captured<()> = capture_observations(|| {
        let Ok(file) = read_pyc(data) else {
            return;
        };
        let header_length: usize = file.header.header_len();
        let Some(body): Option<&[u8]> = data.get(header_length..) else {
            return;
        };
        let _ = load_with_reftable(body, file.header.version);
    })?;
    Ok(AlternativeReferenceRouteReplay { capture })
}

fn replay_without_pyc_route(data: &[u8]) -> Result<AlternativeReferenceRouteReplay, CaptureError> {
    let capture: Captured<()> = capture_observations(|| {
        let Some(magic_bytes): Option<&[u8]> = data.get(..4) else {
            return;
        };
        let magic: u32 = u32::from_le_bytes([
            magic_bytes[0],
            magic_bytes[1],
            magic_bytes[2],
            magic_bytes[3],
        ]);
        let Some(version) = pyversion_from_magic(magic) else {
            return;
        };
        let Some(body): Option<&[u8]> = data.get(version.pyc_header_len()..) else {
            return;
        };
        let _ = dump_reftable(body, version);
    })?;
    Ok(AlternativeReferenceRouteReplay { capture })
}

fn temporary_root() -> core::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let root: PathBuf =
        std::env::temp_dir().join(format!("disrobe-seed-reach-{}", std::process::id()));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn contract_text(source: &str, digest: &str, obligations: &str) -> String {
    format!(
        "schema = 3\n\n[[surface]]\ntarget = \"python_bytecode\"\nid = \"python.pyc.header\"\nentry_point = \"disrobe-py-marshal/src/pyc.rs::read_pyc\"\n\n[[seed]]\ntarget = \"python_bytecode\"\nsource = \"{source}\"\noffset = 0\nlength = 3\nsha256 = \"{digest}\"\n{obligations}"
    )
}

fn accepted_obligation(surface: &str) -> String {
    format!(
        "\n[[seed.obligation]]\nsurface = \"{surface}\"\noutcome = \"accepted\"\nminimum_bytes = 1\nminimum_items = 1\n"
    )
}

fn seed_replay_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_seed_replay"))
}

#[test]
fn committed_python_contract_replays_through_the_fuzz_exercise()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;

    let replay: TargetReplay = replay_target(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        python_bytecode::replay,
    )?;

    assert_eq!(replay.seed_count(), 2);
    assert_eq!(replay.satisfied_obligations(), 4);
    assert_eq!(replay.declared_obligations(), 4);
    assert_eq!(replay.positive_witnesses(), 3);
    assert_eq!(replay.expected_rejection_witnesses(), 1);
    assert_eq!(replay.canonical_trace_runs(), 2);
    Ok(())
}

#[test]
fn shuffled_parallel_replay_is_byte_identical_to_manifest_order()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let sequential: TargetReplay = replay_target_with_options(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        python_bytecode::replay,
        ReplayOptions {
            jobs: 1,
            order_seed: 0,
        },
    )?;
    let parallel: TargetReplay = replay_target_with_options(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        python_bytecode::replay,
        ReplayOptions {
            jobs: 4,
            order_seed: 0x5445_5354_0004,
        },
    )?;

    assert_eq!(sequential.canonical_json()?, parallel.canonical_json()?);
    Ok(())
}

#[test]
fn dropping_a_terminal_observation_fails_closed()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let first_json: serde_json::Value = serde_json::json!({
        "target": "python_bytecode",
        "manifest_index": 0,
        "replay": {
            "sha256": "94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb",
            "trace": [{
                "span": 0,
                "surface": "python.pyc.header",
                "entry_point": "disrobe-py-marshal/src/pyc.rs::read_pyc",
                "phase": "entered",
                "bytes_consumed": 0,
                "items": 0
            }]
        },
        "positive_witnesses": [],
        "expected_rejection_witnesses": [],
        "declared_obligations": 3
    });
    let second_json: serde_json::Value = serde_json::json!({
        "target": "python_bytecode",
        "manifest_index": 1,
        "replay": {
            "sha256": "f18590fc1a3bbbfb9b610044565038b27f6113f553bf47899a4c48d62d485444",
            "trace": []
        },
        "positive_witnesses": [],
        "expected_rejection_witnesses": [],
        "declared_obligations": 1
    });
    let first_bytes: Vec<u8> = serde_json::to_vec(&first_json)?;
    let second_bytes: Vec<u8> = serde_json::to_vec(&second_json)?;
    let first: SeedReplayFragment = SeedReplayFragment::from_json(&first_bytes)?;
    let second: SeedReplayFragment = SeedReplayFragment::from_json(&second_bytes)?;
    let result: Result<TargetReplay, SeedReachError> =
        assemble_target_replay(&contract, ReplayTarget::PythonBytecode, vec![first, second]);

    assert!(
        matches!(result, Err(SeedReachError::Invalid(message)) if message.contains("incomplete"))
    );
    Ok(())
}

#[test]
fn an_alternative_reference_route_cannot_satisfy_the_dump_reftable_obligation()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;

    let result: Result<TargetReplay, SeedReachError> = replay_target(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        replay_without_dump_reftable,
    );

    assert!(
        result.is_err(),
        "load_with_reftable impersonated the removed dump_reftable route"
    );
    Ok(())
}

#[test]
fn removing_the_pyc_route_cannot_keep_header_and_marshal_obligations()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;

    let result: Result<TargetReplay, SeedReachError> = replay_target(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        replay_without_pyc_route,
    );

    assert!(
        result.is_err(),
        "reference parsing replaced the removed pyc route"
    );
    Ok(())
}

#[test]
fn malformed_contracts_and_unavailable_seed_bytes_fail_closed()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let root: PathBuf = temporary_root()?;
    let contract_path: PathBuf = root.join("seed_reach.toml");
    let digest: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    let legacy_schema: String = contract_text(
        "corpus/missing.bin",
        digest,
        &accepted_obligation("python.pyc.header"),
    )
    .replacen("schema = 3", "schema = 2", 1);
    fs::write(&contract_path, legacy_schema)?;
    let legacy_result: Result<SeedContract, SeedReachError> = SeedContract::read(&contract_path);
    assert!(
        matches!(legacy_result, Err(SeedReachError::Invalid(message)) if message.contains("schema 2 is unsupported"))
    );

    let zero_obligations: String = contract_text("corpus/missing.bin", digest, "");
    fs::write(&contract_path, zero_obligations)?;
    let zero_result: Result<SeedContract, SeedReachError> = SeedContract::read(&contract_path);
    assert!(
        matches!(zero_result, Err(SeedReachError::Invalid(message)) if message.contains("zero obligations"))
    );

    let unknown_obligation: String = accepted_obligation("python.unknown");
    fs::write(
        &contract_path,
        contract_text("corpus/missing.bin", digest, &unknown_obligation),
    )?;
    let unknown_result: Result<SeedContract, SeedReachError> = SeedContract::read(&contract_path);
    assert!(
        matches!(unknown_result, Err(SeedReachError::Invalid(message)) if message.contains("unknown surface"))
    );

    let unknown_entry_point: String = contract_text(
        "corpus/missing.bin",
        digest,
        &accepted_obligation("python.pyc.header"),
    )
    .replace(
        "disrobe-py-marshal/src/pyc.rs::read_pyc",
        "disrobe-py-marshal/src/pyc.rs::unknown",
    );
    fs::write(&contract_path, unknown_entry_point)?;
    let unknown_entry_result: Result<SeedContract, SeedReachError> =
        SeedContract::read(&contract_path);
    assert!(matches!(
        unknown_entry_result,
        Err(SeedReachError::Parse(_))
    ));

    let cross_target_entry_point: String = contract_text(
        "corpus/missing.bin",
        digest,
        &accepted_obligation("python.pyc.header"),
    )
    .replace(
        "disrobe-py-marshal/src/pyc.rs::read_pyc",
        "disrobe-pass-jvm/src/classfile.rs::parse",
    );
    fs::write(&contract_path, cross_target_entry_point)?;
    let cross_target_result: Result<SeedContract, SeedReachError> =
        SeedContract::read(&contract_path);
    assert!(
        matches!(cross_target_result, Err(SeedReachError::Invalid(message)) if message.contains("does not belong to target"))
    );

    let obligation: String = accepted_obligation("python.pyc.header");
    let duplicate_obligation: String = format!("{obligation}{obligation}");
    fs::write(
        &contract_path,
        contract_text("corpus/missing.bin", digest, &duplicate_obligation),
    )?;
    let duplicate_obligation_result: Result<SeedContract, SeedReachError> =
        SeedContract::read(&contract_path);
    assert!(
        matches!(duplicate_obligation_result, Err(SeedReachError::Invalid(message)) if message.contains("repeats its"))
    );

    let seed: String = contract_text("corpus/missing.bin", digest, &obligation);
    let duplicate_seed: String = seed
        .split_once("[[seed]]")
        .map_or_else(String::new, |(_, suffix): (&str, &str)| {
            format!("{seed}\n[[seed]]{suffix}")
        });
    fs::write(&contract_path, duplicate_seed)?;
    let duplicate_seed_result: Result<SeedContract, SeedReachError> =
        SeedContract::read(&contract_path);
    assert!(
        matches!(duplicate_seed_result, Err(SeedReachError::Invalid(message)) if message.contains("repeats seed"))
    );

    fs::write(&contract_path, &seed)?;
    let missing_contract: SeedContract = SeedContract::read(&contract_path)?;
    let missing_result: Result<TargetReplay, SeedReachError> = replay_target(
        &root,
        &missing_contract,
        ReplayTarget::PythonBytecode,
        python_bytecode::replay,
    );
    assert!(matches!(missing_result, Err(SeedReachError::Io { .. })));

    let corpus: PathBuf = root.join("corpus");
    fs::create_dir_all(&corpus)?;
    fs::write(corpus.join("stale.bin"), b"abc")?;
    fs::write(
        &contract_path,
        contract_text("corpus/stale.bin", digest, &obligation),
    )?;
    let stale_contract: SeedContract = SeedContract::read(&contract_path)?;
    let stale_result: Result<TargetReplay, SeedReachError> = replay_target(
        &root,
        &stale_contract,
        ReplayTarget::PythonBytecode,
        python_bytecode::replay,
    );
    assert!(
        matches!(stale_result, Err(SeedReachError::Invalid(message)) if message.contains("stale"))
    );

    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn isolated_worker_failures_return_without_crashing_or_hanging_the_parent()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let executable: PathBuf = std::env::current_exe()?;
    let panic_args: Vec<OsString> = [
        "--ignored",
        "--exact",
        "isolated_panic_worker",
        "--nocapture",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let panic_result: Result<Vec<u8>, IsolatedReplayError> =
        run_isolated_replay(&executable, &panic_args, Duration::from_secs(5));
    assert!(matches!(
        panic_result,
        Err(IsolatedReplayError::Failed { .. })
    ));

    let timeout_args: Vec<OsString> = [
        "--ignored",
        "--exact",
        "isolated_timeout_worker",
        "--nocapture",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let timeout_result: Result<Vec<u8>, IsolatedReplayError> =
        run_isolated_replay(&executable, &timeout_args, Duration::from_millis(100));
    assert!(matches!(
        timeout_result,
        Err(IsolatedReplayError::Timeout { .. })
    ));
    Ok(())
}

#[test]
fn replay_worker_executes_exactly_one_manifest_index_and_validates_the_contract_digest()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let output: Output = Command::new(seed_replay_binary())
        .args([
            "--worker",
            "--manifest-index",
            "0",
            "--contract-sha256",
            contract.sha256(),
        ])
        .stdin(Stdio::null())
        .output()?;

    assert!(output.status.success());
    let fragment: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(fragment["manifest_index"], 0);
    Ok(())
}

#[test]
fn parent_rejects_missing_duplicate_and_invalid_child_fragments()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let first: SeedReplayFragment = replay_target_seed(
        workspace_root,
        &contract,
        ReplayTarget::PythonBytecode,
        0,
        python_bytecode::replay,
    )?;

    let missing: Result<TargetReplay, SeedReachError> =
        assemble_target_replay(&contract, ReplayTarget::PythonBytecode, vec![first.clone()]);
    assert!(matches!(missing, Err(SeedReachError::Invalid(message)) if message.contains("1 of 2")));

    let duplicate: Result<TargetReplay, SeedReachError> = assemble_target_replay(
        &contract,
        ReplayTarget::PythonBytecode,
        vec![first.clone(), first],
    );
    assert!(
        matches!(duplicate, Err(SeedReachError::Invalid(message)) if message.contains("duplicate, missing, or foreign"))
    );

    assert!(SeedReplayFragment::from_json(b"{").is_err());
    Ok(())
}

#[test]
fn replay_worker_rejects_a_stale_parent_contract_digest()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let output: Output = Command::new(seed_replay_binary())
        .args([
            "--worker",
            "--manifest-index",
            "0",
            "--contract-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .stdin(Stdio::null())
        .output()?;

    assert!(!output.status.success());
    let stderr: String = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("does not match requested"));
    Ok(())
}

#[test]
fn workflow_requires_the_linux_memory_limiter_for_seed_replay() {
    let workflow: &str = include_str!("../../.github/workflows/fuzz.yml");
    assert!(workflow.contains("command -v prlimit"));
    assert!(workflow.contains("--memory-limit-bytes"));
    assert!(workflow.contains("needs: seed-reach"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn requested_os_memory_limit_fails_closed_off_linux()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report: PathBuf = fuzz_root
        .parent()
        .ok_or("the fuzz manifest has no workspace parent")?
        .join("xtask")
        .join("data")
        .join("fuzz_seed_reach.json");
    let output: Output = Command::new(seed_replay_binary())
        .args([
            "--memory-limit-bytes",
            "1048576",
            "--check",
            report.to_str().ok_or("the report path is not UTF-8")?,
        ])
        .stdin(Stdio::null())
        .output()?;

    assert!(!output.status.success());
    let stderr: String = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("requires Linux prlimit"));
    Ok(())
}

#[test]
#[ignore]
fn isolated_panic_worker() {
    panic!("controlled replay worker failure");
}

#[test]
#[ignore]
fn isolated_timeout_worker() {
    std::thread::park();
}
