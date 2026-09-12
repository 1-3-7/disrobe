use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_fuzz::seed_reach::{
    ReplayTarget, SeedContract, SeedReachReport, SeedReplayFragment, TargetReplay,
    assemble_contract_replay, replay_target_seed, run_isolated_replay,
};
use disrobe_fuzz::{cil_metadata, dex_jvm_classfile, python_bytecode};

const SHUFFLE_SEED: u64 = 0x5445_5354_0004;

type WorkerResult = Result<SeedReplayFragment, String>;

#[derive(Debug)]
enum OutputMode {
    Stdout,
    Write(PathBuf),
    Check(PathBuf),
}

#[derive(Debug)]
enum Mode {
    Parent {
        output: OutputMode,
        memory_limit_bytes: Option<u64>,
    },
    Worker {
        manifest_index: usize,
        contract_sha256: String,
    },
}

fn main() -> core::result::Result<(), Box<dyn std::error::Error>> {
    let mode: Mode = parse_mode()?;
    match mode {
        Mode::Worker {
            manifest_index,
            contract_sha256,
        } => run_worker(manifest_index, &contract_sha256),
        Mode::Parent {
            output,
            memory_limit_bytes,
        } => run_parent(output, memory_limit_bytes),
    }
}

fn parse_mode() -> core::result::Result<Mode, Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => Ok(Mode::Parent {
            output: OutputMode::Stdout,
            memory_limit_bytes: None,
        }),
        [flag, path] if flag == "--write" => Ok(Mode::Parent {
            output: OutputMode::Write(PathBuf::from(path)),
            memory_limit_bytes: None,
        }),
        [flag, path] if flag == "--check" => Ok(Mode::Parent {
            output: OutputMode::Check(PathBuf::from(path)),
            memory_limit_bytes: None,
        }),
        [limit_flag, limit, output_flag, path] if limit_flag == "--memory-limit-bytes" => {
            let memory_limit_bytes: u64 = limit.parse::<u64>()?;
            if memory_limit_bytes == 0 {
                return Err("--memory-limit-bytes must be greater than zero".into());
            }
            let output: OutputMode = match output_flag.as_str() {
                "--write" => OutputMode::Write(PathBuf::from(path)),
                "--check" => OutputMode::Check(PathBuf::from(path)),
                _ => return Err(usage().into()),
            };
            Ok(Mode::Parent {
                output,
                memory_limit_bytes: Some(memory_limit_bytes),
            })
        }
        [worker, index_flag, index, digest_flag, digest]
            if worker == "--worker"
                && index_flag == "--manifest-index"
                && digest_flag == "--contract-sha256" =>
        {
            Ok(Mode::Worker {
                manifest_index: index.parse::<usize>()?,
                contract_sha256: digest.clone(),
            })
        }
        _ => Err(usage().into()),
    }
}

fn usage() -> &'static str {
    "usage: seed_replay [--memory-limit-bytes <bytes>] [--write <path> | --check <path>]"
}

fn workspace_root() -> core::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    Ok(root.to_path_buf())
}

fn read_contract(root: &Path) -> core::result::Result<SeedContract, Box<dyn std::error::Error>> {
    Ok(SeedContract::read(
        &root.join("fuzz").join("seed_reach.toml"),
    )?)
}

fn run_worker(
    manifest_index: usize,
    expected_contract_sha256: &str,
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    let root: PathBuf = workspace_root()?;
    let contract: SeedContract = read_contract(&root)?;
    if contract.sha256() != expected_contract_sha256 {
        return Err(format!(
            "seed-reach contract digest {} does not match requested {expected_contract_sha256}",
            contract.sha256()
        )
        .into());
    }
    let target: ReplayTarget = contract.manifest_target(manifest_index)?;
    let fragment: SeedReplayFragment = match target {
        ReplayTarget::PythonBytecode => replay_target_seed(
            &root,
            &contract,
            target,
            manifest_index,
            python_bytecode::replay,
        )?,
        ReplayTarget::DexJvmClassfile => replay_target_seed(
            &root,
            &contract,
            target,
            manifest_index,
            dex_jvm_classfile::replay,
        )?,
        ReplayTarget::CilMetadata => replay_target_seed(
            &root,
            &contract,
            target,
            manifest_index,
            cil_metadata::replay,
        )?,
    };
    print!("{}", fragment.canonical_json()?);
    Ok(())
}

fn run_parent(
    output: OutputMode,
    memory_limit_bytes: Option<u64>,
) -> core::result::Result<(), Box<dyn std::error::Error>> {
    if memory_limit_bytes.is_some() && !cfg!(target_os = "linux") {
        return Err("--memory-limit-bytes requires Linux prlimit".into());
    }
    let root: PathBuf = workspace_root()?;
    let contract: SeedContract = read_contract(&root)?;
    let executable: PathBuf = std::env::current_exe()?;
    let timeout: Duration = Duration::from_secs(u64::from(disrobe_fuzz::PER_INPUT_TIMEOUT_SECONDS));
    let sequential_targets: Vec<TargetReplay> =
        replay_isolated_contract(&executable, &contract, 1, 0, timeout, memory_limit_bytes)?;
    let parallel_targets: Vec<TargetReplay> = replay_isolated_contract(
        &executable,
        &contract,
        4,
        SHUFFLE_SEED,
        timeout,
        memory_limit_bytes,
    )?;
    let sequential: SeedReachReport = SeedReachReport::new(&contract, sequential_targets)?;
    let parallel: SeedReachReport = SeedReachReport::new(&contract, parallel_targets)?;
    if sequential.canonical_json()? != parallel.canonical_json()? {
        return Err("one-worker and four-worker replay reports differ".into());
    }
    let rendered: String = sequential.canonical_json()?;
    match output {
        OutputMode::Stdout => print!("{rendered}"),
        OutputMode::Write(path) => fs::write(path, rendered.as_bytes())?,
        OutputMode::Check(path) => {
            let committed: String = fs::read_to_string(&path)?;
            if committed != rendered {
                return Err(format!("{} differs from deterministic replay", path.display()).into());
            }
        }
    }
    Ok(())
}

fn replay_isolated_contract(
    executable: &Path,
    contract: &SeedContract,
    jobs: usize,
    order_seed: u64,
    timeout: Duration,
    memory_limit_bytes: Option<u64>,
) -> core::result::Result<Vec<TargetReplay>, Box<dyn std::error::Error>> {
    if jobs == 0 {
        return Err("isolated replay requires at least one worker".into());
    }
    let seed_count: usize = contract.seed_count();
    if seed_count == 0 {
        return Err("the contract has no seeds".into());
    }
    let mut scheduled: Vec<usize> = (0..seed_count).collect();
    shuffle_indices(&mut scheduled, order_seed);
    let workers: usize = jobs.min(seed_count);
    let mut fragments: Vec<SeedReplayFragment> = Vec::with_capacity(seed_count);
    if workers == 1 {
        for manifest_index in scheduled {
            fragments.push(run_seed_worker(
                executable,
                contract.sha256(),
                manifest_index,
                timeout,
                memory_limit_bytes,
            )?);
        }
    } else {
        let (sender, receiver): (
            std::sync::mpsc::Sender<WorkerResult>,
            std::sync::mpsc::Receiver<WorkerResult>,
        ) = std::sync::mpsc::channel();
        std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
            for worker_index in 0..workers {
                let worker_sender: std::sync::mpsc::Sender<WorkerResult> = sender.clone();
                let worker_schedule: Vec<usize> = scheduled
                    .iter()
                    .copied()
                    .skip(worker_index)
                    .step_by(workers)
                    .collect();
                scope.spawn(move || {
                    for manifest_index in worker_schedule {
                        let result: WorkerResult = run_seed_worker(
                            executable,
                            contract.sha256(),
                            manifest_index,
                            timeout,
                            memory_limit_bytes,
                        )
                        .map_err(|error: Box<dyn std::error::Error>| error.to_string());
                        if worker_sender.send(result).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        drop(sender);
        for result in receiver {
            fragments.push(
                result.map_err(|error: String| -> Box<dyn std::error::Error> { error.into() })?,
            );
        }
    }
    Ok(assemble_contract_replay(contract, fragments)?)
}

fn run_seed_worker(
    executable: &Path,
    contract_sha256: &str,
    manifest_index: usize,
    timeout: Duration,
    memory_limit_bytes: Option<u64>,
) -> core::result::Result<SeedReplayFragment, Box<dyn std::error::Error>> {
    let worker_args: Vec<OsString> = vec![
        OsString::from("--worker"),
        OsString::from("--manifest-index"),
        OsString::from(manifest_index.to_string()),
        OsString::from("--contract-sha256"),
        OsString::from(contract_sha256),
    ];
    let (program, args): (PathBuf, Vec<OsString>) =
        limited_worker_command(executable, &worker_args, memory_limit_bytes)?;
    let captured: Vec<u8> = run_isolated_replay(&program, &args, timeout)?;
    Ok(SeedReplayFragment::from_json(&captured)?)
}

fn limited_worker_command(
    executable: &Path,
    worker_args: &[OsString],
    memory_limit_bytes: Option<u64>,
) -> core::result::Result<(PathBuf, Vec<OsString>), Box<dyn std::error::Error>> {
    let Some(limit): Option<u64> = memory_limit_bytes else {
        return Ok((executable.to_path_buf(), worker_args.to_vec()));
    };
    if !cfg!(target_os = "linux") {
        return Err("--memory-limit-bytes requires Linux prlimit".into());
    }
    let mut args: Vec<OsString> = Vec::with_capacity(worker_args.len().saturating_add(3));
    args.push(OsString::from(format!("--as={limit}")));
    args.push(OsString::from("--"));
    args.push(executable.as_os_str().to_owned());
    args.extend_from_slice(worker_args);
    Ok((PathBuf::from("prlimit"), args))
}

fn shuffle_indices(values: &mut [usize], seed: u64) {
    if seed == 0 {
        return;
    }
    let mut state: u64 = seed;
    for index in (1..values.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let modulus: u64 =
            u64::try_from(index.saturating_add(1)).map_or(u64::MAX, |value: u64| value);
        let selected: usize = usize::try_from(state % modulus).map_or(0, |value: usize| value);
        values.swap(index, selected);
    }
}
