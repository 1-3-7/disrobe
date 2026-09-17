#![deny(unsafe_code)]
#![deny(unreachable_pub)]
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use disrobe_ir::{Envelope, MmapView, WitnessSidecar, mmap_envelope_view};
use disrobe_transcode::{
    Transcoded, exact_transcode_witness, transcode_envelope, verify_transcode_envelope,
};

#[derive(Debug)]
struct Args {
    input: String,
    output: String,
    verify: bool,
}

fn parse_args() -> std::result::Result<Args, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(args: I) -> std::result::Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut positional: Vec<String> = Vec::with_capacity(2);
    let mut verify: bool = false;
    for arg in args {
        match arg.as_str() {
            "--verify" => verify = true,
            "-h" | "--help" => return Err(usage()),
            flag if flag.starts_with("--") => {
                return Err(format!("unknown flag: {flag}\n{}", usage()));
            }
            _ if positional.len() == 2 => {
                return Err(format!(
                    "expected <in.dr> <out.dr>, got at least 3 args\n{}",
                    usage()
                ));
            }
            _ => positional.push(arg),
        }
    }
    let [input, output]: [String; 2] = positional.try_into().map_err(|v: Vec<String>| {
        format!(
            "expected <in.dr> <out.dr>, got {} args\n{}",
            v.len(),
            usage()
        )
    })?;
    Ok(Args {
        input,
        output,
        verify,
    })
}

fn usage() -> String {
    "usage: disrobe-transcode <in.dr> <out.dr> [--verify]".to_owned()
}

fn witness_path(output: &Path) -> PathBuf {
    let mut path: OsString = output.as_os_str().to_owned();
    path.push(".witness");
    PathBuf::from(path)
}

fn sibling_path(path: &Path, role: &str, attempt: usize) -> PathBuf {
    let mut candidate: OsString = path.as_os_str().to_owned();
    candidate.push(format!(".disrobe-{role}-{}-{attempt}", std::process::id()));
    PathBuf::from(candidate)
}

fn reserve_sibling(path: &Path, role: &str) -> std::result::Result<(PathBuf, File), String> {
    for attempt in 0..128 {
        let candidate: PathBuf = sibling_path(path, role, attempt);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("stage {}: {error}", path.display())),
        }
    }
    Err(format!(
        "stage {}: no temporary sibling name is available",
        path.display()
    ))
}

fn stage_bytes(path: &Path, bytes: &[u8], role: &str) -> std::result::Result<PathBuf, String> {
    let (stage_path, mut stage_file): (PathBuf, File) = reserve_sibling(path, role)?;
    if let Err(error) = stage_file
        .write_all(bytes)
        .and_then(|()| stage_file.sync_all())
    {
        let cleanup: std::result::Result<(), std::io::Error> = std::fs::remove_file(&stage_path);
        return Err(match cleanup {
            Ok(()) => format!("stage {}: {error}", path.display()),
            Err(cleanup_error) => format!(
                "stage {}: {error}; remove {}: {cleanup_error}",
                path.display(),
                stage_path.display()
            ),
        });
    }
    Ok(stage_path)
}

fn validate_publication_target(path: &Path) -> std::result::Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(format!(
            "write {}: target exists and is not a regular file",
            path.display()
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect {}: {error}", path.display())),
    }
}

fn backup_existing(path: &Path) -> std::result::Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let (backup_path, backup_file): (PathBuf, File) = reserve_sibling(path, "backup")?;
    drop(backup_file);
    std::fs::remove_file(&backup_path)
        .map_err(|error| format!("prepare backup {}: {error}", backup_path.display()))?;
    std::fs::rename(path, &backup_path)
        .map_err(|error| format!("back up {}: {error}", path.display()))?;
    Ok(Some(backup_path))
}

fn restore_backup(path: &Path, backup: Option<&Path>) -> std::result::Result<(), String> {
    backup.map_or(Ok(()), |backup_path: &Path| {
        std::fs::rename(backup_path, path)
            .map_err(|error| format!("restore {}: {error}", path.display()))
    })
}

fn remove_if_present(path: &Path) -> std::result::Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn with_recovery<const N: usize>(
    primary: String,
    recoveries: [std::result::Result<(), String>; N],
) -> String {
    let recovery_errors: Vec<String> = recoveries
        .into_iter()
        .filter_map(std::result::Result::err)
        .collect();
    if recovery_errors.is_empty() {
        primary
    } else {
        format!("{primary}; recovery: {}", recovery_errors.join("; "))
    }
}

fn publish_pair(
    output_path: &Path,
    output_bytes: &[u8],
    witness_path: &Path,
    witness_bytes: &[u8],
) -> std::result::Result<(), String> {
    validate_publication_target(output_path)?;
    validate_publication_target(witness_path)?;
    let output_stage: PathBuf = stage_bytes(output_path, output_bytes, "output")?;
    let witness_stage: PathBuf = match stage_bytes(witness_path, witness_bytes, "witness") {
        Ok(path) => path,
        Err(error) => {
            return Err(with_recovery(error, [remove_if_present(&output_stage)]));
        }
    };
    let output_backup: Option<PathBuf> = match backup_existing(output_path) {
        Ok(backup) => backup,
        Err(error) => {
            return Err(with_recovery(
                error,
                [
                    remove_if_present(&output_stage),
                    remove_if_present(&witness_stage),
                ],
            ));
        }
    };
    let witness_backup: Option<PathBuf> = match backup_existing(witness_path) {
        Ok(backup) => backup,
        Err(error) => {
            return Err(with_recovery(
                error,
                [
                    restore_backup(output_path, output_backup.as_deref()),
                    remove_if_present(&output_stage),
                    remove_if_present(&witness_stage),
                ],
            ));
        }
    };
    if let Err(error) = std::fs::rename(&output_stage, output_path) {
        return Err(with_recovery(
            format!("publish {}: {error}", output_path.display()),
            [
                restore_backup(output_path, output_backup.as_deref()),
                restore_backup(witness_path, witness_backup.as_deref()),
                remove_if_present(&output_stage),
                remove_if_present(&witness_stage),
            ],
        ));
    }
    if let Err(error) = std::fs::rename(&witness_stage, witness_path) {
        return Err(with_recovery(
            format!("publish {}: {error}", witness_path.display()),
            [
                remove_if_present(output_path),
                restore_backup(output_path, output_backup.as_deref()),
                restore_backup(witness_path, witness_backup.as_deref()),
                remove_if_present(&witness_stage),
            ],
        ));
    }
    if let Some(path) = output_backup {
        remove_if_present(&path)?;
    }
    if let Some(path) = witness_backup {
        remove_if_present(&path)?;
    }
    Ok(())
}

fn run() -> std::result::Result<(), String> {
    let args: Args = parse_args()?;
    let input_view: MmapView =
        mmap_envelope_view(&args.input).map_err(|e| format!("read {}: {e}", args.input))?;
    let input_bytes: &[u8] = input_view.as_bytes();
    let input_env: Envelope =
        Envelope::decode(input_bytes).map_err(|e| format!("read {}: {e}", args.input))?;

    let transcoded: Transcoded =
        transcode_envelope(&input_env).map_err(|e| format!("transcode: {e}"))?;
    let witness: WitnessSidecar = exact_transcode_witness(input_bytes, &input_env, &transcoded)
        .map_err(|e| format!("witness: {e}"))?;
    let witness_bytes: Vec<u8> = witness
        .encode()
        .map_err(|e| format!("witness encode: {e}"))?;

    if args.verify {
        verify_transcode_envelope(&input_env, &transcoded)
            .map_err(|e| format!("verify failed: {e}"))?;
    }

    let witness_path: PathBuf = witness_path(Path::new(&args.output));
    publish_pair(
        Path::new(&args.output),
        &transcoded.bytes,
        &witness_path,
        &witness_bytes,
    )?;

    println!(
        "transcoded {} -> {} | witness={} | rung={:?} v{}->v{} hot {}B->{}B cold {}B{}",
        args.input,
        args.output,
        witness_path.display(),
        transcoded.rung,
        transcoded.source_version,
        transcoded.target_version,
        transcoded.old_hot_len,
        transcoded.new_hot_len,
        transcoded.cold_len,
        if args.verify { " [verified]" } else { "" },
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("disrobe-transcode: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value: &&str| (*value).to_owned())
            .collect()
    }

    #[test]
    fn parse_args_accepts_verify_after_paths() {
        let parsed: std::result::Result<Args, String> =
            parse_args_from(strings(&["in.dr", "out.dr", "--verify"]));
        assert!(parsed.is_ok(), "args parse failed: {parsed:?}");
        let args: Args = match parsed {
            Ok(args) => args,
            Err(_) => return,
        };
        assert_eq!(args.input, "in.dr");
        assert_eq!(args.output, "out.dr");
        assert!(args.verify);
    }

    #[test]
    fn parse_args_rejects_third_positional_immediately() {
        let parsed: std::result::Result<Args, String> =
            parse_args_from(strings(&["in.dr", "out.dr", "extra.dr"]));
        assert!(parsed.is_err(), "third positional parsed: {parsed:?}");
        let err: String = match parsed {
            Ok(_) => return,
            Err(err) => err,
        };
        assert!(err.contains("at least 3 args"));
    }

    #[test]
    fn recovery_reports_every_failed_action() {
        let recoveries: [std::result::Result<(), String>; 3] = [
            Err("remove output failed".to_owned()),
            Ok(()),
            Err("restore witness failed".to_owned()),
        ];
        assert_eq!(
            with_recovery("publish failed".to_owned(), recoveries),
            "publish failed; recovery: remove output failed; restore witness failed"
        );
    }
}
