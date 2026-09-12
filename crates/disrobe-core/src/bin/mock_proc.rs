#![deny(unreachable_pub)]
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

#[allow(
    clippy::print_stderr,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode): Option<&String> = args.first() else {
        eprintln!("mock_proc: no mode given");
        return ExitCode::from(2);
    };
    match mode.as_str() {
        "sleep" => mock_sleep(&args[1..]),
        "flood" => mock_flood(&args[1..]),
        "flood-both" => mock_flood_both(&args[1..]),
        "echo-stdin" => mock_echo_stdin(),
        "close-stdin" => ExitCode::SUCCESS,
        "stderr-exit" => mock_stderr_exit(&args[1..]),
        "echo-args" => mock_echo_args(&args[1..]),
        "spawn-marker-pipe" => mock_spawn_marker(&args[1..], true),
        "spawn-marker-null" => mock_spawn_marker(&args[1..], false),
        "write-marker" => mock_write_marker(&args[1..]),
        other => {
            eprintln!("mock_proc: unknown mode `{other}`");
            ExitCode::from(2)
        }
    }
}

fn mock_sleep(rest: &[String]) -> ExitCode {
    let secs: u64 = rest
        .first()
        .and_then(|s: &String| s.parse::<u64>().ok())
        .unwrap_or(60);
    std::thread::sleep(Duration::from_secs(secs));
    ExitCode::SUCCESS
}

fn mock_flood(rest: &[String]) -> ExitCode {
    let total: usize = rest
        .first()
        .and_then(|s: &String| s.parse::<usize>().ok())
        .unwrap_or(8 * 1024 * 1024);
    let chunk: Vec<u8> = vec![b'z'; 65536];
    let stdout: std::io::Stdout = std::io::stdout();
    let mut lock: std::io::StdoutLock<'_> = stdout.lock();
    let mut written: usize = 0;
    while written < total {
        let remaining: usize = total - written;
        let take: usize = remaining.min(chunk.len());
        if lock.write_all(&chunk[..take]).is_err() {
            return ExitCode::from(5);
        }
        written += take;
    }
    let _: std::io::Result<()> = lock.flush();
    ExitCode::SUCCESS
}

fn mock_flood_both(rest: &[String]) -> ExitCode {
    let Some(stdout_total): Option<usize> =
        rest.first().and_then(|value: &String| value.parse().ok())
    else {
        return ExitCode::from(2);
    };
    let Some(stderr_total): Option<usize> =
        rest.get(1).and_then(|value: &String| value.parse().ok())
    else {
        return ExitCode::from(2);
    };
    let stdout: std::io::Stdout = std::io::stdout();
    let stderr: std::io::Stderr = std::io::stderr();
    let mut stdout_lock: std::io::StdoutLock<'_> = stdout.lock();
    let mut stderr_lock: std::io::StderrLock<'_> = stderr.lock();
    let mut stdout_written: usize = 0;
    let mut stderr_written: usize = 0;
    let stdout_chunk: [u8; 1024] = [b'o'; 1024];
    let stderr_chunk: [u8; 1024] = [b'e'; 1024];
    while stdout_written < stdout_total || stderr_written < stderr_total {
        if stdout_written < stdout_total {
            let take: usize = (stdout_total - stdout_written).min(stdout_chunk.len());
            if stdout_lock.write_all(&stdout_chunk[..take]).is_err() {
                return ExitCode::from(5);
            }
            stdout_written += take;
        }
        if stderr_written < stderr_total {
            let take: usize = (stderr_total - stderr_written).min(stderr_chunk.len());
            if stderr_lock.write_all(&stderr_chunk[..take]).is_err() {
                return ExitCode::from(5);
            }
            stderr_written += take;
        }
    }
    ExitCode::SUCCESS
}

fn mock_echo_stdin() -> ExitCode {
    let mut input: Vec<u8> = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        return ExitCode::from(5);
    }
    if std::io::stdout().write_all(&input).is_err() {
        return ExitCode::from(5);
    }
    ExitCode::SUCCESS
}

fn mock_stderr_exit(rest: &[String]) -> ExitCode {
    let Some(code): Option<u8> = rest.first().and_then(|value: &String| value.parse().ok()) else {
        return ExitCode::from(2);
    };
    let Some(message): Option<&String> = rest.get(1) else {
        return ExitCode::from(2);
    };
    if std::io::stderr().write_all(message.as_bytes()).is_err() {
        return ExitCode::from(5);
    }
    ExitCode::from(code)
}

fn mock_echo_args(rest: &[String]) -> ExitCode {
    for arg in rest {
        println!("{arg}");
    }
    ExitCode::SUCCESS
}

fn mock_spawn_marker(rest: &[String], inherit_output: bool) -> ExitCode {
    let Some(marker): Option<&String> = rest.first() else {
        return ExitCode::from(2);
    };
    let Some(delay_millis): Option<&String> = rest.get(1) else {
        return ExitCode::from(2);
    };
    let current_exe: std::path::PathBuf = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return ExitCode::from(3),
    };
    let output: Stdio = if inherit_output {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let error: Stdio = if inherit_output {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    match Command::new(current_exe)
        .args(["write-marker", marker, delay_millis])
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(error)
        .spawn()
    {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(4),
    }
}

fn mock_write_marker(rest: &[String]) -> ExitCode {
    let Some(marker): Option<&String> = rest.first() else {
        return ExitCode::from(2);
    };
    let Some(delay_millis): Option<u64> = rest.get(1).and_then(|value: &String| value.parse().ok())
    else {
        return ExitCode::from(2);
    };
    std::thread::sleep(Duration::from_millis(delay_millis));
    match std::fs::write(Path::new(marker), b"descendant-finished") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(5),
    }
}
