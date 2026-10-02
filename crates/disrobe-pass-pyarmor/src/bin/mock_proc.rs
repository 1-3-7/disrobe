#![deny(unreachable_pub)]
use std::io::Write as _;
use std::process::ExitCode;
use std::time::Duration;

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode): Option<&String> = args.first() else {
        eprintln!("mock_proc: no mode given");
        return ExitCode::from(2);
    };
    match mode.as_str() {
        "sleep" => mock_sleep(&args[1..]),
        "flood" => mock_flood(&args[1..]),
        "echo-args" => mock_echo_args(&args[1..]),
        "orphan" => mock_orphan(&args[1..]),
        "late-marker" => mock_late_marker(&args[1..]),
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

fn mock_echo_args(rest: &[String]) -> ExitCode {
    for arg in rest {
        println!("{arg}");
    }
    ExitCode::SUCCESS
}

fn mock_orphan(rest: &[String]) -> ExitCode {
    let [marker, delay_ms, parent, ..] = rest else {
        eprintln!("mock_proc: orphan needs a marker path, a delay and exit or sleep");
        return ExitCode::from(2);
    };
    let Ok(exe) = std::env::current_exe() else {
        return ExitCode::from(3);
    };
    if std::process::Command::new(exe)
        .args(["late-marker", marker.as_str(), delay_ms.as_str()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_err()
    {
        return ExitCode::from(4);
    }
    match parent.as_str() {
        "sleep" => std::thread::sleep(Duration::from_mins(1)),
        "linger" => std::thread::sleep(Duration::from_secs(3)),
        _ => {}
    }
    ExitCode::SUCCESS
}

fn mock_late_marker(rest: &[String]) -> ExitCode {
    let [marker, delay_ms, ..] = rest else {
        return ExitCode::from(2);
    };
    let delay: u64 = delay_ms.parse::<u64>().unwrap_or(1_000);
    std::thread::sleep(Duration::from_millis(delay));
    match std::fs::write(marker, b"survived") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(5),
    }
}
