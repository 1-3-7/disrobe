#![deny(unreachable_pub)]
use std::io::Write as _;
use std::process::ExitCode;
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
        "echo-args" => mock_echo_args(&args[1..]),
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
