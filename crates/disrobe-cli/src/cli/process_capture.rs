use std::process::Child;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_CAPTURE_OUTPUT: usize = 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

#[derive(Debug)]
pub(crate) struct CapturedOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
) -> Option<CapturedOutput> {
    let stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>> = child
        .stdout
        .take()
        .map(|pipe: std::process::ChildStdout| std::thread::spawn(move || read_capped(pipe)));
    let stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>> = child
        .stderr
        .take()
        .map(|pipe: std::process::ChildStderr| std::thread::spawn(move || read_capped(pipe)));
    let deadline: Instant = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _: Result<(), std::io::Error> = child.kill();
                    let _: Result<std::process::ExitStatus, std::io::Error> = child.wait();
                    drop(join_capture(stdout));
                    drop(join_capture(stderr));
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _: Result<(), std::io::Error> = child.kill();
                let _: Result<std::process::ExitStatus, std::io::Error> = child.wait();
                drop(join_capture(stdout));
                drop(join_capture(stderr));
                return None;
            }
        }
    }
    Some(CapturedOutput {
        stdout: join_capture(stdout)?,
        stderr: join_capture(stderr)?,
    })
}

fn join_capture(handle: Option<JoinHandle<std::io::Result<Vec<u8>>>>) -> Option<Vec<u8>> {
    handle.map_or_else(
        || Some(Vec::new()),
        |handle| match handle.join() {
            Ok(Ok(bytes)) => Some(bytes),
            Ok(Err(_)) | Err(_) => None,
        },
    )
}

fn read_capped<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(MAX_CAPTURE_OUTPUT.min(CAPTURE_READ_CHUNK));
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let n: usize = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let remaining: usize = MAX_CAPTURE_OUTPUT.saturating_sub(out.len());
        let keep: usize = remaining.min(n);
        out.extend_from_slice(&chunk[..keep]);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn read_capped_retains_only_limit() {
        let payload: Vec<u8> = vec![b'x'; MAX_CAPTURE_OUTPUT + 1024];
        let out: Vec<u8> = read_capped(std::io::Cursor::new(payload)).expect("read");
        assert_eq!(out.len(), MAX_CAPTURE_OUTPUT);
    }
}
