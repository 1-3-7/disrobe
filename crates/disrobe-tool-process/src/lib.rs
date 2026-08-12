#![deny(unreachable_pub)]

use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub fn opened_file_matches_path(path: &Path, file: &File) -> io::Result<bool> {
    platform::opened_file_matches_path(path, file)
}

#[cfg(unix)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod unix;
#[cfg(not(any(unix, windows)))]
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod unsupported;
#[cfg(windows)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(not(any(unix, windows)))]
use unsupported as platform;
#[cfg(windows)]
use windows as platform;

const CAPTURE_CHUNK: usize = 8192;
const WORKER_COLLECTION_GRACE: Duration = Duration::from_secs(5);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Debug, Clone)]
pub struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    stdin: StdinSpec,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
}

#[derive(Debug, Clone)]
enum StdinSpec {
    Closed,
    Bytes(Vec<u8>),
}

impl CommandSpec {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            environment: Vec::new(),
            stdin: StdinSpec::Closed,
            timeout,
            stdout_limit: 4 * 1024 * 1024,
            stderr_limit: 4 * 1024 * 1024,
        }
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = StdinSpec::Bytes(input.into());
        self
    }

    #[must_use]
    pub const fn capture_limits(mut self, stdout_limit: usize, stderr_limit: usize) -> Self {
        self.stdout_limit = stdout_limit;
        self.stderr_limit = stderr_limit;
        self
    }

    pub fn run(self) -> Result<Execution, ExecutionError> {
        let started: Instant = Instant::now();
        let deadline: Instant = started
            .checked_add(self.timeout)
            .ok_or(LaunchError::TimeoutOverflow)?;
        let (mut process, mut pipes): (platform::ContainedProcess, PipeSet) =
            platform::spawn(&self)?;
        let stdout_worker: JoinHandle<CaptureOutcome> = match spawn_capture(
            "disrobe-tool-stdout",
            pipes.stdout.take(),
            self.stdout_limit,
        ) {
            Ok(worker) => worker,
            Err(source) => {
                drop(pipes);
                let cleanup: Result<PlatformCompletion, LifecycleError> =
                    process.terminate_and_wait(false);
                drop(process);
                return Err(worker_start_failure(CaptureStream::Stdout, source, cleanup));
            }
        };
        let stderr_worker: JoinHandle<CaptureOutcome> = match spawn_capture(
            "disrobe-tool-stderr",
            pipes.stderr.take(),
            self.stderr_limit,
        ) {
            Ok(worker) => worker,
            Err(source) => {
                drop(pipes);
                let cleanup: Result<PlatformCompletion, LifecycleError> =
                    process.terminate_and_wait(false);
                drop(process);
                let stdout: CaptureOutcome =
                    join_capture_until(stdout_worker, worker_collection_deadline());
                return Err(ExecutionError::Runtime(Box::new(RuntimeFailure {
                    cause: LifecycleError::WorkerStart {
                        stream: WorkerStream::Stderr,
                        source,
                    },
                    cleanup_error: cleanup.err(),
                    stdin: StdinOutcome::NotStarted,
                    stdout,
                    stderr: CaptureOutcome::NotStarted,
                })));
            }
        };
        let stdin_worker: Option<JoinHandle<StdinOutcome>> = match self.stdin {
            StdinSpec::Closed => {
                drop(pipes.stdin.take());
                None
            }
            StdinSpec::Bytes(bytes) => {
                match spawn_stdin("disrobe-tool-stdin", pipes.stdin.take(), bytes) {
                    Ok(worker) => Some(worker),
                    Err(source) => {
                        drop(pipes);
                        let cleanup: Result<PlatformCompletion, LifecycleError> =
                            process.terminate_and_wait(false);
                        drop(process);
                        let collection_deadline: Instant = worker_collection_deadline();
                        let stdout: CaptureOutcome =
                            join_capture_until(stdout_worker, collection_deadline);
                        let stderr: CaptureOutcome =
                            join_capture_until(stderr_worker, collection_deadline);
                        return Err(ExecutionError::Runtime(Box::new(RuntimeFailure {
                            cause: LifecycleError::WorkerStart {
                                stream: WorkerStream::Stdin,
                                source,
                            },
                            cleanup_error: cleanup.err(),
                            stdin: StdinOutcome::NotStarted,
                            stdout,
                            stderr,
                        })));
                    }
                }
            }
        };
        drop(pipes);
        let completion: Result<PlatformCompletion, LifecycleError> = if Instant::now() >= deadline {
            process.terminate_and_wait(true)
        } else {
            #[cfg(windows)]
            {
                match process.start() {
                    Ok(()) => process.wait_until(deadline),
                    Err(failure) => Err(failure),
                }
            }
            #[cfg(not(windows))]
            {
                process.wait_until(deadline)
            }
        };
        let completion: Result<PlatformCompletion, LifecycleError> = settle_lifecycle(
            &mut process,
            completion,
            |process: &mut platform::ContainedProcess| process.terminate_and_wait(false),
        );
        drop(process);
        let collection_deadline: Instant = worker_collection_deadline();
        let stdin: StdinOutcome = join_stdin_until(stdin_worker, collection_deadline);
        let stdout: CaptureOutcome = join_capture_until(stdout_worker, collection_deadline);
        let stderr: CaptureOutcome = join_capture_until(stderr_worker, collection_deadline);
        match completion {
            Ok(completion) => Ok(Execution {
                completion: if completion.timed_out {
                    Completion::TimedOut(completion.status)
                } else {
                    Completion::Exited(completion.status)
                },
                containment: ContainmentEvidence {
                    empty_process_set_proven: true,
                    completion_notification_observed: completion.completion_notification_observed,
                },
                stdin,
                stdout,
                stderr,
            }),
            Err(cause) => Err(ExecutionError::Runtime(Box::new(RuntimeFailure {
                cause,
                cleanup_error: None,
                stdin,
                stdout,
                stderr,
            }))),
        }
    }
}

#[derive(Debug)]
pub struct Execution {
    pub completion: Completion,
    pub containment: ContainmentEvidence,
    pub stdin: StdinOutcome,
    pub stdout: CaptureOutcome,
    pub stderr: CaptureOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentEvidence {
    pub empty_process_set_proven: bool,
    pub completion_notification_observed: bool,
}

#[derive(Debug)]
pub enum Completion {
    Exited(ExitStatus),
    TimedOut(ExitStatus),
}

#[derive(Debug)]
pub enum StdinOutcome {
    Closed,
    Delivered,
    Failed(io::Error),
    NotStarted,
    WorkerPanicked,
    WorkerUnresponsive,
}

#[derive(Debug)]
pub enum CaptureOutcome {
    Complete(CapturedStream),
    Failed {
        captured: CapturedStream,
        source: io::Error,
    },
    NotStarted,
    WorkerPanicked,
    WorkerUnresponsive,
}

impl CaptureOutcome {
    #[must_use]
    pub const fn captured(&self) -> Option<&CapturedStream> {
        match self {
            Self::Complete(captured) | Self::Failed { captured, .. } => Some(captured),
            Self::NotStarted | Self::WorkerPanicked | Self::WorkerUnresponsive => None,
        }
    }
}

#[derive(Debug)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error(transparent)]
    Launch(#[from] LaunchError),
    #[error(transparent)]
    Runtime(Box<RuntimeFailure>),
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("process timeout cannot be represented")]
    TimeoutOverflow,
    #[error("trusted tool path cannot be resolved: {path}")]
    Resolve {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid trusted tool specification: {0}")]
    InvalidInput(&'static str),
    #[error("process setup failed during {stage:?}: {source}")]
    Platform {
        stage: LaunchStage,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStage {
    Pipe,
    Job,
    CompletionPort,
    AttributeList,
    Spawn,
    Assignment,
    SuspendedCleanup,
}

#[derive(Debug)]
pub struct RuntimeFailure {
    pub cause: LifecycleError,
    pub cleanup_error: Option<LifecycleError>,
    pub stdin: StdinOutcome,
    pub stdout: CaptureOutcome,
    pub stderr: CaptureOutcome,
}

impl Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "process lifecycle failed: {}", self.cause)?;
        if let Some(cleanup) = &self.cleanup_error {
            write!(formatter, "; cleanup failed: {cleanup}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RuntimeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("failed to start {stream:?} worker: {source}")]
    WorkerStart {
        stream: WorkerStream,
        #[source]
        source: io::Error,
    },
    #[error("failed to resume contained process: {0}")]
    Resume(#[source] io::Error),
    #[error("failed to wait for direct process: {0}")]
    Wait(#[source] io::Error),
    #[error("failed to terminate contained process set: {0}")]
    Terminate(#[source] io::Error),
    #[error("failed to observe contained process set completion: {0}")]
    Observe(#[source] io::Error),
    #[error("failed to query contained process accounting: {0}")]
    ContainmentQuery(#[source] io::Error),
    #[error("failed to receive contained process notification: {0}")]
    CompletionPort(#[source] io::Error),
    #[error("unexpected containment notification")]
    Notification,
    #[error("contained process teardown exceeded its deadline")]
    TeardownDeadline,
    #[error("{primary}; cleanup failed: {cleanup}")]
    Cleanup {
        primary: Box<Self>,
        cleanup: Box<Self>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStream {
    Stdin,
    Stdout,
    Stderr,
}

pub(crate) struct PipeSet {
    stdin: Option<Box<dyn Write + Send>>,
    stdout: Option<Box<dyn Read + Send>>,
    stderr: Option<Box<dyn Read + Send>>,
}

impl PipeSet {
    pub(crate) fn new(
        stdin: Box<dyn Write + Send>,
        stdout: Box<dyn Read + Send>,
        stderr: Box<dyn Read + Send>,
    ) -> Self {
        Self {
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }
}

pub(crate) struct PlatformCompletion {
    status: ExitStatus,
    timed_out: bool,
    completion_notification_observed: bool,
}

impl PlatformCompletion {
    pub(crate) const fn exited(status: ExitStatus) -> Self {
        Self {
            status,
            timed_out: false,
            completion_notification_observed: false,
        }
    }

    pub(crate) const fn timed_out(status: ExitStatus) -> Self {
        Self {
            status,
            timed_out: true,
            completion_notification_observed: false,
        }
    }

    #[cfg(windows)]
    pub(crate) const fn with_completion_notification(mut self, observed: bool) -> Self {
        self.completion_notification_observed = observed;
        self
    }
}

fn spawn_capture(
    name: &'static str,
    reader: Option<Box<dyn Read + Send>>,
    limit: usize,
) -> io::Result<JoinHandle<CaptureOutcome>> {
    let reader: Box<dyn Read + Send> =
        reader.ok_or_else(|| io::Error::other("capture pipe missing"))?;
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || read_capture(reader, limit))
}

fn spawn_stdin(
    name: &'static str,
    writer: Option<Box<dyn Write + Send>>,
    bytes: Vec<u8>,
) -> io::Result<JoinHandle<StdinOutcome>> {
    let mut writer: Box<dyn Write + Send> =
        writer.ok_or_else(|| io::Error::other("stdin pipe missing"))?;
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || match writer.write_all(&bytes) {
            Ok(()) => StdinOutcome::Delivered,
            Err(source) => StdinOutcome::Failed(source),
        })
}

fn read_capture(mut reader: Box<dyn Read + Send>, limit: usize) -> CaptureOutcome {
    let mut bytes: Vec<u8> = Vec::with_capacity(limit.min(CAPTURE_CHUNK));
    let mut truncated: bool = false;
    let mut chunk: [u8; CAPTURE_CHUNK] = [0; CAPTURE_CHUNK];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                return CaptureOutcome::Complete(CapturedStream { bytes, truncated });
            }
            Ok(read) => {
                let remaining: usize = limit.saturating_sub(bytes.len());
                let keep: usize = remaining.min(read);
                bytes.extend_from_slice(&chunk[..keep]);
                truncated |= keep < read;
            }
            Err(source) => {
                return CaptureOutcome::Failed {
                    captured: CapturedStream { bytes, truncated },
                    source,
                };
            }
        }
    }
}

fn join_capture_until(worker: JoinHandle<CaptureOutcome>, deadline: Instant) -> CaptureOutcome {
    if !wait_for_worker(&worker, deadline) {
        return CaptureOutcome::WorkerUnresponsive;
    }
    worker.join().unwrap_or(CaptureOutcome::WorkerPanicked)
}

fn join_stdin_until(worker: Option<JoinHandle<StdinOutcome>>, deadline: Instant) -> StdinOutcome {
    worker.map_or(StdinOutcome::Closed, |worker: JoinHandle<StdinOutcome>| {
        if !wait_for_worker(&worker, deadline) {
            return StdinOutcome::WorkerUnresponsive;
        }
        worker.join().unwrap_or(StdinOutcome::WorkerPanicked)
    })
}

fn wait_for_worker<T>(worker: &JoinHandle<T>, deadline: Instant) -> bool {
    while !worker.is_finished() {
        let now: Instant = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(WORKER_POLL_INTERVAL),
        );
    }
    true
}

fn worker_collection_deadline() -> Instant {
    Instant::now()
        .checked_add(WORKER_COLLECTION_GRACE)
        .unwrap_or_else(Instant::now)
}

fn settle_lifecycle<P, F>(
    process: &mut P,
    completion: Result<PlatformCompletion, LifecycleError>,
    cleanup: F,
) -> Result<PlatformCompletion, LifecycleError>
where
    F: FnOnce(&mut P) -> Result<PlatformCompletion, LifecycleError>,
{
    match completion {
        Ok(completion) => Ok(completion),
        Err(primary) => match cleanup(process) {
            Ok(_) => Err(primary),
            Err(cleanup) => Err(LifecycleError::Cleanup {
                primary: Box::new(primary),
                cleanup: Box::new(cleanup),
            }),
        },
    }
}

fn worker_start_failure(
    stream: CaptureStream,
    source: io::Error,
    cleanup: Result<PlatformCompletion, LifecycleError>,
) -> ExecutionError {
    ExecutionError::Runtime(Box::new(RuntimeFailure {
        cause: LifecycleError::WorkerStart {
            stream: match stream {
                CaptureStream::Stdout => WorkerStream::Stdout,
            },
            source,
        },
        cleanup_error: cleanup.err(),
        stdin: StdinOutcome::NotStarted,
        stdout: CaptureOutcome::NotStarted,
        stderr: CaptureOutcome::NotStarted,
    }))
}

enum CaptureStream {
    Stdout,
}

pub(crate) fn canonical_program(program: &Path) -> Result<PathBuf, LaunchError> {
    if program.components().count() == 1
        && let Some(path_value) = std::env::var_os("PATH")
    {
        for directory in std::env::split_paths(&path_value) {
            for candidate in executable_candidates(&directory, program) {
                if candidate.is_file()
                    && let Ok(canonical) = std::fs::canonicalize(&candidate)
                {
                    return Ok(canonical);
                }
            }
        }
    }
    std::fs::canonicalize(program).map_err(|source: io::Error| LaunchError::Resolve {
        path: program.to_path_buf(),
        source,
    })
}

fn executable_candidates(directory: &Path, program: &Path) -> Vec<PathBuf> {
    let direct: PathBuf = directory.join(program);
    #[cfg(windows)]
    {
        if program.extension().is_some() {
            return vec![direct];
        }
        let extensions: Vec<OsString> = std::env::var_os("PATHEXT").map_or_else(
            || {
                vec![
                    OsString::from(".COM"),
                    OsString::from(".EXE"),
                    OsString::from(".BAT"),
                    OsString::from(".CMD"),
                ]
            },
            |value: OsString| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension: &&str| !extension.is_empty())
                    .map(OsString::from)
                    .collect()
            },
        );
        let mut candidates: Vec<PathBuf> = Vec::with_capacity(extensions.len() + 1);
        candidates.push(direct);
        candidates.extend(extensions.into_iter().map(|extension: OsString| {
            let mut name: OsString = program.as_os_str().to_os_string();
            name.push(extension);
            directory.join(name)
        }));
        candidates
    }
    #[cfg(not(windows))]
    {
        vec![direct]
    }
}

pub(crate) fn arguments(spec: &CommandSpec) -> &[OsString] {
    &spec.args
}

pub(crate) fn environment(spec: &CommandSpec) -> &[(OsString, OsString)] {
    &spec.environment
}

pub(crate) fn program(spec: &CommandSpec) -> &Path {
    &spec.program
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FailingReader {
        delivered: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                return Err(io::Error::other("capture fault"));
            }
            self.delivered = true;
            buffer[..7].copy_from_slice(b"partial");
            Ok(7)
        }
    }

    struct CountingReader {
        remaining: usize,
        read_count: Arc<AtomicUsize>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let read: usize = self.remaining.min(buffer.len());
            buffer[..read].fill(b'x');
            self.remaining -= read;
            self.read_count.fetch_add(read, Ordering::SeqCst);
            Ok(read)
        }
    }

    #[test]
    fn capture_error_retains_partial_bytes_and_stream_error() {
        let outcome: CaptureOutcome =
            read_capture(Box::new(FailingReader { delivered: false }), 1024);
        let CaptureOutcome::Failed { captured, source } = outcome else {
            panic!("capture fault was not retained");
        };
        assert_eq!(captured.bytes, b"partial");
        assert!(!captured.truncated);
        assert_eq!(source.to_string(), "capture fault");
    }

    #[test]
    #[cfg(unix)]
    fn opened_file_identity_rejects_replacement_path() -> io::Result<()> {
        let root: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-tool-process-identity-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        let path: PathBuf = root.join("source.java");
        let replacement: PathBuf = root.join("replacement.java");
        std::fs::write(&path, b"class First {}")?;
        std::fs::write(&replacement, b"class Replacement {}")?;
        let opened: File = File::open(&path)?;
        std::fs::rename(&replacement, path.with_extension("replacement"))?;
        std::fs::write(&path, b"class Replacement {}")?;
        assert!(!opened_file_matches_path(&path, &opened)?);
        let _: io::Result<()> = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn zero_capture_limit_still_drains_the_reader_to_eof() {
        let read_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let outcome: CaptureOutcome = read_capture(
            Box::new(CountingReader {
                remaining: CAPTURE_CHUNK * 3 + 17,
                read_count: Arc::clone(&read_count),
            }),
            0,
        );
        let CaptureOutcome::Complete(captured) = outcome else {
            panic!("zero-limit capture failed");
        };
        assert!(captured.bytes.is_empty());
        assert!(captured.truncated);
        assert_eq!(read_count.load(Ordering::SeqCst), CAPTURE_CHUNK * 3 + 17);
    }

    #[test]
    fn runtime_failure_display_includes_cleanup_failure() {
        let failure: RuntimeFailure = RuntimeFailure {
            cause: LifecycleError::Wait(io::Error::other("primary wait failure")),
            cleanup_error: Some(LifecycleError::Terminate(io::Error::other(
                "cleanup termination failure",
            ))),
            stdin: StdinOutcome::NotStarted,
            stdout: CaptureOutcome::NotStarted,
            stderr: CaptureOutcome::NotStarted,
        };
        let rendered: String = failure.to_string();
        assert!(rendered.contains("primary wait failure"));
        assert!(rendered.contains("cleanup termination failure"));
    }

    #[test]
    fn lifecycle_failure_runs_cleanup_before_results_are_collected() {
        let mut cleaned: bool = false;
        let primary: LifecycleError = LifecycleError::Wait(io::Error::other("wait failure"));
        let result: Result<PlatformCompletion, LifecycleError> =
            settle_lifecycle(&mut cleaned, Err(primary), |cleaned: &mut bool| {
                *cleaned = true;
                Ok(PlatformCompletion::exited(success_status()))
            });
        assert!(cleaned);
        assert!(matches!(result, Err(LifecycleError::Wait(_))));
    }

    #[test]
    fn capture_worker_collection_has_a_deadline() {
        let worker: JoinHandle<CaptureOutcome> = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            CaptureOutcome::Complete(CapturedStream {
                bytes: Vec::new(),
                truncated: false,
            })
        });
        let started: Instant = Instant::now();
        let outcome: CaptureOutcome =
            join_capture_until(worker, started + Duration::from_millis(10));
        assert!(matches!(outcome, CaptureOutcome::WorkerUnresponsive));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[cfg(unix)]
    fn success_status() -> ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn success_status() -> ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        ExitStatus::from_raw(0)
    }
}
