use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::{
    CommandSpec, LaunchError, LaunchStage, LifecycleError, PipeSet, PlatformCompletion, arguments,
    canonical_program, environment, program,
};

const OBSERVATION_INTERVAL: Duration = Duration::from_millis(2);
const TEARDOWN_GRACE: Duration = Duration::from_secs(5);

pub(crate) struct ContainedProcess {
    child: Child,
    process_group: i32,
    finished: bool,
}

pub(crate) fn spawn(spec: &CommandSpec) -> Result<(ContainedProcess, PipeSet), LaunchError> {
    let executable: std::path::PathBuf = canonical_program(program(spec))?;
    let mut command: Command = Command::new(executable);
    command
        .args(arguments(spec))
        .envs(
            environment(spec)
                .iter()
                .map(|(key, value): &(std::ffi::OsString, std::ffi::OsString)| (key, value)),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child: Child = command
        .spawn()
        .map_err(|source: io::Error| LaunchError::Platform {
            stage: LaunchStage::Spawn,
            source,
        })?;
    let process_group: i32 = i32::try_from(child.id()).map_err(|_| {
        terminate_direct_child(&mut child);
        LaunchError::InvalidInput("child process identifier exceeds Unix process-group range")
    })?;
    if process_group <= 1 {
        terminate_direct_child(&mut child);
        return Err(LaunchError::InvalidInput(
            "child process group must be greater than one",
        ));
    }
    let Some(stdin): Option<std::process::ChildStdin> = child.stdin.take() else {
        return Err(pipe_failure(&mut child, "child stdin pipe missing"));
    };
    let Some(stdout): Option<std::process::ChildStdout> = child.stdout.take() else {
        return Err(pipe_failure(&mut child, "child stdout pipe missing"));
    };
    let Some(stderr): Option<std::process::ChildStderr> = child.stderr.take() else {
        return Err(pipe_failure(&mut child, "child stderr pipe missing"));
    };
    Ok((
        ContainedProcess {
            child,
            process_group,
            finished: false,
        },
        PipeSet::new(Box::new(stdin), Box::new(stdout), Box::new(stderr)),
    ))
}

fn pipe_failure(child: &mut Child, message: &'static str) -> LaunchError {
    terminate_direct_child(child);
    LaunchError::Platform {
        stage: LaunchStage::Pipe,
        source: io::Error::other(message),
    }
}

fn terminate_direct_child(child: &mut Child) {
    let _: io::Result<()> = child.kill();
    let Some(deadline): Option<Instant> = Instant::now().checked_add(TEARDOWN_GRACE) else {
        return;
    };
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(OBSERVATION_INTERVAL),
        }
    }
}

impl ContainedProcess {
    pub(crate) fn wait_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PlatformCompletion, LifecycleError> {
        loop {
            let direct_status: Option<ExitStatus> =
                self.child.try_wait().map_err(LifecycleError::Wait)?;
            let group_empty: bool = self.group_is_empty()?;
            if let Some(status) = direct_status
                && group_empty
            {
                self.finished = true;
                return Ok(PlatformCompletion::exited(status));
            }
            if Instant::now() >= deadline {
                return self.terminate_and_wait(true);
            }
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
    }

    pub(crate) fn terminate_and_wait(
        &mut self,
        timed_out: bool,
    ) -> Result<PlatformCompletion, LifecycleError> {
        let teardown_deadline: Instant = Instant::now()
            .checked_add(TEARDOWN_GRACE)
            .ok_or(LifecycleError::TeardownDeadline)?;
        let mut status: Option<ExitStatus> = None;
        loop {
            match self.signal_group(libc::SIGKILL) {
                Ok(_) => {}
                Err(source) => return Err(LifecycleError::Terminate(source)),
            }
            if status.is_none() {
                status = self.child.try_wait().map_err(LifecycleError::Wait)?;
                if status.is_none() {
                    match self.child.kill() {
                        Ok(()) => {}
                        Err(source) if source.kind() == io::ErrorKind::InvalidInput => {}
                        Err(source) => return Err(LifecycleError::Terminate(source)),
                    }
                }
            }
            if self.group_is_empty()?
                && let Some(direct_status) = status
            {
                self.finished = true;
                return Ok(if timed_out {
                    PlatformCompletion::timed_out(direct_status)
                } else {
                    PlatformCompletion::exited(direct_status)
                });
            }
            if Instant::now() >= teardown_deadline {
                return Err(LifecycleError::TeardownDeadline);
            }
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
    }

    fn group_is_empty(&self) -> Result<bool, LifecycleError> {
        self.signal_group(0).map_err(LifecycleError::Observe)
    }

    fn signal_group(&self, signal: i32) -> io::Result<bool> {
        let result: i32 = unsafe { libc::kill(-self.process_group, signal) };
        if result == 0 {
            return Ok(false);
        }
        let source: io::Error = io::Error::last_os_error();
        match source.raw_os_error() {
            Some(libc::ESRCH) => Ok(true),
            _ => Err(source),
        }
    }
}

impl Drop for ContainedProcess {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _: io::Result<bool> = self.signal_group(libc::SIGKILL);
        terminate_direct_child(&mut self.child);
    }
}
