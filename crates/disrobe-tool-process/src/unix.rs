use std::fs::File;
use std::io;
#[cfg(target_os = "macos")]
use std::mem::{MaybeUninit, size_of};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
#[cfg(any(not(target_os = "macos"), test))]
use std::process::ExitStatus;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::{
    CommandSpec, LaunchError, LaunchStage, LifecycleError, PipeSet, PlatformCompletion, arguments,
    canonical_program, environment, program,
};

pub(crate) fn opened_file_matches_path(path: &Path, file: &File) -> io::Result<bool> {
    let path_metadata: std::fs::Metadata = std::fs::symlink_metadata(path)?;
    let opened_metadata: std::fs::Metadata = file.metadata()?;
    Ok(path_metadata.dev() == opened_metadata.dev()
        && path_metadata.ino() == opened_metadata.ino()
        && path_metadata.is_file()
        && opened_metadata.is_file())
}

const OBSERVATION_INTERVAL: Duration = Duration::from_millis(2);
const TEARDOWN_GRACE: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MAX_GROUP_MEMBERS: usize = 1024;
#[cfg(target_os = "macos")]
const PROC_PIDT_SHORTBSDINFO: i32 = 13;
#[cfg(target_os = "macos")]
const PROC_PIDINFO_INCLUDE_ZOMBIES: u64 = 1;

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcBsdShortInfo {
    pbsi_pid: u32,
    _pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    _pbsi_comm: [libc::c_char; libc::MAXCOMLEN],
    _pbsi_flags: u32,
    _pbsi_uid: libc::uid_t,
    _pbsi_gid: libc::gid_t,
    _pbsi_ruid: libc::uid_t,
    _pbsi_rgid: libc::gid_t,
    _pbsi_svuid: libc::uid_t,
    _pbsi_svgid: libc::gid_t,
    _pbsi_rfu: u32,
}

pub(crate) struct ContainedProcess {
    child: Child,
    process_group: i32,
    finished: bool,
}

#[cfg(target_os = "macos")]
enum MacosGroupObservation {
    Empty,
    NotEmpty,
    Unproven(io::Error),
}

pub(crate) fn spawn(spec: &CommandSpec) -> Result<(ContainedProcess, PipeSet), LaunchError> {
    let executable: std::path::PathBuf = canonical_program(program(spec))?;
    let mut command: Command = Command::new(executable);
    command
        .arg0(program(spec))
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
    #[cfg(target_os = "macos")]
    pub(crate) fn wait_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PlatformCompletion, LifecycleError> {
        loop {
            match self.macos_group_observation()? {
                MacosGroupObservation::Empty => {
                    if let Some(status) = self.child.try_wait().map_err(LifecycleError::Wait)? {
                        self.finished = true;
                        return Ok(PlatformCompletion::exited(status));
                    }
                }
                MacosGroupObservation::NotEmpty | MacosGroupObservation::Unproven(_) => {}
            }
            if Instant::now() >= deadline {
                return self.terminate_and_wait(true);
            }
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
    }

    #[cfg(not(target_os = "macos"))]
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

    #[cfg(target_os = "macos")]
    pub(crate) fn terminate_and_wait(
        &mut self,
        timed_out: bool,
    ) -> Result<PlatformCompletion, LifecycleError> {
        let teardown_deadline: Instant = Instant::now()
            .checked_add(TEARDOWN_GRACE)
            .ok_or(LifecycleError::TeardownDeadline)?;
        let mut permission_error: Option<io::Error> = None;
        loop {
            match self.signal_group(libc::SIGKILL) {
                Ok(_) => permission_error = None,
                Err(source) if macos_zombie_only_error(self.process_group, &source) => {}
                Err(source) if source.raw_os_error() == Some(libc::EPERM) => {
                    permission_error = Some(source);
                }
                Err(source) => return Err(LifecycleError::Terminate(source)),
            }
            match self.macos_group_observation()? {
                MacosGroupObservation::Empty => {
                    if let Some(direct_status) =
                        self.child.try_wait().map_err(LifecycleError::Wait)?
                    {
                        self.finished = true;
                        return Ok(if timed_out {
                            PlatformCompletion::timed_out(direct_status)
                        } else {
                            PlatformCompletion::exited(direct_status)
                        });
                    }
                }
                MacosGroupObservation::NotEmpty => {}
                MacosGroupObservation::Unproven(source) => permission_error = Some(source),
            }
            if Instant::now() >= teardown_deadline {
                if let Some(source) = permission_error {
                    return Err(LifecycleError::Terminate(source));
                }
                return Err(LifecycleError::TeardownDeadline);
            }
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
    }

    #[cfg(not(target_os = "macos"))]
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

    #[cfg(not(target_os = "macos"))]
    fn group_is_empty(&self) -> Result<bool, LifecycleError> {
        match self.signal_group(0) {
            Ok(empty) => Ok(empty),
            Err(source) if macos_zombie_only_error(self.process_group, &source) => Ok(true),
            Err(source) => Err(LifecycleError::Observe(source)),
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_group_observation(&self) -> Result<MacosGroupObservation, LifecycleError> {
        match self.signal_group(0) {
            Ok(true) => Ok(MacosGroupObservation::Empty),
            Ok(false) => Ok(MacosGroupObservation::NotEmpty),
            Err(source) if macos_zombie_only_error(self.process_group, &source) => {
                Ok(MacosGroupObservation::Empty)
            }
            Err(source) if source.raw_os_error() == Some(libc::EPERM) => {
                Ok(MacosGroupObservation::Unproven(source))
            }
            Err(source) => Err(LifecycleError::Observe(source)),
        }
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

#[cfg(target_os = "macos")]
fn macos_zombie_only_error(process_group: i32, source: &io::Error) -> bool {
    source.raw_os_error() == Some(libc::EPERM) && macos_group_contains_only_zombies(process_group)
}

#[cfg(not(target_os = "macos"))]
const fn macos_zombie_only_error(_process_group: i32, _source: &io::Error) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_group_contains_only_zombies(process_group: i32) -> bool {
    let Ok(process_group_id): Result<u32, _> = u32::try_from(process_group) else {
        return false;
    };
    let Some(capacity): Option<usize> = MAX_GROUP_MEMBERS.checked_add(1) else {
        return false;
    };
    let Some(buffer_size): Option<usize> = capacity.checked_mul(size_of::<libc::pid_t>()) else {
        return false;
    };
    let Ok(buffer_size): Result<i32, _> = i32::try_from(buffer_size) else {
        return false;
    };
    let mut members: Vec<libc::pid_t> = vec![0; capacity];
    let found: i32 =
        unsafe { libc::proc_listpgrppids(process_group, members.as_mut_ptr().cast(), buffer_size) };
    let Ok(found): Result<usize, _> = usize::try_from(found) else {
        return false;
    };
    if found == 0 || found >= capacity {
        return false;
    }
    members.truncate(found);
    members.into_iter().all(|member_pid: libc::pid_t| {
        if member_pid <= 1 {
            return false;
        }
        let Ok(member_id): Result<u32, _> = u32::try_from(member_pid) else {
            return false;
        };
        let mut info: MaybeUninit<ProcBsdShortInfo> = MaybeUninit::uninit();
        let Ok(size): Result<i32, _> = size_of::<ProcBsdShortInfo>().try_into() else {
            return false;
        };
        let received: i32 = unsafe {
            libc::proc_pidinfo(
                member_pid,
                PROC_PIDT_SHORTBSDINFO,
                PROC_PIDINFO_INCLUDE_ZOMBIES,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if received != size {
            return false;
        }
        let info: ProcBsdShortInfo = unsafe { info.assume_init() };
        info.pbsi_pid == member_id
            && info.pbsi_pgid == process_group_id
            && info.pbsi_status == libc::SZOMB
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_DIRECTORY_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn create() -> io::Result<Self> {
            let sequence: usize = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path: std::path::PathBuf = std::env::temp_dir().join(format!(
                "disrobe-tool-process-argv-zero-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _: io::Result<()> = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn canonical_execution_preserves_requested_program_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch: TestDirectory = TestDirectory::create()?;
        let target: std::path::PathBuf = scratch.path().join("dispatch-target");
        let source: std::path::PathBuf = scratch.path().join("dispatch.rs");
        fs::write(
            &source,
            "fn main() {\n    let alias = std::env::args_os().next().is_some_and(|arg| arg.to_string_lossy().ends_with(\"dispatch-alias\"));\n    print!(\"{}\", if alias { \"alias\" } else { \"target\" });\n}\n",
        )?;
        let compiler: OsString =
            std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
        let built: crate::Execution = CommandSpec::new(compiler, Duration::from_secs(20))
            .args([
                source.as_os_str(),
                std::ffi::OsStr::new("-o"),
                target.as_os_str(),
            ])
            .run()?;
        assert!(
            matches!(built.completion, crate::Completion::Exited(status) if status.success()),
            "trusted argv-zero dispatch fixture did not compile: {built:?}"
        );
        let alias: std::path::PathBuf = scratch.path().join("dispatch-alias");
        symlink(&target, &alias)?;

        let execution: crate::Execution = CommandSpec::new(&alias, Duration::from_secs(1)).run()?;
        let captured: &crate::CapturedStream = execution
            .stdout
            .captured()
            .ok_or_else(|| io::Error::other("alias dispatch did not produce stdout"))?;
        assert_eq!(captured.bytes, b"alias");
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::thread;

    #[test]
    fn exited_leader_is_reaped_only_after_group_containment_is_proven()
    -> Result<(), Box<dyn std::error::Error>> {
        let execution: crate::Execution = CommandSpec::new("/bin/sh", Duration::from_secs(2))
            .args(["-c", "printf contained"])
            .run()?;
        let captured: &crate::CapturedStream = execution
            .stdout
            .captured()
            .ok_or_else(|| io::Error::other("contained command did not produce stdout"))?;
        assert_eq!(captured.bytes, b"contained");
        assert!(
            matches!(execution.completion, crate::Completion::Exited(status) if status.success())
        );
        assert!(execution.containment.empty_process_set_proven);
        Ok(())
    }

    #[test]
    fn concurrent_python_exits_preserve_process_set_containment()
    -> Result<(), Box<dyn std::error::Error>> {
        let results: Vec<Result<Result<crate::Execution, crate::ExecutionError>, io::Error>> =
            thread::scope(|scope| {
                let workers: [thread::ScopedJoinHandle<
                    '_,
                    Result<crate::Execution, crate::ExecutionError>,
                >; 8] = std::array::from_fn(|_| {
                    scope.spawn(|| {
                        CommandSpec::new("python3", Duration::from_secs(5))
                            .args(["-c", "print('contained')"])
                            .run()
                    })
                });
                workers
                    .into_iter()
                    .map(|worker| {
                        worker
                            .join()
                            .map_err(|_| io::Error::other("Python lifecycle worker panicked"))
                    })
                    .collect()
            });
        for result in results {
            let execution: crate::Execution = result??;
            assert!(
                matches!(execution.completion, crate::Completion::Exited(status) if status.success()),
                "concurrent Python execution did not exit successfully: {execution:?}"
            );
            assert!(execution.containment.empty_process_set_proven);
            let captured: &crate::CapturedStream =
                execution.stdout.captured().ok_or_else(|| {
                    io::Error::other("concurrent Python execution did not produce stdout")
                })?;
            assert_eq!(captured.bytes, b"contained\n");
        }
        Ok(())
    }

    #[test]
    fn zombie_only_process_group_probe_is_distinguished_from_live_members()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command: Command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]).process_group(0);
        let mut child: Child = command.spawn()?;
        let process_group: i32 = match i32::try_from(child.id()) {
            Ok(process_group) => process_group,
            Err(error) => {
                let _: io::Result<()> = child.kill();
                let _: io::Result<ExitStatus> = child.wait();
                return Err(error.into());
            }
        };
        let deadline: Instant = Instant::now() + Duration::from_secs(2);
        let mut result: Option<io::Error> = None;
        while Instant::now() < deadline {
            if unsafe { libc::kill(-process_group, 0) } == -1 {
                result = Some(io::Error::last_os_error());
                break;
            }
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
        let zombie_only: bool = macos_group_contains_only_zombies(process_group);
        let status: ExitStatus = child.wait()?;
        assert!(status.success());
        let source: io::Error = result.ok_or_else(|| {
            io::Error::other("unreaped zombie process group did not report an error")
        })?;
        assert_eq!(source.raw_os_error(), Some(libc::EPERM));
        assert!(zombie_only);
        assert_eq!(unsafe { libc::kill(-process_group, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));

        let mut command: Command = Command::new("/bin/sleep");
        command.args(["2"]).process_group(0);
        let mut child: Child = command.spawn()?;
        let process_group: i32 = match i32::try_from(child.id()) {
            Ok(process_group) => process_group,
            Err(error) => {
                let _: io::Result<()> = child.kill();
                let _: io::Result<ExitStatus> = child.wait();
                return Err(error.into());
            }
        };
        let zombie_only: bool = macos_group_contains_only_zombies(process_group);
        let killed: io::Result<()> = child.kill();
        let status: ExitStatus = child.wait()?;
        assert!(!zombie_only);
        assert!(killed.is_ok());
        assert!(!status.success());
        assert_eq!(unsafe { libc::kill(-process_group, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        Ok(())
    }
}
