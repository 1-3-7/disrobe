use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::os::windows::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::{
    CommandSpec, LaunchError, LaunchStage, LifecycleError, PipeSet, PlatformCompletion, arguments,
    canonical_program, program,
};

const OBSERVATION_INTERVAL: Duration = Duration::from_millis(10);
const TEARDOWN_GRACE: Duration = Duration::from_secs(5);
const TERMINATION_EXIT_CODE: u32 = 0xffff_fffe;
const MAX_COMMAND_LINE_UNITS: usize = 32_767;

pub(crate) struct ContainedProcess {
    job: OwnedHandle,
    completion_port: OwnedHandle,
    process: OwnedHandle,
    primary_thread: Option<OwnedHandle>,
    completion_key: usize,
    direct_status: Option<ExitStatus>,
    active_zero_seen: bool,
    finished: bool,
}

struct PipePair {
    parent: OwnedHandle,
    child: OwnedHandle,
}

struct AttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

struct InheritanceWindow<'a> {
    handles: &'a [HANDLE; 3],
    enabled: usize,
}

pub(crate) fn spawn(spec: &CommandSpec) -> Result<(ContainedProcess, PipeSet), LaunchError> {
    let executable: PathBuf = canonical_program(program(spec))?;
    let prepared: PreparedCommand = prepare_command(&executable, arguments(spec))?;
    let job: OwnedHandle = create_job()?;
    let completion_port: OwnedHandle = create_completion_port()?;
    let completion_key: usize = job.as_raw_handle() as usize;
    associate_completion_port(&job, &completion_port)?;
    let stdin_pipe: PipePair = create_pipe(true)?;
    let stdout_pipe: PipePair = create_pipe(false)?;
    let stderr_pipe: PipePair = create_pipe(false)?;
    let child_handles: [HANDLE; 3] = [
        raw_handle(&stdin_pipe.child),
        raw_handle(&stdout_pipe.child),
        raw_handle(&stderr_pipe.child),
    ];
    let mut attributes: AttributeList = AttributeList::new(&child_handles)?;
    let mut startup: STARTUPINFOEXW = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = structure_size::<STARTUPINFOEXW>()?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_handles[0];
    startup.StartupInfo.hStdOutput = child_handles[1];
    startup.StartupInfo.hStdError = child_handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();
    let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();
    let mut command_line: Vec<u16> = prepared.command_line;
    let created: i32 = {
        let _inheritance: InheritanceWindow<'_> = InheritanceWindow::new(&child_handles)?;
        unsafe {
            CreateProcessW(
                prepared.application.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                null(),
                null(),
                &raw const startup.StartupInfo,
                &raw mut process_info,
            )
        }
    };
    if created == 0 {
        return Err(platform_launch(LaunchStage::Spawn));
    }
    let process_handle: OwnedHandle =
        unsafe { OwnedHandle::from_raw_handle(process_info.hProcess.cast()) };
    let thread_handle: OwnedHandle =
        unsafe { OwnedHandle::from_raw_handle(process_info.hThread.cast()) };
    drop(stdin_pipe.child);
    drop(stdout_pipe.child);
    drop(stderr_pipe.child);
    let assigned: i32 =
        unsafe { AssignProcessToJobObject(raw_handle(&job), raw_handle(&process_handle)) };
    if assigned == 0 {
        let source: io::Error = io::Error::last_os_error();
        cleanup_suspended_process(&process_handle).map_err(|cleanup: io::Error| {
            LaunchError::Platform {
                stage: LaunchStage::SuspendedCleanup,
                source: io::Error::other(format!(
                    "assignment failed: {source}; cleanup failed: {cleanup}"
                )),
            }
        })?;
        return Err(LaunchError::Platform {
            stage: LaunchStage::Assignment,
            source,
        });
    }
    let stdin_file: File = File::from(stdin_pipe.parent);
    let stdout_file: File = File::from(stdout_pipe.parent);
    let stderr_file: File = File::from(stderr_pipe.parent);
    Ok((
        ContainedProcess {
            job,
            completion_port,
            process: process_handle,
            primary_thread: Some(thread_handle),
            completion_key,
            direct_status: None,
            active_zero_seen: false,
            finished: false,
        },
        PipeSet::new(
            Box::new(stdin_file),
            Box::new(stdout_file),
            Box::new(stderr_file),
        ),
    ))
}

impl ContainedProcess {
    pub(crate) fn start(&mut self) -> Result<(), LifecycleError> {
        let thread: OwnedHandle = self.primary_thread.take().ok_or_else(|| {
            LifecycleError::Resume(io::Error::other("primary thread handle missing"))
        })?;
        let previous_count: u32 = unsafe { ResumeThread(raw_handle(&thread)) };
        if previous_count == u32::MAX {
            return Err(LifecycleError::Resume(io::Error::last_os_error()));
        }
        if previous_count != 1 {
            return Err(LifecycleError::Resume(io::Error::other(format!(
                "unexpected primary thread suspend count {previous_count}"
            ))));
        }
        Ok(())
    }

    pub(crate) fn wait_until(
        &mut self,
        deadline: Instant,
    ) -> Result<PlatformCompletion, LifecycleError> {
        loop {
            let direct_status: Option<ExitStatus> = self.poll_direct_status()?;
            let active_processes: u32 = self.active_processes()?;
            if let Some(status) = direct_status
                && active_processes == 0
            {
                self.finished = true;
                return Ok(PlatformCompletion::exited(status)
                    .with_completion_notification(self.active_zero_seen));
            }
            if Instant::now() >= deadline {
                return self.terminate_and_wait(true);
            }
            let wait: Duration = deadline
                .saturating_duration_since(Instant::now())
                .min(OBSERVATION_INTERVAL);
            self.observe_completion_port(wait)?;
        }
    }

    pub(crate) fn terminate_and_wait(
        &mut self,
        timed_out: bool,
    ) -> Result<PlatformCompletion, LifecycleError> {
        self.terminate_job()?;
        let teardown_deadline: Instant = Instant::now()
            .checked_add(TEARDOWN_GRACE)
            .ok_or(LifecycleError::TeardownDeadline)?;
        let mut port_failure: Option<LifecycleError> = None;
        loop {
            let direct_status: Option<ExitStatus> = self.poll_direct_status()?;
            let active_processes: u32 = self.active_processes()?;
            if let Some(status) = direct_status
                && active_processes == 0
            {
                self.finished = true;
                if let Some(failure) = port_failure {
                    return Err(failure);
                }
                let completion: PlatformCompletion = if timed_out {
                    PlatformCompletion::timed_out(status)
                } else {
                    PlatformCompletion::exited(status)
                };
                return Ok(completion.with_completion_notification(self.active_zero_seen));
            }
            if port_failure.is_none()
                && let Err(failure) = self.observe_completion_port(OBSERVATION_INTERVAL)
            {
                port_failure = Some(failure);
            }
            if port_failure.is_some() {
                std::thread::sleep(OBSERVATION_INTERVAL);
            }
            if Instant::now() >= teardown_deadline {
                return Err(LifecycleError::TeardownDeadline);
            }
        }
    }

    fn terminate_job(&self) -> Result<(), LifecycleError> {
        let terminated: i32 =
            unsafe { TerminateJobObject(raw_handle(&self.job), TERMINATION_EXIT_CODE) };
        if terminated == 0 {
            return Err(LifecycleError::Terminate(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn poll_direct_status(&mut self) -> Result<Option<ExitStatus>, LifecycleError> {
        if let Some(status) = self.direct_status {
            return Ok(Some(status));
        }
        let wait: u32 = unsafe { WaitForSingleObject(raw_handle(&self.process), 0) };
        match wait {
            WAIT_OBJECT_0 => {
                let mut exit_code: u32 = 0;
                let read: i32 =
                    unsafe { GetExitCodeProcess(raw_handle(&self.process), &raw mut exit_code) };
                if read == 0 {
                    return Err(LifecycleError::Wait(io::Error::last_os_error()));
                }
                let status: ExitStatus = ExitStatus::from_raw(exit_code);
                self.direct_status = Some(status);
                Ok(Some(status))
            }
            WAIT_TIMEOUT => Ok(None),
            WAIT_FAILED => Err(LifecycleError::Wait(io::Error::last_os_error())),
            other => Err(LifecycleError::Wait(io::Error::other(format!(
                "unexpected direct-process wait result {other}"
            )))),
        }
    }

    fn active_processes(&self) -> Result<u32, LifecycleError> {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let size: u32 = runtime_structure_size::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>()?;
        let queried: i32 = unsafe {
            QueryInformationJobObject(
                raw_handle(&self.job),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size,
                null_mut(),
            )
        };
        if queried == 0 {
            return Err(LifecycleError::ContainmentQuery(io::Error::last_os_error()));
        }
        Ok(accounting.ActiveProcesses)
    }

    fn observe_completion_port(&mut self, wait: Duration) -> Result<(), LifecycleError> {
        let mut message: u32 = 0;
        let mut key: usize = 0;
        let mut overlapped: *mut windows_sys::Win32::System::IO::OVERLAPPED = null_mut();
        let wait_millis: u32 = duration_millis(wait);
        let received: i32 = unsafe {
            GetQueuedCompletionStatus(
                raw_handle(&self.completion_port),
                &raw mut message,
                &raw mut key,
                &raw mut overlapped,
                wait_millis,
            )
        };
        if received == 0 {
            let source: io::Error = io::Error::last_os_error();
            if source.raw_os_error() == i32::try_from(WAIT_TIMEOUT).ok() {
                return Ok(());
            }
            return Err(LifecycleError::CompletionPort(source));
        }
        if key != self.completion_key {
            return Err(LifecycleError::Notification);
        }
        if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
            self.active_zero_seen = true;
        }
        Ok(())
    }
}

impl Drop for ContainedProcess {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let terminated: i32 =
            unsafe { TerminateJobObject(raw_handle(&self.job), TERMINATION_EXIT_CODE) };
        if terminated == 0 {
            let _: i32 =
                unsafe { TerminateProcess(raw_handle(&self.process), TERMINATION_EXIT_CODE) };
        }
        let _: u32 = unsafe {
            WaitForSingleObject(raw_handle(&self.process), duration_millis(TEARDOWN_GRACE))
        };
    }
}

impl AttributeList {
    fn new(handles: &[HANDLE; 3]) -> Result<Self, LaunchError> {
        let mut bytes: usize = 0;
        let _: i32 = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &raw mut bytes) };
        if bytes == 0 {
            return Err(platform_launch(LaunchStage::AttributeList));
        }
        let words: usize = bytes.div_ceil(size_of::<usize>());
        let mut list: Self = Self {
            storage: vec![0usize; words],
            initialized: false,
        };
        let initialized: i32 =
            unsafe { InitializeProcThreadAttributeList(list.as_mut_ptr(), 1, 0, &raw mut bytes) };
        if initialized == 0 {
            return Err(platform_launch(LaunchStage::AttributeList));
        }
        list.initialized = true;
        let updated: i32 = unsafe {
            UpdateProcThreadAttribute(
                list.as_mut_ptr(),
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).map_err(|_| {
                    LaunchError::InvalidInput("handle-list attribute cannot be represented")
                })?,
                handles.as_ptr().cast(),
                size_of_val(handles),
                null_mut(),
                null(),
            )
        };
        if updated == 0 {
            return Err(platform_launch(LaunchStage::AttributeList));
        }
        Ok(list)
    }

    const fn as_mut_ptr(
        &mut self,
    ) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) };
        }
    }
}

impl<'a> InheritanceWindow<'a> {
    fn new(handles: &'a [HANDLE; 3]) -> Result<Self, LaunchError> {
        let mut window: Self = Self {
            handles,
            enabled: 0,
        };
        for handle in handles {
            let enabled: i32 =
                unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
            if enabled == 0 {
                return Err(platform_launch(LaunchStage::Pipe));
            }
            window.enabled += 1;
        }
        Ok(window)
    }
}

impl Drop for InheritanceWindow<'_> {
    fn drop(&mut self) {
        for handle in &self.handles[..self.enabled] {
            let _: i32 = unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

struct PreparedCommand {
    application: Vec<u16>,
    command_line: Vec<u16>,
}

fn prepare_command(
    executable: &Path,
    args: &[std::ffi::OsString],
) -> Result<PreparedCommand, LaunchError> {
    let extension: Option<String> = executable
        .extension()
        .map(OsStr::to_string_lossy)
        .map(|extension: std::borrow::Cow<'_, str>| extension.to_ascii_lowercase());
    let is_batch: bool = matches!(extension.as_deref(), Some("bat" | "cmd"));
    let (mut application, mut command_line): (Vec<u16>, Vec<u16>) = if is_batch {
        (
            system_command_prompt()?,
            batch_command_line(executable, args)?,
        )
    } else {
        (
            nul_terminated(executable.as_os_str())?,
            executable_command_line(executable.as_os_str(), args)?,
        )
    };
    if application.last() != Some(&0) {
        application.push(0);
    }
    command_line.push(0);
    if command_line.len() > MAX_COMMAND_LINE_UNITS {
        return Err(LaunchError::InvalidInput(
            "Windows command line exceeds 32767 UTF-16 units",
        ));
    }
    Ok(PreparedCommand {
        application,
        command_line,
    })
}

fn executable_command_line(
    executable: &OsStr,
    args: &[std::ffi::OsString],
) -> Result<Vec<u16>, LaunchError> {
    ensure_no_nul(executable)?;
    let mut command: Vec<u16> = Vec::new();
    command.push(u16::from(b'"'));
    command.extend(executable.encode_wide());
    command.push(u16::from(b'"'));
    for arg in args {
        command.push(u16::from(b' '));
        append_executable_arg(&mut command, arg)?;
    }
    Ok(command)
}

fn append_executable_arg(command: &mut Vec<u16>, arg: &OsStr) -> Result<(), LaunchError> {
    ensure_no_nul(arg)?;
    let units: Vec<u16> = arg.encode_wide().collect();
    let quote: bool = units.is_empty()
        || units
            .iter()
            .any(|unit: &u16| *unit == u16::from(b' ') || *unit == u16::from(b'\t'));
    if quote {
        command.push(u16::from(b'"'));
    }
    let mut backslashes: usize = 0;
    for unit in units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if unit == u16::from(b'"') {
                command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes + 1));
            }
            backslashes = 0;
        }
        command.push(unit);
    }
    if quote {
        command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        command.push(u16::from(b'"'));
    }
    Ok(())
}

fn batch_command_line(
    executable: &Path,
    args: &[std::ffi::OsString],
) -> Result<Vec<u16>, LaunchError> {
    let script: Vec<u16> = user_path(executable)?;
    if script.contains(&u16::from(b'"')) || script.last() == Some(&u16::from(b'\\')) {
        return Err(LaunchError::InvalidInput(
            "invalid Windows batch script path",
        ));
    }
    let mut command: Vec<u16> = "cmd.exe /e:ON /v:OFF /d /c \"".encode_utf16().collect();
    command.push(u16::from(b'"'));
    for unit in script {
        append_batch_unit(&mut command, unit);
    }
    command.push(u16::from(b'"'));
    for arg in args {
        command.push(u16::from(b' '));
        append_batch_arg(&mut command, arg)?;
    }
    command.push(u16::from(b'"'));
    Ok(command)
}

fn append_batch_arg(command: &mut Vec<u16>, arg: &OsStr) -> Result<(), LaunchError> {
    ensure_no_nul(arg)?;
    let units: Vec<u16> = arg.encode_wide().collect();
    if units.contains(&u16::from(b'"')) {
        return Err(LaunchError::InvalidInput(
            "Windows batch argument contains an unrepresentable quote",
        ));
    }
    if units
        .iter()
        .any(|unit: &u16| *unit == u16::from(b'\r') || *unit == u16::from(b'\n'))
    {
        return Err(LaunchError::InvalidInput(
            "Windows batch argument contains a line break",
        ));
    }
    let mut quote: bool = units.is_empty() || units.last() == Some(&u16::from(b'\\'));
    quote |= units.iter().copied().any(batch_unit_requires_quotes);
    if quote {
        command.push(u16::from(b'"'));
    }
    for unit in units {
        append_batch_unit(command, unit);
    }
    if quote {
        command.push(u16::from(b'"'));
    }
    Ok(())
}

fn append_batch_unit(command: &mut Vec<u16>, unit: u16) {
    if unit == u16::from(b'%') {
        command.extend("%%cd:~,".encode_utf16());
    }
    command.push(unit);
}

fn batch_unit_requires_quotes(unit: u16) -> bool {
    const SAFE: &[u8] = br"#$*+-./:?@\_";
    if unit > 0x7f {
        return false;
    }
    let byte: u8 = u8::try_from(unit).unwrap_or_default();
    if byte.is_ascii_alphanumeric() {
        return false;
    }
    !SAFE.contains(&byte)
}

fn user_path(path: &Path) -> Result<Vec<u16>, LaunchError> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure_units_no_nul(&wide)?;
    let verbatim_unc: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    if let Some(rest) = wide.strip_prefix(verbatim_unc.as_slice()) {
        let mut user: Vec<u16> = r"\\".encode_utf16().collect();
        user.extend_from_slice(rest);
        return Ok(user);
    }
    Ok(wide
        .strip_prefix(verbatim.as_slice())
        .unwrap_or(&wide)
        .to_vec())
}

fn system_command_prompt() -> Result<Vec<u16>, LaunchError> {
    let mut capacity: usize = 260;
    loop {
        let buffer_size: u32 = u32::try_from(capacity)
            .map_err(|_| LaunchError::InvalidInput("system directory path is too long"))?;
        let mut buffer: Vec<u16> = vec![0; capacity];
        let copied: u32 = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer_size) };
        if copied == 0 {
            return Err(platform_launch(LaunchStage::Spawn));
        }
        let copied_len: usize = usize::try_from(copied).map_err(|_| {
            LaunchError::InvalidInput("system directory length cannot be represented")
        })?;
        if copied_len < capacity {
            buffer.truncate(copied_len);
            buffer.extend(r"\cmd.exe".encode_utf16());
            buffer.push(0);
            return Ok(buffer);
        }
        capacity = copied_len.checked_add(1).ok_or(LaunchError::InvalidInput(
            "system directory length overflow",
        ))?;
    }
}

fn create_job() -> Result<OwnedHandle, LaunchError> {
    let raw: HANDLE = unsafe { CreateJobObjectW(null(), null()) };
    let job: OwnedHandle = owned_handle(raw, LaunchStage::Job)?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured: i32 = unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            structure_size::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()?,
        )
    };
    if configured == 0 {
        return Err(platform_launch(LaunchStage::Job));
    }
    Ok(job)
}

fn create_completion_port() -> Result<OwnedHandle, LaunchError> {
    let raw: HANDLE = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) };
    owned_handle(raw, LaunchStage::CompletionPort)
}

fn associate_completion_port(job: &OwnedHandle, port: &OwnedHandle) -> Result<(), LaunchError> {
    let association: JOBOBJECT_ASSOCIATE_COMPLETION_PORT = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: raw_handle(job),
        CompletionPort: raw_handle(port),
    };
    let associated: i32 = unsafe {
        SetInformationJobObject(
            raw_handle(job),
            JobObjectAssociateCompletionPortInformation,
            (&raw const association).cast(),
            structure_size::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>()?,
        )
    };
    if associated == 0 {
        return Err(platform_launch(LaunchStage::CompletionPort));
    }
    Ok(())
}

fn create_pipe(parent_writes: bool) -> Result<PipePair, LaunchError> {
    let attributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
        nLength: structure_size::<SECURITY_ATTRIBUTES>()?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 0,
    };
    let mut read_raw: HANDLE = null_mut();
    let mut write_raw: HANDLE = null_mut();
    let created: i32 = unsafe {
        CreatePipe(
            &raw mut read_raw,
            &raw mut write_raw,
            &raw const attributes,
            0,
        )
    };
    if created == 0 {
        return Err(platform_launch(LaunchStage::Pipe));
    }
    let read: OwnedHandle = unsafe { OwnedHandle::from_raw_handle(read_raw.cast()) };
    let write: OwnedHandle = unsafe { OwnedHandle::from_raw_handle(write_raw.cast()) };
    Ok(if parent_writes {
        PipePair {
            parent: write,
            child: read,
        }
    } else {
        PipePair {
            parent: read,
            child: write,
        }
    })
}

fn cleanup_suspended_process(process: &OwnedHandle) -> io::Result<()> {
    let terminated: i32 = unsafe { TerminateProcess(raw_handle(process), TERMINATION_EXIT_CODE) };
    if terminated == 0 {
        return Err(io::Error::last_os_error());
    }
    let wait: u32 =
        unsafe { WaitForSingleObject(raw_handle(process), duration_millis(TEARDOWN_GRACE)) };
    if wait != WAIT_OBJECT_0 {
        return Err(if wait == WAIT_FAILED {
            io::Error::last_os_error()
        } else {
            io::Error::other(format!("unexpected suspended cleanup wait result {wait}"))
        });
    }
    Ok(())
}

fn owned_handle(raw: HANDLE, stage: LaunchStage) -> Result<OwnedHandle, LaunchError> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(platform_launch(stage));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw.cast()) })
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle().cast()
}

fn structure_size<T>() -> Result<u32, LaunchError> {
    u32::try_from(size_of::<T>())
        .map_err(|_| LaunchError::InvalidInput("Windows structure size cannot be represented"))
}

fn runtime_structure_size<T>() -> Result<u32, LifecycleError> {
    u32::try_from(size_of::<T>()).map_err(|_| {
        LifecycleError::ContainmentQuery(io::Error::other(
            "Windows accounting structure size cannot be represented",
        ))
    })
}

fn duration_millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1)
}

fn nul_terminated(value: &OsStr) -> Result<Vec<u16>, LaunchError> {
    ensure_no_nul(value)?;
    let mut wide: Vec<u16> = value.encode_wide().collect();
    wide.push(0);
    Ok(wide)
}

fn ensure_no_nul(value: &OsStr) -> Result<(), LaunchError> {
    let units: Vec<u16> = value.encode_wide().collect();
    ensure_units_no_nul(&units)
}

fn ensure_units_no_nul(units: &[u16]) -> Result<(), LaunchError> {
    if units.contains(&0) {
        return Err(LaunchError::InvalidInput(
            "Windows program and arguments cannot contain a NUL code unit",
        ));
    }
    Ok(())
}

fn platform_launch(stage: LaunchStage) -> LaunchError {
    LaunchError::Platform {
        stage,
        source: io::Error::last_os_error(),
    }
}
