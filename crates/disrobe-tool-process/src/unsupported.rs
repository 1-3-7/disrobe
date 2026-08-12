use std::fs::File;
use std::io;
use std::path::Path;
use std::time::Instant;

use crate::{CommandSpec, LaunchError, LifecycleError, PipeSet, PlatformCompletion};

pub(crate) fn opened_file_matches_path(_path: &Path, _file: &File) -> io::Result<bool> {
    Ok(false)
}

pub(crate) struct ContainedProcess;

pub(crate) fn spawn(_spec: &CommandSpec) -> Result<(ContainedProcess, PipeSet), LaunchError> {
    Err(LaunchError::InvalidInput(
        "trusted tool execution is unsupported on this target",
    ))
}

impl ContainedProcess {
    pub(crate) const fn wait_until(
        &mut self,
        _deadline: Instant,
    ) -> Result<PlatformCompletion, LifecycleError> {
        Err(LifecycleError::Notification)
    }

    pub(crate) const fn terminate_and_wait(
        &mut self,
        _timed_out: bool,
    ) -> Result<PlatformCompletion, LifecycleError> {
        Err(LifecycleError::Notification)
    }
}
