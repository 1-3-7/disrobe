use std::process::ExitStatus;

use disrobe_tool_process::{CaptureOutcome, CommandSpec, Completion, Execution, ExecutionError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub success: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ToolOutput {
    #[must_use]
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    #[must_use]
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error("the {stream} capture did not complete: {reason}")]
    Capture {
        stream: &'static str,
        reason: String,
    },
}

pub fn tool_output(spec: CommandSpec) -> Result<ToolOutput, ToolError> {
    let execution: Execution = spec.run()?;
    let (status, timed_out): (ExitStatus, bool) = match execution.completion {
        Completion::Exited(status) => (status, false),
        Completion::TimedOut(status) => (status, true),
    };
    Ok(ToolOutput {
        success: !timed_out && status.success(),
        timed_out,
        exit_code: status.code(),
        stdout: captured_bytes("stdout", execution.stdout)?,
        stderr: captured_bytes("stderr", execution.stderr)?,
    })
}

fn captured_bytes(stream: &'static str, outcome: CaptureOutcome) -> Result<Vec<u8>, ToolError> {
    match outcome {
        CaptureOutcome::Complete(captured) => Ok(captured.bytes),
        CaptureOutcome::Failed { source, .. } => Err(ToolError::Capture {
            stream,
            reason: source.to_string(),
        }),
        CaptureOutcome::NotStarted => Err(ToolError::Capture {
            stream,
            reason: "the capture worker never started".to_owned(),
        }),
        CaptureOutcome::WorkerPanicked => Err(ToolError::Capture {
            stream,
            reason: "the capture worker panicked".to_owned(),
        }),
        CaptureOutcome::WorkerUnresponsive => Err(ToolError::Capture {
            stream,
            reason: "the capture worker did not finish".to_owned(),
        }),
    }
}
