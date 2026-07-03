use super::process::{run_or_fail, tool_available};
use super::{FormatError, FormatterLanguage, SourceFormatter, current_config};

const TOOL: &str = "ruff";

#[derive(Debug, Default)]
pub struct PythonRuffFormatter;

impl SourceFormatter for PythonRuffFormatter {
    #[inline]
    fn language(&self) -> FormatterLanguage {
        FormatterLanguage::Python
    }

    fn format(&self, source: &str) -> Result<String, FormatError> {
        let timeout: u32 = current_config().timeout_secs;
        run_or_fail(
            TOOL,
            &["format", "--isolated", "--stdin-filename", "input.py", "-"],
            source,
            timeout,
        )
    }

    #[inline]
    fn is_available(&self) -> bool {
        tool_available(TOOL)
    }

    #[inline]
    fn external_tool(&self) -> Option<&'static str> {
        Some(TOOL)
    }
}
