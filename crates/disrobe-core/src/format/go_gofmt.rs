use super::process::{run_or_fail, tool_available};
use super::{FormatError, FormatterLanguage, SourceFormatter, current_config};

const TOOL: &str = "gofmt";

#[derive(Debug, Default)]
pub struct GoGofmtFormatter;

impl SourceFormatter for GoGofmtFormatter {
    #[inline]
    fn language(&self) -> FormatterLanguage {
        FormatterLanguage::Go
    }

    fn format(&self, source: &str) -> Result<String, FormatError> {
        let timeout: u32 = current_config().timeout_secs;
        run_or_fail(TOOL, &[], source, timeout)
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
