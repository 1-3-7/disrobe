use super::process::{run_or_fail, tool_available};
use super::{FormatError, FormatterLanguage, SourceFormatter, current_config};

const TOOL: &str = "rubocop";

#[derive(Debug, Default)]
pub struct RubyRubocopFormatter;

impl SourceFormatter for RubyRubocopFormatter {
    #[inline]
    fn language(&self) -> FormatterLanguage {
        FormatterLanguage::Ruby
    }

    fn format(&self, source: &str) -> Result<String, FormatError> {
        let timeout: u32 = current_config().timeout_secs;
        run_or_fail(
            TOOL,
            &["--stdin", "input.rb", "--auto-correct-all", "--stderr"],
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
