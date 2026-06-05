use super::{FormatError, FormatterLanguage, SourceFormatter};

#[derive(Debug, Default)]
pub struct IdentityFormatter;

impl SourceFormatter for IdentityFormatter {
    #[inline]
    fn language(&self) -> FormatterLanguage {
        FormatterLanguage::Identity
    }

    #[inline]
    fn format(&self, source: &str) -> Result<String, FormatError> {
        Ok(source.to_owned())
    }

    #[inline]
    fn is_available(&self) -> bool {
        true
    }

    #[inline]
    fn external_tool(&self) -> Option<&'static str> {
        None
    }
}
