mod entropy_classify;
mod name_section;

pub use entropy_classify::{NameStrategy, classify_export_strategy};
pub use name_section::{NameStripStats, obfuscated_name_style, strip_obfuscated_names};
