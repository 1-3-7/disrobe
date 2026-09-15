pub mod actions;
pub mod crypt;
pub mod filters;
pub mod limits;
pub mod names;
pub mod object;
pub mod parse;
pub mod report;
pub mod xref;

pub use object::{EncryptionStatus, PdfDocument};
pub use report::{
    ActionFinding, EmbeddedFileFinding, EncryptionInfo, JsFinding, NameObfuscation, PdfReport,
    analyze as analyze_pdf, is_pdf as is_pdf_document, render_report,
};
