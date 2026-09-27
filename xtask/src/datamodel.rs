use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct VerificationDoc {
    pub(crate) rows: Vec<VerificationRow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerificationRow {
    pub(crate) ecosystem: String,
    #[serde(default)]
    pub(crate) result: String,
}
