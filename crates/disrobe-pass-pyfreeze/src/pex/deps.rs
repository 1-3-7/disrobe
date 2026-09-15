use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct WheelRecord {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
}
