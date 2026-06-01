use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FreezerKind {
    CxFreeze,
    Py2exe,
    Shiv,
    Pex,
    PyOxidizer,
    Briefcase,
    Unknown,
}

impl FreezerKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CxFreeze => "cx_freeze",
            Self::Py2exe => "py2exe",
            Self::Shiv => "shiv",
            Self::Pex => "pex",
            Self::PyOxidizer => "pyoxidizer",
            Self::Briefcase => "briefcase",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryRecord {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub python_major: Option<u8>,
    pub python_minor: Option<u8>,
    pub source_path: Option<String>,
    pub origin: EntryOrigin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    PythonModule,
    PythonByteCode,
    NativeExtension,
    Resource,
    Wheel,
    Metadata,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EntryOrigin {
    LibraryZip,
    SiblingFile,
    PeResource,
    TrailingZip,
    Deps,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezerManifest {
    pub schema: String,
    pub kind: FreezerKind,
    pub source_path: String,
    pub python_major: Option<u8>,
    pub python_minor: Option<u8>,
    pub interpreter_hint: Option<String>,
    pub entry_count: usize,
    pub primary_module: Option<String>,
    pub entries: Vec<EntryRecord>,
}

impl FreezerManifest {
    #[must_use]
    pub fn new(kind: FreezerKind, source_path: String) -> Self {
        Self {
            schema: "disrobe.pyfreeze.manifest/v0".to_owned(),
            kind,
            source_path,
            python_major: None,
            python_minor: None,
            interpreter_hint: None,
            entry_count: 0,
            primary_module: None,
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: EntryRecord) {
        self.entries.push(entry);
        self.entry_count = self.entries.len();
    }
}
