use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FreezerKind {
    CxFreeze,
    Py2exe,
    Bbfreeze,
    Shiv,
    Pex,
    Zipapp,
    Pyc,
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
            Self::Bbfreeze => "bbfreeze",
            Self::Shiv => "shiv",
            Self::Pex => "pex",
            Self::Zipapp => "zipapp",
            Self::Pyc => "pyc",
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleInventoryEntry {
    pub name: String,
    pub is_package: bool,
    pub has_source: bool,
    pub has_bytecode: bool,
    pub has_bytecode_opt1: bool,
    pub has_bytecode_opt2: bool,
    pub has_extension: bool,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_inventory: Vec<ModuleInventoryEntry>,
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
            module_inventory: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: EntryRecord) {
        self.entries.push(entry);
        self.entry_count = self.entries.len();
    }
}
