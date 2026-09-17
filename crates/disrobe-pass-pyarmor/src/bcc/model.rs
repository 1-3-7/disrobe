use serde::Serialize;

pub(crate) const CO_OPTIMIZED: i32 = 0x0001;
pub(crate) const CO_VARARGS: i32 = 0x0004;
pub(crate) const CO_VARKEYWORDS: i32 = 0x0008;
pub(crate) const CO_GENERATOR: i32 = 0x0020;
pub(crate) const CO_COROUTINE: i32 = 0x0080;
pub(crate) const CO_ASYNC_GENERATOR: i32 = 0x0200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkConfidence {
    Confirmed,
    Probable,
    Synthetic,
}

impl LinkConfidence {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Probable => "probable",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    Recovered,
    Stripped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionKind {
    Function,
    Method,
    AsyncFunction,
    AsyncMethod,
    Generator,
    GeneratorMethod,
    AsyncGenerator,
    AsyncGeneratorMethod,
    Lambda,
}

impl FunctionKind {
    #[must_use]
    pub const fn is_method(self) -> bool {
        matches!(
            self,
            Self::Method | Self::AsyncMethod | Self::GeneratorMethod | Self::AsyncGeneratorMethod
        )
    }

    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::AsyncFunction
            | Self::AsyncMethod
            | Self::AsyncGenerator
            | Self::AsyncGeneratorMethod => "async def",
            _ => "def",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyStatus {
    NativeWall,
    BytecodeRetained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ResidualCodeObject,
    WrapperStub,
    DispatchTable,
    NativeNameTable,
    PackageLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    PositionalOnly,
    PositionalOrKeyword,
    VarPositional,
    KeywordOnly,
    VarKeyword,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Parameter {
    pub name: String,
    pub kind: ParamKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signature {
    pub argcount: u32,
    pub posonlyargcount: u32,
    pub kwonlyargcount: u32,
    pub has_varargs: bool,
    pub has_varkeywords: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub param_names_recovered: bool,
    pub parameters: Vec<Parameter>,
    pub rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceIdentity {
    pub py_path: Option<String>,
    pub module: Option<String>,
    pub qualname: String,
    pub class: Option<String>,
    pub kind: FunctionKind,
    pub firstlineno: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRef {
    pub offset: u64,
    pub size: u64,
    pub arch: String,
    pub container: String,
    pub dispatch_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionRecord {
    pub native: Option<NativeRef>,
    pub source: SourceIdentity,
    pub signature: Signature,
    pub body_status: BodyStatus,
    pub confidence: LinkConfidence,
    pub name_status: NameStatus,
    pub evidence: Vec<EvidenceSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered_body: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkSummary {
    pub total_functions: usize,
    pub native_functions: usize,
    pub bytecode_retained: usize,
    pub confirmed: usize,
    pub probable: usize,
    pub synthetic: usize,
    pub dispatch_entries: usize,
    pub unlinked_dispatch_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BccLinkMap {
    pub module: Option<String>,
    pub py_path: Option<String>,
    pub python_version: String,
    pub records: Vec<FunctionRecord>,
    pub summary: LinkSummary,
    pub notes: Vec<String>,
}

impl BccLinkMap {
    pub fn native_records(&self) -> impl Iterator<Item = &FunctionRecord> {
        self.records
            .iter()
            .filter(|record: &&FunctionRecord| record.native.is_some())
    }
}
