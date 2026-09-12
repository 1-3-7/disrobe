pub mod builder;
pub mod validator;

use std::collections::BTreeMap;
use std::ops::Range;

use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    Module,
    Try,
    With,
    AsyncWith,
    ForLoop,
    AsyncForLoop,
    WhileLoop,
    IfChain,
    MatchStmt,
    FunctionDef,
    ClassDef,
    Lambda,
    Comprehension,
    ExceptHandler,
    FinallyClause,
    ExceptGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerRange {
    pub range: Range<u32>,
    pub exception_target: u32,
    pub depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub id: FrameId,
    pub kind: FrameKind,
    pub range: Range<u32>,
    pub body_range: Range<u32>,
    pub child_ranges: Vec<Range<u32>>,
    pub handlers: Vec<HandlerRange>,
    pub finally_range: Option<Range<u32>>,
    pub line: Option<u32>,
    pub children: Vec<Frame>,
}

impl Frame {
    #[must_use]
    pub fn new(id: FrameId, kind: FrameKind, range: Range<u32>) -> Self {
        let body_range: Range<u32> = range.clone();
        Self {
            id,
            kind,
            range,
            body_range,
            child_ranges: Vec::new(),
            handlers: Vec::new(),
            finally_range: None,
            line: None,
            children: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameTree {
    pub root: Frame,
    pub by_offset: BTreeMap<u32, FrameId>,
}

impl FrameTree {
    #[must_use]
    pub fn new(root: Frame) -> Self {
        let mut by_offset: BTreeMap<u32, FrameId> = BTreeMap::new();
        index_frame(&root, &mut by_offset);
        Self { root, by_offset }
    }

    #[must_use]
    pub fn find(&self, offset: u32) -> Option<FrameId> {
        self.by_offset
            .range(..=offset)
            .next_back()
            .map(|(_, id): (&u32, &FrameId)| *id)
    }
}

fn index_frame(frame: &Frame, sink: &mut BTreeMap<u32, FrameId>) {
    let _: Option<FrameId> = sink.insert(frame.range.start, frame.id);
    for child in &frame.children {
        index_frame(child, sink);
    }
}

pub trait FrameTreeBuilder: Send + Sync + std::fmt::Debug {
    fn build(&self, code: &CodeObject, version: PyVersion) -> Result<FrameTree>;
}

#[must_use]
pub fn builder_for(version: PyVersion) -> Box<dyn FrameTreeBuilder> {
    if version.major > 3 || (version.major == 3 && version.minor >= 11) {
        Box::new(builder::Post311Builder::new())
    } else {
        Box::new(builder::Pre311Builder::new())
    }
}

pub use builder::{Post311Builder, Pre311Builder};
pub use validator::validate;
