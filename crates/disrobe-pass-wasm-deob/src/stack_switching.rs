use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{Handle, Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum StackSwitchOpKind {
    ContNew,
    ContBind,
    Suspend,
    Resume,
    ResumeThrow,
    Switch,
}

impl StackSwitchOpKind {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::ContNew => "cont.new",
            Self::ContBind => "cont.bind",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::ResumeThrow => "resume_throw",
            Self::Switch => "switch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResumeHandlerRecord {
    pub tag_index: u32,
    pub label: Option<u32>,
    pub is_switch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StackSwitchOpRecord {
    pub function_index: u32,
    pub operator_offset: usize,
    pub kind: StackSwitchOpKind,
    pub cont_type_index: Option<u32>,
    pub tag_index: Option<u32>,
    pub argument_index: Option<u32>,
    pub result_index: Option<u32>,
    pub handlers: Vec<ResumeHandlerRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StackSwitchReport {
    pub ops: Vec<StackSwitchOpRecord>,
    pub kinds: BTreeMap<StackSwitchOpKind, usize>,
    pub functions_with_stack_switch: BTreeMap<u32, usize>,
    pub uses_switch: bool,
    pub uses_resume_throw: bool,
}

impl StackSwitchReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    #[inline]
    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.ops.len()
    }

    #[must_use]
    pub fn rust_lift_skeleton(&self) -> String {
        let mut out: String = String::with_capacity(64usize);
        for op in &self.ops {
            let line: String = match op.kind {
                StackSwitchOpKind::ContNew => format!(
                    "let cont_{idx}: Continuation = Continuation::new::<T{tindex}>();",
                    idx = op.operator_offset,
                    tindex = op.cont_type_index.unwrap_or(u32::MAX)
                ),
                StackSwitchOpKind::Suspend => format!(
                    "suspend_to_tag(Tag::{t});",
                    t = op.tag_index.unwrap_or(u32::MAX)
                ),
                StackSwitchOpKind::Resume => format!(
                    "resume_continuation(cont_{idx}, [{handlers}]);",
                    idx = op.operator_offset,
                    handlers = render_handlers(&op.handlers)
                ),
                StackSwitchOpKind::ResumeThrow => format!(
                    "resume_continuation_throw(cont_{idx}, Tag::{t});",
                    idx = op.operator_offset,
                    t = op.tag_index.unwrap_or(u32::MAX)
                ),
                StackSwitchOpKind::Switch => format!(
                    "switch_to_tag(Tag::{t});",
                    t = op.tag_index.unwrap_or(u32::MAX)
                ),
                StackSwitchOpKind::ContBind => format!(
                    "cont_bind::<T{a},T{r}>(cont_{idx});",
                    a = op.argument_index.unwrap_or(u32::MAX),
                    r = op.result_index.unwrap_or(u32::MAX),
                    idx = op.operator_offset
                ),
            };
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

fn render_handlers(handlers: &[ResumeHandlerRecord]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(handlers.len());
    for h in handlers {
        if h.is_switch {
            parts.push(format!("on Tag::{} switch", h.tag_index));
        } else {
            parts.push(format!(
                "on Tag::{} -> label{}",
                h.tag_index,
                h.label.unwrap_or(u32::MAX)
            ));
        }
    }
    parts.join(", ")
}

pub fn scan_stack_switching(input: &[u8]) -> Result<StackSwitchReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-STACKSWITCH: not a wasm module".to_owned(),
        ));
    }
    let mut report: StackSwitchReport = StackSwitchReport::default();
    let mut fn_index: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut ops_reader: wasmparser::OperatorsReader<'_> = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(format!("{e}")))?;
            while !ops_reader.eof() {
                let pos: usize = ops_reader.original_position();
                let op: Operator<'_> = ops_reader
                    .read()
                    .map_err(|e| Error::Parse(format!("{e}")))?;
                if let Some(record) = classify_op(fn_index, pos, &op) {
                    let kind: StackSwitchOpKind = record.kind;
                    *report.kinds.entry(kind).or_insert(0usize) += 1usize;
                    *report
                        .functions_with_stack_switch
                        .entry(fn_index)
                        .or_insert(0usize) += 1usize;
                    if matches!(kind, StackSwitchOpKind::Switch) {
                        report.uses_switch = true;
                    }
                    if matches!(kind, StackSwitchOpKind::ResumeThrow) {
                        report.uses_resume_throw = true;
                    }
                    report.ops.push(record);
                }
            }
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(report)
}

fn classify_op(
    function_index: u32,
    operator_offset: usize,
    op: &Operator<'_>,
) -> Option<StackSwitchOpRecord> {
    let base: StackSwitchOpRecord = StackSwitchOpRecord {
        function_index,
        operator_offset,
        kind: StackSwitchOpKind::ContNew,
        cont_type_index: None,
        tag_index: None,
        argument_index: None,
        result_index: None,
        handlers: Vec::new(),
    };
    match op {
        Operator::ContNew { cont_type_index } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::ContNew,
            cont_type_index: Some(*cont_type_index),
            ..base
        }),
        Operator::ContBind {
            argument_index,
            result_index,
        } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::ContBind,
            argument_index: Some(*argument_index),
            result_index: Some(*result_index),
            ..base
        }),
        Operator::Suspend { tag_index } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::Suspend,
            tag_index: Some(*tag_index),
            ..base
        }),
        Operator::Resume {
            cont_type_index,
            resume_table,
        } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::Resume,
            cont_type_index: Some(*cont_type_index),
            handlers: collect_handlers(resume_table),
            ..base
        }),
        Operator::ResumeThrow {
            cont_type_index,
            tag_index,
            resume_table,
        } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::ResumeThrow,
            cont_type_index: Some(*cont_type_index),
            tag_index: Some(*tag_index),
            handlers: collect_handlers(resume_table),
            ..base
        }),
        Operator::Switch {
            cont_type_index,
            tag_index,
        } => Some(StackSwitchOpRecord {
            kind: StackSwitchOpKind::Switch,
            cont_type_index: Some(*cont_type_index),
            tag_index: Some(*tag_index),
            ..base
        }),
        _ => None,
    }
}

fn collect_handlers(table: &wasmparser::ResumeTable) -> Vec<ResumeHandlerRecord> {
    let mut out: Vec<ResumeHandlerRecord> = Vec::with_capacity(table.handlers.len());
    for h in &table.handlers {
        match h {
            Handle::OnLabel { tag, label } => out.push(ResumeHandlerRecord {
                tag_index: *tag,
                label: Some(*label),
                is_switch: false,
            }),
            Handle::OnSwitch { tag } => out.push(ResumeHandlerRecord {
                tag_index: *tag,
                label: None,
                is_switch: true,
            }),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const STACK_SWITCH_WAT: &str = r"
        (module
          (type $ft (func))
          (type $ct (cont $ft))
          (tag $t)
          (func $worker
            (suspend $t)
            (return))
          (func $main
            (cont.new $ct (ref.func $worker))
            (resume $ct (on $t 0))
            (return)))
    ";

    fn try_wat(src: &str) -> Option<Vec<u8>> {
        wat::parse_str(src).ok()
    }

    #[test]
    fn detects_stack_switching_when_supported() {
        let Some(bytes): Option<Vec<u8>> = try_wat(STACK_SWITCH_WAT) else {
            return;
        };
        let report: StackSwitchReport = scan_stack_switching(&bytes).expect("scan");
        assert!(!report.is_empty());
        assert!(report.kinds.contains_key(&StackSwitchOpKind::Suspend));
        assert!(report.kinds.contains_key(&StackSwitchOpKind::ContNew));
        assert!(report.kinds.contains_key(&StackSwitchOpKind::Resume));
        let skeleton: String = report.rust_lift_skeleton();
        assert!(skeleton.contains("suspend_to_tag"));
    }

    #[test]
    fn empty_module_reports_no_stack_switch_ops() {
        let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
        let report: StackSwitchReport = scan_stack_switching(&bytes).expect("scan");
        assert!(report.is_empty());
        assert!(!report.uses_switch);
        assert!(!report.uses_resume_throw);
    }

    #[test]
    fn rejects_non_wasm_input() {
        let err: Error = scan_stack_switching(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
