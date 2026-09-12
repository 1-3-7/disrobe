#![allow(clippy::redundant_pub_crate)]
use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::exception_table::{ExceptionEntry, decode_exception_table};
use crate::lines::{LineMark, line_marks};
use crate::{Instruction, cache_size, jumps};

const OPNAME_WIDTH: usize = 20;
const OPARG_WIDTH: usize = 5;
const NO_LINENO: &str = "  --";
const BYTECODE_UNIT_BYTES: u32 = 2;

#[derive(Debug, Clone)]
pub(crate) struct LabelMap {
    labels: BTreeMap<u32, u32>,
}

impl LabelMap {
    pub(crate) fn build(instructions: &[Instruction], co: &CodeObject, version: PyVersion) -> Self {
        let mut offsets: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for instruction in instructions {
            if let Some(target) = jump_destination(instruction, version) {
                offsets.insert(target);
            }
        }
        if uses_labels(version) {
            for entry in exception_entries(co) {
                offsets.insert(entry.start_offset);
                offsets.insert(entry.end_offset);
                offsets.insert(entry.target_offset);
            }
        }
        let labels: BTreeMap<u32, u32> = offsets
            .into_iter()
            .enumerate()
            .map(|(index, offset): (usize, u32)| (offset, index as u32 + 1))
            .collect();
        Self { labels }
    }

    #[must_use]
    pub(crate) fn count(&self) -> usize {
        self.labels.len()
    }

    #[must_use]
    pub(crate) fn label_for(&self, offset: u32) -> Option<u32> {
        self.labels.get(&offset).copied()
    }
}

fn exception_entries(co: &CodeObject) -> Vec<ExceptionEntry> {
    decode_exception_table(&co.exceptiontable).unwrap_or_default()
}

#[must_use]
pub(crate) const fn uses_labels(version: PyVersion) -> bool {
    version.major > 3 || (version.major == 3 && version.minor >= 13)
}

#[must_use]
const fn shows_absolute_arrow(version: PyVersion) -> bool {
    version.major > 3 || (version.major == 3 && version.minor >= 10)
}

#[must_use]
const fn has_exception_table(version: PyVersion) -> bool {
    version.major > 3 || (version.major == 3 && version.minor >= 11)
}

#[must_use]
fn jump_destination(instruction: &Instruction, version: PyVersion) -> Option<u32> {
    let kind: jumps::JumpKind = jumps::jump_kind(&instruction.opname, version);
    if matches!(kind, jumps::JumpKind::None) {
        return None;
    }
    let arg: u32 = instruction.arg?;
    let caches: u32 = u32::from(cache_size(instruction.opcode, version));
    jumps::jump_target(kind, instruction.offset as u32, arg, caches, version)
}

pub(crate) fn assign_jump_arrows(
    instructions: &mut [Instruction],
    labels: &LabelMap,
    version: PyVersion,
) {
    let absolute_arrow: bool = shows_absolute_arrow(version);
    let use_labels: bool = uses_labels(version);
    for instruction in instructions.iter_mut() {
        if instruction.argrepr.is_some() {
            continue;
        }
        let kind: jumps::JumpKind = jumps::jump_kind(&instruction.opname, version);
        if matches!(kind, jumps::JumpKind::None) {
            continue;
        }
        let is_absolute: bool = matches!(kind, jumps::JumpKind::Absolute);
        if is_absolute && !absolute_arrow {
            continue;
        }
        let Some(target): Option<u32> = jump_destination(instruction, version) else {
            continue;
        };
        let preposition: &str = if instruction.opname == "END_ASYNC_FOR" {
            "from"
        } else {
            "to"
        };
        if use_labels {
            if let Some(label) = labels.label_for(target) {
                instruction.argrepr = Some(format!("{preposition} L{label}"));
            }
        } else {
            instruction.argrepr = Some(format!("{preposition} {target}"));
        }
    }
}

#[must_use]
pub fn render_listing(instructions: &[Instruction], co: &CodeObject, version: PyVersion) -> String {
    let labels: LabelMap = LabelMap::build(instructions, co, version);
    if uses_labels(version) {
        render_label_era(instructions, co, &labels, version)
    } else {
        render_offset_era(instructions, co, version)
    }
}

fn offsets_of(instructions: &[Instruction]) -> Vec<u32> {
    instructions
        .iter()
        .map(|i: &Instruction| i.offset as u32)
        .collect()
}

fn offset_era_jump_markers(
    instructions: &[Instruction],
    co: &CodeObject,
    version: PyVersion,
) -> std::collections::BTreeSet<u32> {
    let mut markers: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for instruction in instructions {
        if let Some(target) = jump_destination(instruction, version) {
            markers.insert(target);
        }
    }
    if has_exception_table(version) {
        for entry in exception_entries(co) {
            markers.insert(entry.target_offset);
        }
    }
    markers
}

fn lineno_width_offset_era(marks: &[LineMark]) -> usize {
    let has_lines: bool = marks.iter().any(|m: &LineMark| m.line.is_some());
    if !has_lines {
        return 0;
    }
    let max_line: u32 = marks
        .iter()
        .filter_map(|m: &LineMark| m.line)
        .max()
        .unwrap_or(0);
    if max_line >= 1000 {
        max_line.to_string().len()
    } else {
        3
    }
}

fn offset_width_offset_era(code_len: usize) -> usize {
    let max_offset: i64 = code_len as i64 - i64::from(BYTECODE_UNIT_BYTES);
    if max_offset >= 10_000 {
        max_offset.to_string().len()
    } else {
        4
    }
}

fn render_offset_era(instructions: &[Instruction], co: &CodeObject, version: PyVersion) -> String {
    let marks: Vec<LineMark> = line_marks(co, version, &offsets_of(instructions));
    let lineno_width: usize = lineno_width_offset_era(&marks);
    let offset_width: usize = offset_width_offset_era(co.code.len());
    let markers: std::collections::BTreeSet<u32> =
        offset_era_jump_markers(instructions, co, version);
    let mut out: String = String::with_capacity(instructions.len() * 48);
    for (instruction, mark) in instructions.iter().zip(marks.iter()) {
        if lineno_width > 0 && mark.line.is_some() && instruction.offset > 0 {
            out.push('\n');
        }
        let mut fields: Vec<String> = Vec::with_capacity(6);
        if lineno_width > 0 {
            match mark.line {
                Some(line) => fields.push(format!("{line:>lineno_width$}")),
                None => fields.push(" ".repeat(lineno_width)),
            }
        }
        fields.push("   ".to_owned());
        fields.push(if markers.contains(&(instruction.offset as u32)) {
            ">>".to_owned()
        } else {
            "  ".to_owned()
        });
        fields.push(format!("{:>offset_width$}", instruction.offset));
        fields.push(format!("{:<OPNAME_WIDTH$}", instruction.opname));
        if let Some(arg) = instruction.arg {
            fields.push(format!("{arg:>OPARG_WIDTH$}"));
            if let Some(repr) = instruction
                .argrepr
                .as_deref()
                .filter(|r: &&str| !r.is_empty())
            {
                fields.push(format!("({repr})"));
            }
        }
        push_row(&mut out, &fields);
    }
    if has_exception_table(version) {
        append_exception_table_offset_era(&mut out, co);
    }
    out
}

fn render_label_era(
    instructions: &[Instruction],
    co: &CodeObject,
    labels: &LabelMap,
    version: PyVersion,
) -> String {
    let marks: Vec<LineMark> = line_marks(co, version, &offsets_of(instructions));
    let lineno_width: usize = lineno_width_label_era(&marks);
    let label_width: usize = 4 + labels.count().to_string().len();
    let mut out: String = String::with_capacity(instructions.len() * 48);
    for (instruction, mark) in instructions.iter().zip(marks.iter()) {
        if lineno_width > 0 && mark.starts_line && instruction.offset > 0 {
            out.push('\n');
        }
        let mut fields: Vec<String> = Vec::with_capacity(6);
        if lineno_width > 0 {
            if mark.starts_line {
                match mark.line {
                    Some(line) => fields.push(format!("{line:>lineno_width$}")),
                    None => fields.push(format!("{NO_LINENO:>lineno_width$}")),
                }
            } else {
                fields.push(" ".repeat(lineno_width));
            }
        }
        match labels.label_for(instruction.offset as u32) {
            Some(label) => {
                let lbl: String = format!("L{label}:");
                fields.push(format!("{lbl:>label_width$}"));
            }
            None => fields.push(" ".repeat(label_width)),
        }
        fields.push("   ".to_owned());
        fields.push(format!("{:<OPNAME_WIDTH$}", instruction.opname));
        if let Some(arg) = instruction.arg {
            let opname_excess: usize = instruction.opname.len().saturating_sub(OPNAME_WIDTH);
            let arg_width: usize = OPARG_WIDTH.saturating_sub(opname_excess);
            fields.push(format!("{arg:>arg_width$}"));
            if let Some(repr) = instruction
                .argrepr
                .as_deref()
                .filter(|r: &&str| !r.is_empty())
            {
                fields.push(format!("({repr})"));
            }
        }
        push_row(&mut out, &fields);
    }
    if has_exception_table(version) {
        append_exception_table_label_era(&mut out, co, labels);
    }
    out
}

fn lineno_width_label_era(marks: &[LineMark]) -> usize {
    let starts: Vec<&LineMark> = marks.iter().filter(|m: &&LineMark| m.starts_line).collect();
    let max_line: Option<u32> = starts.iter().filter_map(|m: &&LineMark| m.line).max();
    let Some(max_line): Option<u32> = max_line else {
        return 0;
    };
    let mut width: usize = 3.max(max_line.to_string().len());
    let has_none_start: bool = starts.iter().any(|m: &&LineMark| m.line.is_none());
    if width < NO_LINENO.len() && has_none_start {
        width = NO_LINENO.len();
    }
    width
}

fn push_row(out: &mut String, fields: &[String]) {
    let joined: String = fields.join(" ");
    out.push_str(joined.trim_end());
    out.push('\n');
}

fn append_exception_table_offset_era(out: &mut String, co: &CodeObject) {
    let entries: Vec<ExceptionEntry> = exception_entries(co);
    if entries.is_empty() {
        return;
    }
    out.push_str("ExceptionTable:\n");
    for entry in &entries {
        let end_inclusive: u32 = entry.end_offset.saturating_sub(BYTECODE_UNIT_BYTES);
        let lasti: &str = if entry.last_i { " lasti" } else { "" };
        crate::push_string_line(
            out,
            format_args!(
                "  {} to {} -> {} [{}]{lasti}",
                entry.start_offset, end_inclusive, entry.target_offset, entry.stack_depth
            ),
        );
    }
}

fn append_exception_table_label_era(out: &mut String, co: &CodeObject, labels: &LabelMap) {
    let entries: Vec<ExceptionEntry> = exception_entries(co);
    if entries.is_empty() {
        return;
    }
    out.push_str("ExceptionTable:\n");
    for entry in &entries {
        let start: u32 = labels.label_for(entry.start_offset).unwrap_or(0);
        let end: u32 = labels.label_for(entry.end_offset).unwrap_or(0);
        let target: u32 = labels.label_for(entry.target_offset).unwrap_or(0);
        let lasti: &str = if entry.last_i { " lasti" } else { "" };
        crate::push_string_line(
            out,
            format_args!(
                "  L{start} to L{end} -> L{target} [{}]{lasti}",
                entry.stack_depth
            ),
        );
    }
}
