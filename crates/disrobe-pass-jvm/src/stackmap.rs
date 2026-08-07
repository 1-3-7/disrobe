use std::collections::BTreeSet;

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::bytecode::{Instruction, Operands};
use crate::descriptor::{JavaType, MethodDescriptor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationType {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Uninitialized { offset: u32, class: String },
    Object(String),
}

fn java_type_to_verification(ty: &JavaType) -> VerificationType {
    match ty {
        JavaType::Byte | JavaType::Char | JavaType::Int | JavaType::Short | JavaType::Boolean => {
            VerificationType::Integer
        }
        JavaType::Float => VerificationType::Float,
        JavaType::Long => VerificationType::Long,
        JavaType::Double => VerificationType::Double,
        JavaType::Object(internal) => VerificationType::Object(internal.clone()),
        JavaType::Array(_) => VerificationType::Object("[".to_owned()),
        JavaType::Void => VerificationType::Top,
    }
}

#[must_use]
pub fn entry_frame_locals(
    descriptor: &MethodDescriptor,
    is_static: bool,
    is_init_ctor: bool,
    this_class: &str,
) -> Vec<VerificationType> {
    let mut locals: Vec<VerificationType> = Vec::new();
    if !is_static {
        locals.push(if is_init_ctor {
            VerificationType::UninitializedThis
        } else {
            VerificationType::Object(this_class.to_owned())
        });
    }
    for param in &descriptor.params {
        let vt: VerificationType = java_type_to_verification(param);
        let is_wide: bool = matches!(vt, VerificationType::Long | VerificationType::Double);
        locals.push(vt);
        if is_wide {
            locals.push(VerificationType::Top);
        }
    }
    locals
}

const SAME_FRAME_MAX: u8 = 63;
const SAME_LOCALS_1_STACK_MIN: u8 = 64;
const SAME_LOCALS_1_STACK_MAX: u8 = 127;
const SAME_LOCALS_1_STACK_EXTENDED: u8 = 247;
const CHOP_MIN: u8 = 248;
const CHOP_MAX: u8 = 250;
const SAME_FRAME_EXTENDED: u8 = 251;
const APPEND_MIN: u8 = 252;
const APPEND_MAX: u8 = 254;
const FULL_FRAME: u8 = 255;
const ITEM_OBJECT: u8 = 7;
const ITEM_UNINITIALIZED: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackMapReport {
    pub present: bool,
    pub declared_frames: usize,
    pub declared_offsets: Vec<u32>,
    pub required_offsets: Vec<u32>,
    pub missing_offsets: Vec<u32>,
    pub stray_offsets: Vec<u32>,
    pub consistent: bool,
    pub entry_frame: Vec<VerificationType>,
    pub note: String,
}

fn find_stack_map_table<'a>(
    info: &'a [u8],
    code_length: usize,
    utf8_lookup: &dyn Fn(u16) -> Option<String>,
) -> Option<&'a [u8]> {
    let exc_count_off: usize = 8usize.checked_add(code_length)?;
    let mut r: ByteReader<'a> = ByteReader::new(info);
    r.seek(exc_count_off).ok()?;
    let exc_count: u16 = r.read_u16_be().ok()?;
    let exc_bytes: usize = usize::from(exc_count).checked_mul(8)?;
    let exception_end: usize = r.position().checked_add(exc_bytes)?;
    r.seek(exception_end).ok()?;
    let attr_count: u16 = r.read_u16_be().ok()?;
    for _ in 0..attr_count {
        let name_index: u16 = r.read_u16_be().ok()?;
        let attr_len: u32 = r.read_u32_be().ok()?;
        let body_start: usize = r.position();
        let attr_len_usize: usize = usize::try_from(attr_len).ok()?;
        let body_end: usize = body_start.checked_add(attr_len_usize)?;
        let body: &'a [u8] = info.get(body_start..body_end)?;
        if utf8_lookup(name_index).as_deref() == Some("StackMapTable") {
            return Some(body);
        }
        r.seek(body_end).ok()?;
    }
    None
}

fn parse_declared_offsets(table: &[u8]) -> Option<Vec<u32>> {
    let mut r: ByteReader<'_> = ByteReader::new(table);
    let count: u16 = r.read_u16_be().ok()?;
    let mut offsets: Vec<u32> = Vec::with_capacity(usize::from(count));
    let mut current: i64 = -1;
    for _ in 0..count {
        let frame_type: u8 = r.read_u8().ok()?;
        let delta: u16 = match frame_type {
            0..=SAME_FRAME_MAX => u16::from(frame_type),
            SAME_LOCALS_1_STACK_MIN..=SAME_LOCALS_1_STACK_MAX => {
                skip_verification_type(&mut r)?;
                u16::from(frame_type - SAME_LOCALS_1_STACK_MIN)
            }
            SAME_LOCALS_1_STACK_EXTENDED => {
                let d: u16 = r.read_u16_be().ok()?;
                skip_verification_type(&mut r)?;
                d
            }
            CHOP_MIN..=CHOP_MAX | SAME_FRAME_EXTENDED => r.read_u16_be().ok()?,
            APPEND_MIN..=APPEND_MAX => {
                let d: u16 = r.read_u16_be().ok()?;
                let added: u8 = frame_type - (APPEND_MIN - 1);
                for _ in 0..added {
                    skip_verification_type(&mut r)?;
                }
                d
            }
            FULL_FRAME => {
                let d: u16 = r.read_u16_be().ok()?;
                let locals: u16 = r.read_u16_be().ok()?;
                for _ in 0..locals {
                    skip_verification_type(&mut r)?;
                }
                let stack: u16 = r.read_u16_be().ok()?;
                for _ in 0..stack {
                    skip_verification_type(&mut r)?;
                }
                d
            }
            _ => return None,
        };
        current = if current < 0 {
            i64::from(delta)
        } else {
            current + i64::from(delta) + 1
        };
        offsets.push(u32::try_from(current).ok()?);
    }
    Some(offsets)
}

fn skip_verification_type(r: &mut ByteReader<'_>) -> Option<()> {
    let tag: u8 = r.read_u8().ok()?;
    if tag == ITEM_OBJECT || tag == ITEM_UNINITIALIZED {
        r.read_u16_be().ok()?;
    }
    Some(())
}

#[must_use]
pub fn required_frame_offsets(insns: &[Instruction]) -> BTreeSet<u32> {
    let mut required: BTreeSet<u32> = BTreeSet::new();
    let mut prev_unconditional: bool = false;
    for insn in insns {
        if prev_unconditional {
            required.insert(insn.pc);
        }
        match insn.operands {
            Operands::Branch(off) => {
                let target: i64 = i64::from(insn.pc) + i64::from(off);
                if let Ok(t) = u32::try_from(target) {
                    required.insert(t);
                }
            }
            Operands::TableSwitch {
                default,
                ref offsets,
                ..
            } => {
                insert_switch_targets(&mut required, insn.pc, default, offsets);
            }
            Operands::LookupSwitch { default, ref pairs } => {
                let targets: Vec<i32> = pairs.iter().map(|(_, t): &(i32, i32)| *t).collect();
                insert_switch_targets(&mut required, insn.pc, default, &targets);
            }
            _ => {}
        }
        prev_unconditional = is_unconditional_transfer(insn.opcode);
    }
    required.remove(&0);
    required
}

fn insert_switch_targets(required: &mut BTreeSet<u32>, pc: u32, default: i32, targets: &[i32]) {
    for off in std::iter::once(&default).chain(targets) {
        let target: i64 = i64::from(pc) + i64::from(*off);
        if let Ok(t) = u32::try_from(target) {
            required.insert(t);
        }
    }
}

const fn is_unconditional_transfer(opcode: u8) -> bool {
    matches!(opcode, 0xA7 | 0xC8 | 0xAC..=0xB1 | 0xBF | 0xA9)
}

#[must_use]
pub fn analyze_stack_map(
    info: &[u8],
    code_length: usize,
    insns: &[Instruction],
    utf8_lookup: &dyn Fn(u16) -> Option<String>,
) -> StackMapReport {
    let required: BTreeSet<u32> = required_frame_offsets(insns);
    let required_vec: Vec<u32> = required.iter().copied().collect();

    let Some(table): Option<&[u8]> = find_stack_map_table(info, code_length, utf8_lookup) else {
        let consistent: bool = required.is_empty();
        crate::debug::dbg_kv("stackmap", || {
            format!(
                "absent; required_frames={} consistent={consistent}",
                required.len()
            )
        });
        return StackMapReport {
            present: false,
            declared_frames: 0,
            declared_offsets: Vec::new(),
            required_offsets: required_vec.clone(),
            missing_offsets: required_vec,
            stray_offsets: Vec::new(),
            consistent,
            entry_frame: Vec::new(),
            note: if consistent {
                "no StackMapTable and no branch targets require one".to_owned()
            } else {
                "StackMapTable absent though the method has branch targets that require frames (obfuscator stripped it, or pre-50 classfile); frame offsets recomputed from the control-flow graph".to_owned()
            },
        };
    };

    let Some(declared): Option<Vec<u32>> = parse_declared_offsets(table) else {
        crate::debug::dbg_kv("stackmap", || {
            format!("present but malformed; required_frames={}", required.len())
        });
        return StackMapReport {
            present: true,
            declared_frames: 0,
            declared_offsets: Vec::new(),
            required_offsets: required_vec.clone(),
            missing_offsets: required_vec,
            stray_offsets: Vec::new(),
            consistent: false,
            entry_frame: Vec::new(),
            note: "StackMapTable present but malformed; frame offsets recomputed from the control-flow graph".to_owned(),
        };
    };

    let declared_set: BTreeSet<u32> = declared.iter().copied().collect();
    let missing: Vec<u32> = required.difference(&declared_set).copied().collect();
    let stray: Vec<u32> = declared_set.difference(&required).copied().collect();
    let consistent: bool = missing.is_empty() && stray.is_empty();
    crate::debug::dbg_kv("stackmap", || {
        format!(
            "declared_frames={} required={} missing={} stray={} consistent={consistent}",
            declared.len(),
            required.len(),
            missing.len(),
            stray.len()
        )
    });
    StackMapReport {
        present: true,
        declared_frames: declared.len(),
        declared_offsets: declared,
        required_offsets: required_vec,
        missing_offsets: missing,
        stray_offsets: stray,
        consistent,
        entry_frame: Vec::new(),
        note: if consistent {
            "StackMapTable frame offsets match the control-flow graph".to_owned()
        } else {
            "StackMapTable frame offsets disagree with the control-flow graph; recomputed required offsets are reported".to_owned()
        },
    }
}

#[must_use]
pub fn analyze_stack_map_with_entry_frame(
    info: &[u8],
    code_length: usize,
    insns: &[Instruction],
    descriptor: &MethodDescriptor,
    is_static: bool,
    is_init_ctor: bool,
    this_class: &str,
    utf8_lookup: &dyn Fn(u16) -> Option<String>,
) -> StackMapReport {
    let mut report: StackMapReport = analyze_stack_map(info, code_length, insns, utf8_lookup);
    report.entry_frame = entry_frame_locals(descriptor, is_static, is_init_ctor, this_class);
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bytecode::disassemble;

    #[test]
    fn required_offsets_from_goto() {
        let code: &[u8] = &[0xA7, 0x00, 0x03, 0x00, 0x00, 0xB1];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        let required: BTreeSet<u32> = required_frame_offsets(&insns);
        assert!(
            required.contains(&3),
            "goto target at pc 3 must require a frame: {required:?}"
        );
    }

    #[test]
    fn absent_table_with_branches_is_inconsistent() {
        let code: &[u8] = &[0x99, 0x00, 0x04, 0x00, 0x00, 0xB1];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        let info: Vec<u8> = build_code_info(code, &[]);
        let report: StackMapReport = analyze_stack_map(&info, code.len(), &insns, &|_| None);
        assert!(!report.present);
        assert!(!report.consistent);
        assert!(!report.missing_offsets.is_empty());
    }

    #[test]
    fn straight_line_method_without_table_is_consistent() {
        let code: &[u8] = &[0x04, 0xAC];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        let info: Vec<u8> = build_code_info(code, &[]);
        let report: StackMapReport = analyze_stack_map(&info, code.len(), &insns, &|_| None);
        assert!(
            report.consistent,
            "no branches means no frames required: {report:?}"
        );
    }

    #[test]
    fn matching_table_is_consistent() {
        let code: &[u8] = &[0x99, 0x00, 0x04, 0x00, 0x00, 0xB1];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        let mut table: Vec<u8> = Vec::new();
        table.extend_from_slice(&1u16.to_be_bytes());
        table.push(4);
        let info: Vec<u8> = build_code_info(code, &[(1u16, &table)]);
        let report: StackMapReport = analyze_stack_map(&info, code.len(), &insns, &|idx: u16| {
            (idx == 1).then(|| "StackMapTable".to_owned())
        });
        assert!(report.present);
        assert_eq!(report.declared_offsets, vec![4]);
        assert!(report.consistent, "{report:?}");
    }

    #[test]
    fn entry_frame_locals_for_instance_method() {
        let desc: MethodDescriptor = MethodDescriptor {
            params: vec![
                JavaType::Int,
                JavaType::Long,
                JavaType::Object("java/lang/String".to_owned()),
            ],
            returns: JavaType::Void,
        };
        let locals: Vec<VerificationType> = entry_frame_locals(&desc, false, false, "Sample");
        assert_eq!(
            locals,
            vec![
                VerificationType::Object("Sample".to_owned()),
                VerificationType::Integer,
                VerificationType::Long,
                VerificationType::Top,
                VerificationType::Object("java/lang/String".to_owned()),
            ]
        );
    }

    #[test]
    fn entry_frame_locals_for_static_and_ctor() {
        let desc: MethodDescriptor = MethodDescriptor {
            params: vec![JavaType::Double],
            returns: JavaType::Void,
        };
        let static_locals: Vec<VerificationType> = entry_frame_locals(&desc, true, false, "Sample");
        assert_eq!(
            static_locals,
            vec![VerificationType::Double, VerificationType::Top]
        );
        let ctor_locals: Vec<VerificationType> = entry_frame_locals(
            &MethodDescriptor {
                params: Vec::new(),
                returns: JavaType::Void,
            },
            false,
            true,
            "Sample",
        );
        assert_eq!(ctor_locals, vec![VerificationType::UninitializedThis]);
    }

    #[test]
    fn analyze_with_entry_frame_populates_locals() {
        let code: &[u8] = &[0x04, 0xAC];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        let info: Vec<u8> = build_code_info(code, &[]);
        let desc: MethodDescriptor = MethodDescriptor {
            params: vec![
                JavaType::Int,
                JavaType::Object("Ljava/lang/String;".to_owned()),
            ],
            returns: JavaType::Int,
        };
        let report: StackMapReport = analyze_stack_map_with_entry_frame(
            &info,
            code.len(),
            &insns,
            &desc,
            false,
            false,
            "Sample",
            &|_| None,
        );
        assert_eq!(
            report.entry_frame,
            vec![
                VerificationType::Object("Sample".to_owned()),
                VerificationType::Integer,
                VerificationType::Object("Ljava/lang/String;".to_owned()),
            ]
        );
    }

    #[test]
    fn stack_map_lookup_rejects_offset_overflow() {
        let lookup: fn(u16) -> Option<String> = |_| None;
        assert_eq!(find_stack_map_table(&[], usize::MAX, &lookup), None);
    }

    fn build_code_info(code: &[u8], attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&(code.len() as u32).to_be_bytes());
        info.extend_from_slice(code);
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        for (name_index, body) in attributes {
            info.extend_from_slice(&name_index.to_be_bytes());
            info.extend_from_slice(&(body.len() as u32).to_be_bytes());
            info.extend_from_slice(body);
        }
        info
    }
}
