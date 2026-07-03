use super::*;
use crate::bytecode::CodeAttribute;
use crate::classfile::{Attribute, ConstantPoolEntry, MethodInfo};

fn code_attr(body: Vec<u8>) -> CodeAttribute {
    CodeAttribute {
        max_stack: 8,
        max_locals: 8,
        code: body,
        exception_table: Vec::new(),
        dropped_exception_entries: 0,
    }
}

enum Item {
    Op(u8),
    Goto(usize),
    LookupSwitch {
        default: usize,
        pairs: Vec<(i32, usize)>,
    },
}

fn assemble(items: &[Item]) -> Vec<u8> {
    let mut pcs: Vec<u32> = Vec::with_capacity(items.len());
    let mut pc: usize = 0;
    for item in items {
        pcs.push(pc as u32);
        let size: usize = match item {
            Item::Op(_) => 1,
            Item::Goto(_) => 3,
            Item::LookupSwitch { pairs, .. } => {
                let after_op: usize = pc + 1;
                let pad: usize = (4 - (after_op % 4)) % 4;
                1 + pad + 4 + 4 + pairs.len() * 8
            }
        };
        pc += size;
    }
    let mut out: Vec<u8> = Vec::with_capacity(pc);
    for (i, item) in items.iter().enumerate() {
        let here: i32 = pcs[i] as i32;
        match item {
            Item::Op(op) => out.push(*op),
            Item::Goto(target) => {
                out.push(0xA7);
                let rel: i32 = pcs[*target] as i32 - here;
                out.extend_from_slice(&(rel as i16).to_be_bytes());
            }
            Item::LookupSwitch { default, pairs } => {
                out.push(0xAB);
                let pad: usize = (4 - (out.len() % 4)) % 4;
                out.extend(std::iter::repeat_n(0x00u8, pad));
                let default_rel: i32 = pcs[*default] as i32 - here;
                out.extend_from_slice(&default_rel.to_be_bytes());
                out.extend_from_slice(&(pairs.len() as i32).to_be_bytes());
                for (k, target) in pairs {
                    out.extend_from_slice(&k.to_be_bytes());
                    let rel: i32 = pcs[*target] as i32 - here;
                    out.extend_from_slice(&rel.to_be_bytes());
                }
            }
        }
    }
    out
}

fn flattened_two_state_method() -> Vec<u8> {
    const DISPATCHER: usize = 3;
    const CASE0: usize = 5;
    const CASE1: usize = 10;
    const DEFAULT: usize = 12;
    let items: Vec<Item> = vec![
        Item::Op(0x03),
        Item::Op(0x3D),
        Item::Goto(DISPATCHER),
        Item::Op(0x1C),
        Item::LookupSwitch {
            default: DEFAULT,
            pairs: vec![(0, CASE0), (1, CASE1)],
        },
        Item::Op(0x05),
        Item::Op(0x3C),
        Item::Op(0x04),
        Item::Op(0x3D),
        Item::Goto(DISPATCHER),
        Item::Op(0x1B),
        Item::Op(0xAC),
        Item::Op(0x04),
        Item::Op(0xAC),
    ];
    assemble(&items)
}

#[test]
fn flattened_method_is_unflattened_and_structures_cleanly() {
    let mut cb_cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cb_cp.push(ConstantPoolEntry::Utf8("Code".into()));
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cb_cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let body: Vec<u8> = flattened_two_state_method();
    let code: CodeAttribute = code_attr(body);
    let result: MethodCff = unflatten_method(&cf, &code).expect("method unflattens");
    assert!(result.flattened, "the fixture is a state-dispatcher method");
    assert!(
        result.report.dispatchers_unflattened >= 1,
        "the real sccp engine must redirect the dispatcher, not count gotos"
    );
    assert!(
        result.fully_structured,
        "after unflattening the structurer must reduce the CFG with no residual switch"
    );
    assert_eq!(
        result.residual_switch_regions, 0,
        "the dispatcher switch must be gone from the structured form"
    );
}

#[test]
fn clean_method_is_not_flagged_flattened() {
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: vec![ConstantPoolEntry::Placeholder],
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let code: CodeAttribute = code_attr(vec![0x04, 0xAC]);
    let result: MethodCff = unflatten_method(&cf, &code).expect("trivial method");
    assert!(!result.flattened, "a clean method has no state dispatcher");
    assert_eq!(result.report.dispatchers_unflattened, 0);
}

#[test]
fn class_level_aggregate_counts_one_flattened_method() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8("Code".into()));
    let code_name: u16 = 1;
    let body: Vec<u8> = flattened_two_state_method();
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&8u16.to_be_bytes());
    info.extend_from_slice(&8u16.to_be_bytes());
    info.extend_from_slice(&(body.len() as u32).to_be_bytes());
    info.extend_from_slice(&body);
    info.extend_from_slice(&0u16.to_be_bytes());
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![MethodInfo {
            access_flags: 0x0009,
            name_index: 0,
            descriptor_index: 0,
            attributes: vec![Attribute {
                name_index: code_name,
                info,
            }],
        }],
        attributes: Vec::new(),
    };
    let report: CffReport = unflatten_class(&cf);
    assert_eq!(report.methods_scanned, 1);
    assert_eq!(report.flattened_methods, 1);
    assert_eq!(report.methods_fully_structured, 1);
    assert!(report.dispatchers_unflattened >= 1);
    assert_eq!(report.residual_switch_regions, 0);
}
