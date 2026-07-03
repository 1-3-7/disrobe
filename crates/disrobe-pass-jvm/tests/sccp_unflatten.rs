#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    Attribute, ClassFile, ConstantPoolEntry, DecompiledClass, MethodInfo, decompile_class,
};

const ACC_PUBLIC: u16 = 0x0001;
const ACC_STATIC: u16 = 0x0008;

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

fn flattened_dispatcher_body() -> Vec<u8> {
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

fn cp_utf8(s: &str) -> ConstantPoolEntry {
    ConstantPoolEntry::Utf8(s.to_string())
}

fn flattened_class() -> ClassFile {
    let cp: Vec<ConstantPoolEntry> = vec![
        ConstantPoolEntry::Placeholder,
        cp_utf8("com/example/Flat"),
        ConstantPoolEntry::Class { name_index: 1 },
        cp_utf8("java/lang/Object"),
        ConstantPoolEntry::Class { name_index: 3 },
        cp_utf8("compute"),
        cp_utf8("()I"),
        cp_utf8("Code"),
    ];
    let code_body: Vec<u8> = flattened_dispatcher_body();
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&8u16.to_be_bytes());
    info.extend_from_slice(&8u16.to_be_bytes());
    info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
    info.extend_from_slice(&code_body);
    info.extend_from_slice(&0u16.to_be_bytes());
    ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: ACC_PUBLIC,
        this_class: 2,
        super_class: 4,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![MethodInfo {
            access_flags: ACC_PUBLIC | ACC_STATIC,
            name_index: 5,
            descriptor_index: 6,
            attributes: vec![Attribute {
                name_index: 7,
                info,
            }],
        }],
        attributes: Vec::new(),
    }
}

#[test]
fn flattened_dispatcher_method_decompiles_to_structured_source() {
    let cf: ClassFile = flattened_class();
    let d: DecompiledClass = decompile_class(&cf);
    let src: &str = &d.source;

    assert!(
        !src.contains("irreducible"),
        "flattened method must not fall back to an irreducible region:\n{src}"
    );
    assert!(
        !src.contains("goto L") && !src.contains("(stack reset)"),
        "flattened method must not leave goto-soup fallback markers:\n{src}"
    );
    assert!(
        !src.contains("switch ("),
        "the dispatcher switch must be eliminated, not emitted:\n{src}"
    );
    assert!(
        src.contains("return"),
        "decompiled flattened method should recover a return:\n{src}"
    );
    assert_eq!(
        src.matches("return").count(),
        1,
        "the unreachable default branch must be pruned, leaving a single return:\n{src}"
    );
    assert!(
        src.contains("= 2;"),
        "the resolved dispatcher path should assign the original constant:\n{src}"
    );
    assert_eq!(
        d.fully_lifted_methods, 1,
        "the single flattened method should be fully lifted after unflattening:\n{src}"
    );
}
