use super::*;
use crate::classfile::{Attribute, ConstantPoolEntry, FieldInfo, MethodInfo};

struct ClassBuilder {
    cp: Vec<ConstantPoolEntry>,
}

impl ClassBuilder {
    fn new() -> Self {
        Self {
            cp: vec![ConstantPoolEntry::Placeholder],
        }
    }

    fn push(&mut self, entry: ConstantPoolEntry) -> u16 {
        self.cp.push(entry);
        u16::try_from(self.cp.len() - 1).unwrap()
    }

    fn utf8(&mut self, s: &str) -> u16 {
        self.push(ConstantPoolEntry::Utf8(s.into()))
    }

    fn string(&mut self, s: &str) -> u16 {
        let u: u16 = self.utf8(s);
        self.push(ConstantPoolEntry::String { utf8_index: u })
    }

    fn class(&mut self, name: &str) -> u16 {
        let u: u16 = self.utf8(name);
        self.push(ConstantPoolEntry::Class { name_index: u })
    }

    fn methodref(&mut self, owner: &str, name: &str, desc: &str) -> u16 {
        let c: u16 = self.class(owner);
        let n: u16 = self.utf8(name);
        let d: u16 = self.utf8(desc);
        let nt: u16 = self.push(ConstantPoolEntry::NameAndType {
            name_index: n,
            descriptor_index: d,
        });
        self.push(ConstantPoolEntry::Methodref {
            class_index: c,
            name_and_type_index: nt,
        })
    }

    fn integer(&mut self, v: i32) -> u16 {
        self.push(ConstantPoolEntry::Integer(v))
    }
}

fn code_attr(name_index: u16, max_locals: u16, code: &[u8]) -> Attribute {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&16u16.to_be_bytes());
    info.extend_from_slice(&max_locals.to_be_bytes());
    info.extend_from_slice(&(code.len() as u32).to_be_bytes());
    info.extend_from_slice(code);
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    Attribute { name_index, info }
}

fn make_class(cb: ClassBuilder, fields: Vec<FieldInfo>, methods: Vec<MethodInfo>) -> ClassFile {
    ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cb.cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields,
        methods,
        attributes: Vec::new(),
    }
}

fn const_key_xor_decrypt_code(
    key: u8,
    tochararray_ref: u16,
    new_string_ref: u16,
    string_class: u16,
) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();
    c.push(0x2A);
    c.push(0xB6);
    c.extend_from_slice(&tochararray_ref.to_be_bytes());
    c.push(0x4C);
    c.push(0x03);
    c.push(0x3D);
    let loop_start: usize = c.len();
    c.push(0x1C);
    c.push(0x2B);
    c.push(0xBE);
    c.push(0xA2);
    let exit_branch_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    c.push(0x2B);
    c.push(0x1C);
    c.push(0x2B);
    c.push(0x1C);
    c.push(0x34);
    c.push(0x10);
    c.push(key);
    c.push(0x82);
    c.push(0x91);
    c.push(0x55);
    c.push(0x84);
    c.push(0x02);
    c.push(0x01);
    c.push(0xA7);
    let back_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    let exit_pc: usize = c.len();
    c.push(0xBB);
    c.extend_from_slice(&string_class.to_be_bytes());
    c.push(0x59);
    c.push(0x2B);
    c.push(0xB7);
    c.extend_from_slice(&new_string_ref.to_be_bytes());
    c.push(0xB0);

    let exit_target: i16 =
        i16::try_from(exit_pc).unwrap() - i16::try_from(exit_branch_pos - 1).unwrap();
    c[exit_branch_pos] = exit_target.to_be_bytes()[0];
    c[exit_branch_pos + 1] = exit_target.to_be_bytes()[1];
    let back_target: i16 =
        i16::try_from(loop_start).unwrap() - i16::try_from(back_pos - 1).unwrap();
    c[back_pos] = back_target.to_be_bytes()[0];
    c[back_pos + 1] = back_target.to_be_bytes()[1];
    c
}

#[test]
fn recovers_constant_key_xor_via_bytecode_emulation() {
    let key: u8 = 0x3F;
    let plain: &str = "https://api.example.com/v1/secret";
    let encrypted: String = plain
        .encode_utf16()
        .map(|u| u ^ u16::from(key))
        .map(|u| char::from_u32(u32::from(u)).unwrap())
        .collect();

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("a");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let tochararray: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");
    let string_class: u16 = cb.class("java/lang/String");
    let lit: u16 = cb.string(&encrypted);
    let self_decrypt: u16 = cb.methodref("Sample", "a", "(Ljava/lang/String;)Ljava/lang/String;");

    let code: Vec<u8> = const_key_xor_decrypt_code(key, tochararray, new_string, string_class);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 3, &code)],
    };
    let caller_name: u16 = cb.utf8("run");
    let caller_desc: u16 = cb.utf8("()V");
    let mut caller_code: Vec<u8> = Vec::new();
    caller_code.push(0x13);
    caller_code.extend_from_slice(&lit.to_be_bytes());
    caller_code.push(0xB8);
    caller_code.extend_from_slice(&self_decrypt.to_be_bytes());
    caller_code.push(0x57);
    caller_code.push(0xB1);
    let caller: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: caller_name,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 1, &caller_code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method, caller]);

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    assert_eq!(stubs.len(), 1);
    let out: String =
        emulate_string_decrypt(&cf, &stubs[0], &encrypted, 0).expect("emulate decrypt");
    assert_eq!(out, plain);

    let report: StringRecoveryReport = recover_strings(&cf);
    assert_eq!(report.decrypt_methods, 1);
    assert_eq!(
        report.recovered.values().next().map(String::as_str),
        Some(plain)
    );
}

fn position_key_xor_decrypt_code(
    base: i32,
    tochararray_ref: u16,
    new_string_ref: u16,
    string_class: u16,
    base_const: u16,
) -> Vec<u8> {
    let _ = base;
    let mut c: Vec<u8> = Vec::new();
    c.push(0x2A);
    c.push(0xB6);
    c.extend_from_slice(&tochararray_ref.to_be_bytes());
    c.push(0x4D);
    c.push(0x03);
    c.push(0x3E);
    let loop_start: usize = c.len();
    c.push(0x1D);
    c.push(0x2C);
    c.push(0xBE);
    c.push(0xA2);
    let exit_branch_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    c.push(0x2C);
    c.push(0x1D);
    c.push(0x2C);
    c.push(0x1D);
    c.push(0x34);
    c.push(0x13);
    c.extend_from_slice(&base_const.to_be_bytes());
    c.push(0x1D);
    c.push(0x60);
    c.push(0x1B);
    c.push(0x60);
    c.push(0x82);
    c.push(0x91);
    c.push(0x55);
    c.push(0x84);
    c.push(0x03);
    c.push(0x01);
    c.push(0xA7);
    let back_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    let exit_pc: usize = c.len();
    c.push(0xBB);
    c.extend_from_slice(&string_class.to_be_bytes());
    c.push(0x59);
    c.push(0x2C);
    c.push(0xB7);
    c.extend_from_slice(&new_string_ref.to_be_bytes());
    c.push(0xB0);

    let exit_target: i16 =
        i16::try_from(exit_pc).unwrap() - i16::try_from(exit_branch_pos - 1).unwrap();
    c[exit_branch_pos] = exit_target.to_be_bytes()[0];
    c[exit_branch_pos + 1] = exit_target.to_be_bytes()[1];
    let back_target: i16 =
        i16::try_from(loop_start).unwrap() - i16::try_from(back_pos - 1).unwrap();
    c[back_pos] = back_target.to_be_bytes()[0];
    c[back_pos + 1] = back_target.to_be_bytes()[1];
    c
}

#[test]
fn recovers_position_dependent_xor_with_int_seed() {
    let base: i32 = 0x2A;
    let seed: i32 = 7;
    let plain: &str = "db.password=hunter2";
    let encrypted: String = plain
        .encode_utf16()
        .enumerate()
        .map(|(i, u)| {
            let k: i32 = (base + (i as i32) + seed) & 0xFF;
            let x: u16 = u ^ (k as u16);
            char::from_u32(u32::from(x)).unwrap()
        })
        .collect();

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("b");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/String;I)Ljava/lang/String;");
    let tochararray: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");
    let string_class: u16 = cb.class("java/lang/String");
    let base_const: u16 = cb.integer(base);

    let code: Vec<u8> =
        position_key_xor_decrypt_code(base, tochararray, new_string, string_class, base_const);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 4, &code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method]);

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    assert_eq!(stubs.len(), 1);
    assert!(stubs[0].takes_int_seed());
    let out: String =
        emulate_string_decrypt(&cf, &stubs[0], &encrypted, seed).expect("emulate decrypt");
    assert_eq!(out, plain);
}

fn builder_xor_decrypt_code(
    key: u8,
    charat_ref: u16,
    length_ref: u16,
    sb_new: u16,
    sb_init: u16,
    sb_append: u16,
    sb_tostring: u16,
) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();
    c.push(0xBB);
    c.extend_from_slice(&sb_new.to_be_bytes());
    c.push(0x59);
    c.push(0xB7);
    c.extend_from_slice(&sb_init.to_be_bytes());
    c.push(0x4C);
    c.push(0x03);
    c.push(0x3D);
    let loop_start: usize = c.len();
    c.push(0x1C);
    c.push(0x2A);
    c.push(0xB6);
    c.extend_from_slice(&length_ref.to_be_bytes());
    c.push(0xA2);
    let exit_branch_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    c.push(0x2B);
    c.push(0x2A);
    c.push(0x1C);
    c.push(0xB6);
    c.extend_from_slice(&charat_ref.to_be_bytes());
    c.push(0x10);
    c.push(key);
    c.push(0x82);
    c.push(0x92);
    c.push(0xB6);
    c.extend_from_slice(&sb_append.to_be_bytes());
    c.push(0x57);
    c.push(0x84);
    c.push(0x02);
    c.push(0x01);
    c.push(0xA7);
    let back_pos: usize = c.len();
    c.extend_from_slice(&[0x00, 0x00]);
    let exit_pc: usize = c.len();
    c.push(0x2B);
    c.push(0xB6);
    c.extend_from_slice(&sb_tostring.to_be_bytes());
    c.push(0xB0);

    let exit_target: i16 =
        i16::try_from(exit_pc).unwrap() - i16::try_from(exit_branch_pos - 1).unwrap();
    c[exit_branch_pos] = exit_target.to_be_bytes()[0];
    c[exit_branch_pos + 1] = exit_target.to_be_bytes()[1];
    let back_target: i16 =
        i16::try_from(loop_start).unwrap() - i16::try_from(back_pos - 1).unwrap();
    c[back_pos] = back_target.to_be_bytes()[0];
    c[back_pos + 1] = back_target.to_be_bytes()[1];
    c
}

#[test]
fn recovers_stringbuilder_decrypt() {
    let key: u8 = 0x55;
    let plain: &str = "ENCRYPTION_KEY_v3";
    let encrypted: String = plain
        .encode_utf16()
        .map(|u| u ^ u16::from(key))
        .map(|u| char::from_u32(u32::from(u)).unwrap())
        .collect();

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("c");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let charat: u16 = cb.methodref("java/lang/String", "charAt", "(I)C");
    let length: u16 = cb.methodref("java/lang/String", "length", "()I");
    let sb_new: u16 = cb.class("java/lang/StringBuilder");
    let sb_init: u16 = cb.methodref("java/lang/StringBuilder", "<init>", "()V");
    let sb_append: u16 = cb.methodref(
        "java/lang/StringBuilder",
        "append",
        "(C)Ljava/lang/StringBuilder;",
    );
    let sb_tostring: u16 = cb.methodref(
        "java/lang/StringBuilder",
        "toString",
        "()Ljava/lang/String;",
    );
    let _lit: u16 = cb.string(&encrypted);

    let code: Vec<u8> =
        builder_xor_decrypt_code(key, charat, length, sb_new, sb_init, sb_append, sb_tostring);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 3, &code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method]);

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    assert_eq!(stubs.len(), 1);
    let out: String =
        emulate_string_decrypt(&cf, &stubs[0], &encrypted, 0).expect("emulate decrypt");
    assert_eq!(out, plain);

    let report: StringRecoveryReport = recover_strings(&cf);
    assert_eq!(
        report.recovered.values().next().map(String::as_str),
        Some(plain)
    );
}

#[test]
fn runtime_key_wall_flagged() {
    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("d");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let getprop: u16 = cb.methodref(
        "java/lang/System",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;",
    );

    let mut code: Vec<u8> = Vec::new();
    code.push(0x2A);
    code.push(0xB8);
    code.extend_from_slice(&getprop.to_be_bytes());
    code.push(0xB0);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 2, &code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method]);

    let report: StringRecoveryReport = recover_strings(&cf);
    assert!(report.runtime_key_wall);
}

#[test]
fn literal_seeded_random_signature_is_not_runtime_key() {
    assert_eq!(
        random_signature("java/util/Random.<init>:(J)V"),
        RandomSignature::DeterministicSeed
    );
    assert_eq!(
        random_signature("java/util/Random.setSeed:(J)V"),
        RandomSignature::DeterministicSeed
    );
    assert_eq!(
        random_signature("java/util/Random.nextInt:(I)I"),
        RandomSignature::DeterministicDraw
    );
    assert_eq!(
        random_signature("java/util/Random.<init>:()V"),
        RandomSignature::UnseededCtor
    );
    assert!(is_non_random_runtime_key_signature(
        "java/security/SecureRandom.nextInt:()I"
    ));
}

#[test]
fn stringer_stacktrace_key_flagged_as_walled() {
    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("a");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/Object;)Ljava/lang/String;");
    let get_stack: u16 = cb.methodref(
        "java/lang/Thread",
        "getStackTrace",
        "()[Ljava/lang/StackTraceElement;",
    );

    let mut code: Vec<u8> = Vec::new();
    code.push(0x2A);
    code.push(0xB8);
    code.extend_from_slice(&get_stack.to_be_bytes());
    code.push(0xB0);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 2, &code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method]);

    let report: StringRecoveryReport = recover_strings(&cf);
    assert!(
        report.runtime_key_wall,
        "stringer-style stack-frame-keyed decrypt must be flagged walled, not faked"
    );
}

#[test]
fn ignores_classes_without_decrypt_method() {
    let mut cb: ClassBuilder = ClassBuilder::new();
    let _lit: u16 = cb.string("\u{1}\u{2}\u{3}\u{4}");
    let cf: ClassFile = make_class(cb, Vec::new(), Vec::new());
    let report: StringRecoveryReport = recover_strings(&cf);
    assert_eq!(report.decrypt_methods, 0);
    assert!(report.recovered.is_empty());
}

#[test]
fn recovers_allatori_object_signature_decrypt() {
    let key: u8 = 0x55;
    let plain: &str = "C:/Windows/System32/payload.dll";
    let encrypted: String = plain
        .encode_utf16()
        .map(|u| u ^ u16::from(key))
        .map(|u| char::from_u32(u32::from(u)).unwrap())
        .collect();

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let decrypt_name: u16 = cb.utf8("d");
    let decrypt_desc: u16 = cb.utf8("(Ljava/lang/Object;)Ljava/lang/String;");
    let tochararray: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");
    let string_class: u16 = cb.class("java/lang/String");
    let lit: u16 = cb.string(&encrypted);
    let self_decrypt: u16 = cb.methodref("Sample", "d", "(Ljava/lang/Object;)Ljava/lang/String;");

    let code: Vec<u8> = const_key_xor_decrypt_code(key, tochararray, new_string, string_class);
    let method: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: decrypt_name,
        descriptor_index: decrypt_desc,
        attributes: vec![code_attr(code_name, 3, &code)],
    };
    let caller_name: u16 = cb.utf8("run");
    let caller_desc: u16 = cb.utf8("()V");
    let mut caller_code: Vec<u8> = Vec::new();
    caller_code.push(0x13);
    caller_code.extend_from_slice(&lit.to_be_bytes());
    caller_code.push(0xB8);
    caller_code.extend_from_slice(&self_decrypt.to_be_bytes());
    caller_code.push(0x57);
    caller_code.push(0xB1);
    let caller: MethodInfo = MethodInfo {
        access_flags: 0x0008,
        name_index: caller_name,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 1, &caller_code)],
    };
    let cf: ClassFile = make_class(cb, Vec::new(), vec![method, caller]);

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    assert_eq!(
        stubs.len(),
        1,
        "the (Object)->String entry point must be recognized"
    );
    let report: StringRecoveryReport = recover_strings(&cf);
    assert_eq!(report.decrypt_methods, 1);
    assert_eq!(
        report.recovered.values().next().map(String::as_str),
        Some(plain),
        "the Allatori-style (Object)->String decrypt must recover cleartext"
    );
}
