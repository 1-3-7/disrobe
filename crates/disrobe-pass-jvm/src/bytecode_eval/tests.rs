use super::*;
use crate::classfile::{Attribute, ConstantPoolEntry, MethodInfo};

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

    fn long(&mut self, value: i64) -> u16 {
        self.push(ConstantPoolEntry::Long(value))
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
}

fn code_attr(name_index: u16, max_stack: u16, max_locals: u16, code: &[u8]) -> Attribute {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&max_stack.to_be_bytes());
    info.extend_from_slice(&max_locals.to_be_bytes());
    info.extend_from_slice(&(code.len() as u32).to_be_bytes());
    info.extend_from_slice(code);
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    Attribute { name_index, info }
}

fn assemble(cb: ClassBuilder, this_class: u16, methods: Vec<MethodInfo>) -> ClassFile {
    ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cb.cp,
        access_flags: 0,
        this_class,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods,
        attributes: Vec::new(),
    }
}

#[test]
fn descriptor_arg_slots_counts_long_and_double_as_two() {
    assert_eq!(descriptor_arg_slots("()V"), 0);
    assert_eq!(
        descriptor_arg_slots("(Ljava/lang/String;)Ljava/lang/String;"),
        1
    );
    assert_eq!(
        descriptor_arg_slots("(Ljava/lang/String;I)Ljava/lang/String;"),
        2
    );
    assert_eq!(descriptor_arg_slots("(JD)V"), 4);
    assert_eq!(descriptor_arg_slots("([CII)V"), 3);
    assert_eq!(descriptor_arg_slots("([Ljava/lang/String;I)V"), 2);
}

#[test]
fn java_string_hash_matches_jdk() {
    assert_eq!(
        java_string_hash(&"hello".encode_utf16().collect::<Vec<u16>>()),
        99162322
    );
    assert_eq!(
        java_string_hash(&"".encode_utf16().collect::<Vec<u16>>()),
        0
    );
    assert_eq!(
        java_string_hash(&"a".encode_utf16().collect::<Vec<u16>>()),
        97
    );
}

fn caller_key(class_name: &str, method_name: &str) -> u8 {
    let mut h: i32 = 0;
    for c in class_name.chars() {
        h = h.wrapping_mul(31).wrapping_add(c as i32);
    }
    for c in method_name.chars() {
        h = h.wrapping_mul(31).wrapping_add(c as i32);
    }
    (h & 0x7F) as u8
}

fn encrypt(plain: &str, key: u8) -> String {
    plain
        .encode_utf16()
        .enumerate()
        .map(|(i, u)| {
            let k: u16 = u16::from(key.wrapping_add(i as u8) & 0x7F);
            char::from_u32(u32::from(u ^ k)).unwrap()
        })
        .collect()
}

fn xor_with_key(plain: &str, key: u8) -> String {
    plain
        .encode_utf16()
        .map(|u: u16| char::from_u32(u32::from(u ^ u16::from(key))).unwrap())
        .collect()
}

#[test]
fn java_random_state_matches_jdk_oracle() {
    let mut bounded: JavaRandomState = JavaRandomState::from_user_seed(123456789);
    assert_eq!(bounded.next_bounded_int(127), Ok(101));

    let mut unbounded: JavaRandomState = JavaRandomState::from_user_seed(123456789);
    assert_eq!(unbounded.next_int(), -1_442_945_365);
}

#[test]
fn recovers_caller_keyed_via_synthetic_stack_trace() {
    let owner: &str = "com/example/Crypt";
    let caller_method: &str = "load";
    let key: u8 = caller_key(owner, caller_method);
    let plain: &str = "redis://cache:6379/secrets";
    let cipher: String = encrypt(plain, key);

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let this_class: u16 = cb.class(owner);

    let ck_name: u16 = cb.utf8("ck");
    let ck_desc: u16 = cb.utf8("(Ljava/lang/String;Ljava/lang/String;)I");
    let str_len: u16 = cb.methodref("java/lang/String", "length", "()I");
    let str_char_at: u16 = cb.methodref("java/lang/String", "charAt", "(I)C");
    let mut ck: Vec<u8> = Vec::new();
    ck.push(0x03);
    ck.push(0x3D);
    ck.push(0x03);
    ck.push(0x36);
    ck.push(0x04);
    let l0: usize = ck.len();
    ck.push(0x15);
    ck.push(0x04);
    ck.push(0x2A);
    ck.push(0xB6);
    ck.extend_from_slice(&str_len.to_be_bytes());
    ck.push(0xA2);
    let b0: usize = ck.len();
    ck.extend_from_slice(&[0, 0]);
    ck.push(0x1C);
    ck.push(0x10);
    ck.push(31);
    ck.push(0x68);
    ck.push(0x2A);
    ck.push(0x15);
    ck.push(0x04);
    ck.push(0xB6);
    ck.extend_from_slice(&str_char_at.to_be_bytes());
    ck.push(0x60);
    ck.push(0x3D);
    ck.push(0x84);
    ck.push(0x04);
    ck.push(0x01);
    ck.push(0xA7);
    let g0: usize = ck.len();
    ck.extend_from_slice(&[0, 0]);
    let e0: usize = ck.len();
    ck.push(0x03);
    ck.push(0x36);
    ck.push(0x04);
    let l1: usize = ck.len();
    ck.push(0x15);
    ck.push(0x04);
    ck.push(0x2B);
    ck.push(0xB6);
    ck.extend_from_slice(&str_len.to_be_bytes());
    ck.push(0xA2);
    let b1: usize = ck.len();
    ck.extend_from_slice(&[0, 0]);
    ck.push(0x1C);
    ck.push(0x10);
    ck.push(31);
    ck.push(0x68);
    ck.push(0x2B);
    ck.push(0x15);
    ck.push(0x04);
    ck.push(0xB6);
    ck.extend_from_slice(&str_char_at.to_be_bytes());
    ck.push(0x60);
    ck.push(0x3D);
    ck.push(0x84);
    ck.push(0x04);
    ck.push(0x01);
    ck.push(0xA7);
    let g1: usize = ck.len();
    ck.extend_from_slice(&[0, 0]);
    let e1: usize = ck.len();
    ck.push(0x1C);
    ck.push(0x10);
    ck.push(127);
    ck.push(0x7E);
    ck.push(0xAC);
    patch(&mut ck, b0, e0);
    patch(&mut ck, g0, l0);
    patch(&mut ck, b1, e1);
    patch(&mut ck, g1, l1);
    let ck_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: ck_name,
        descriptor_index: ck_desc,
        attributes: vec![code_attr(code_name, 6, 5, &ck)],
    };

    let dec_name: u16 = cb.utf8("dec");
    let dec_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let throwable: u16 = cb.class("java/lang/Throwable");
    let thr_init: u16 = cb.methodref("java/lang/Throwable", "<init>", "()V");
    let get_stack: u16 = cb.methodref(
        "java/lang/Throwable",
        "getStackTrace",
        "()[Ljava/lang/StackTraceElement;",
    );
    let ste_class: u16 = cb.methodref(
        "java/lang/StackTraceElement",
        "getClassName",
        "()Ljava/lang/String;",
    );
    let replace: u16 = cb.methodref("java/lang/String", "replace", "(CC)Ljava/lang/String;");
    let ste_method: u16 = cb.methodref(
        "java/lang/StackTraceElement",
        "getMethodName",
        "()Ljava/lang/String;",
    );
    let self_ck: u16 = cb.methodref(owner, "ck", "(Ljava/lang/String;Ljava/lang/String;)I");
    let to_chars: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.class("java/lang/String");
    let str_chars_init: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");

    let mut dec: Vec<u8> = Vec::new();
    dec.push(0xBB);
    dec.extend_from_slice(&throwable.to_be_bytes());
    dec.push(0x59);
    dec.push(0xB7);
    dec.extend_from_slice(&thr_init.to_be_bytes());
    dec.push(0xB6);
    dec.extend_from_slice(&get_stack.to_be_bytes());
    dec.push(0x04);
    dec.push(0x32);
    dec.push(0x4C);
    dec.push(0x2B);
    dec.push(0xB6);
    dec.extend_from_slice(&ste_class.to_be_bytes());
    dec.push(0x10);
    dec.push(46);
    dec.push(0x10);
    dec.push(47);
    dec.push(0xB6);
    dec.extend_from_slice(&replace.to_be_bytes());
    dec.push(0x4D);
    dec.push(0x2C);
    dec.push(0x2B);
    dec.push(0xB6);
    dec.extend_from_slice(&ste_method.to_be_bytes());
    dec.push(0xB8);
    dec.extend_from_slice(&self_ck.to_be_bytes());
    dec.push(0x3E);
    dec.push(0x2A);
    dec.push(0xB6);
    dec.extend_from_slice(&to_chars.to_be_bytes());
    dec.push(0x3A);
    dec.push(0x04);
    dec.push(0x03);
    dec.push(0x36);
    dec.push(0x05);
    let dl: usize = dec.len();
    dec.push(0x15);
    dec.push(0x05);
    dec.push(0x19);
    dec.push(0x04);
    dec.push(0xBE);
    dec.push(0xA2);
    let db: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    dec.push(0x19);
    dec.push(0x04);
    dec.push(0x15);
    dec.push(0x05);
    dec.push(0x19);
    dec.push(0x04);
    dec.push(0x15);
    dec.push(0x05);
    dec.push(0x34);
    dec.push(0x1D);
    dec.push(0x15);
    dec.push(0x05);
    dec.push(0x60);
    dec.push(0x10);
    dec.push(127);
    dec.push(0x7E);
    dec.push(0x82);
    dec.push(0x91);
    dec.push(0x55);
    dec.push(0x84);
    dec.push(0x05);
    dec.push(0x01);
    dec.push(0xA7);
    let dg: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    let de: usize = dec.len();
    dec.push(0xBB);
    dec.extend_from_slice(&new_string.to_be_bytes());
    dec.push(0x59);
    dec.push(0x19);
    dec.push(0x04);
    dec.push(0xB7);
    dec.extend_from_slice(&str_chars_init.to_be_bytes());
    dec.push(0xB0);
    patch(&mut dec, db, de);
    patch(&mut dec, dg, dl);
    let dec_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: dec_name,
        descriptor_index: dec_desc,
        attributes: vec![code_attr(code_name, 7, 6, &dec)],
    };

    let lit: u16 = cb.string(&cipher);
    let caller_name_idx: u16 = cb.utf8(caller_method);
    let caller_desc: u16 = cb.utf8("()Ljava/lang/String;");
    let self_dec: u16 = cb.methodref(owner, "dec", "(Ljava/lang/String;)Ljava/lang/String;");
    let mut caller: Vec<u8> = Vec::new();
    caller.push(0x13);
    caller.extend_from_slice(&lit.to_be_bytes());
    caller.push(0xB8);
    caller.extend_from_slice(&self_dec.to_be_bytes());
    caller.push(0xB0);
    let caller_method_info: MethodInfo = MethodInfo {
        access_flags: 0x0009,
        name_index: caller_name_idx,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 2, 1, &caller)],
    };

    let cf: ClassFile = assemble(
        cb,
        this_class,
        vec![ck_method, dec_method, caller_method_info],
    );

    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    assert_eq!(
        report.decrypt_methods, 1,
        "dec must be the only decrypt method"
    );
    assert_eq!(report.call_sites, 1, "one call site in load()");
    assert_eq!(
        report.recovered.values().next().map(String::as_str),
        Some(plain),
        "caller-context evaluator must recover the plaintext keyed on load()"
    );
}

fn patch(code: &mut [u8], at: usize, target: usize) {
    let origin: i32 = at as i32 - 1;
    let off: i16 = i16::try_from(target as i32 - origin).unwrap();
    let b: [u8; 2] = off.to_be_bytes();
    code[at] = b[0];
    code[at + 1] = b[1];
}

#[test]
fn wrong_caller_does_not_recover() {
    let owner: &str = "com/example/Crypt";
    let key_for_load: u8 = caller_key(owner, "load");
    let plain: &str = "topsecret-value-1234";
    let cipher: String = encrypt(plain, key_for_load);

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let this_class: u16 = cb.class(owner);
    let dec_name: u16 = cb.utf8("dec");
    let dec_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let throwable: u16 = cb.class("java/lang/Throwable");
    let thr_init: u16 = cb.methodref("java/lang/Throwable", "<init>", "()V");
    let get_stack: u16 = cb.methodref(
        "java/lang/Throwable",
        "getStackTrace",
        "()[Ljava/lang/StackTraceElement;",
    );
    let ste_method: u16 = cb.methodref(
        "java/lang/StackTraceElement",
        "getMethodName",
        "()Ljava/lang/String;",
    );
    let str_hash: u16 = cb.methodref("java/lang/String", "hashCode", "()I");
    let to_chars: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.class("java/lang/String");
    let str_chars_init: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");

    let mut dec: Vec<u8> = Vec::new();
    dec.push(0xBB);
    dec.extend_from_slice(&throwable.to_be_bytes());
    dec.push(0x59);
    dec.push(0xB7);
    dec.extend_from_slice(&thr_init.to_be_bytes());
    dec.push(0xB6);
    dec.extend_from_slice(&get_stack.to_be_bytes());
    dec.push(0x04);
    dec.push(0x32);
    dec.push(0xB6);
    dec.extend_from_slice(&ste_method.to_be_bytes());
    dec.push(0xB6);
    dec.extend_from_slice(&str_hash.to_be_bytes());
    dec.push(0x10);
    dec.push(127);
    dec.push(0x7E);
    dec.push(0x3D);
    dec.push(0x2A);
    dec.push(0xB6);
    dec.extend_from_slice(&to_chars.to_be_bytes());
    dec.push(0x4C);
    dec.push(0x03);
    dec.push(0x36);
    dec.push(0x04);
    let dl: usize = dec.len();
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x2B);
    dec.push(0xBE);
    dec.push(0xA2);
    let db: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    dec.push(0x2B);
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x2B);
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x34);
    dec.push(0x1C);
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x60);
    dec.push(0x10);
    dec.push(127);
    dec.push(0x7E);
    dec.push(0x82);
    dec.push(0x91);
    dec.push(0x55);
    dec.push(0x84);
    dec.push(0x04);
    dec.push(0x01);
    dec.push(0xA7);
    let dg: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    let de: usize = dec.len();
    dec.push(0xBB);
    dec.extend_from_slice(&new_string.to_be_bytes());
    dec.push(0x59);
    dec.push(0x2B);
    dec.push(0xB7);
    dec.extend_from_slice(&str_chars_init.to_be_bytes());
    dec.push(0xB0);
    patch(&mut dec, db, de);
    patch(&mut dec, dg, dl);
    let dec_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: dec_name,
        descriptor_index: dec_desc,
        attributes: vec![code_attr(code_name, 6, 5, &dec)],
    };

    let lit: u16 = cb.string(&cipher);
    let caller_name_idx: u16 = cb.utf8("differentCaller");
    let caller_desc: u16 = cb.utf8("()Ljava/lang/String;");
    let self_dec: u16 = cb.methodref(owner, "dec", "(Ljava/lang/String;)Ljava/lang/String;");
    let mut caller: Vec<u8> = Vec::new();
    caller.push(0x13);
    caller.extend_from_slice(&lit.to_be_bytes());
    caller.push(0xB8);
    caller.extend_from_slice(&self_dec.to_be_bytes());
    caller.push(0xB0);
    let caller_method_info: MethodInfo = MethodInfo {
        access_flags: 0x0009,
        name_index: caller_name_idx,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 2, 1, &caller)],
    };

    let cf: ClassFile = assemble(cb, this_class, vec![dec_method, caller_method_info]);
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    let recovered_matches_plain: bool = report.recovered.values().any(|v: &String| v == plain);
    assert!(
        !recovered_matches_plain,
        "a cipher keyed to load() must not decode to plaintext under differentCaller's identity"
    );
}

#[test]
fn seeded_java_random_decrypt_recovers_without_runtime_wall() {
    const RANDOM_SEED: i64 = 123456789;
    const RANDOM_KEY: u8 = 101;

    let owner: &str = "com/example/SeededRandom";
    let plain: &str = "seeded-random-value";
    let cipher: String = xor_with_key(plain, RANDOM_KEY);

    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let this_class: u16 = cb.class(owner);

    let dec_name: u16 = cb.utf8("dec");
    let dec_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let random_class: u16 = cb.class("java/util/Random");
    let random_init: u16 = cb.methodref("java/util/Random", "<init>", "(J)V");
    let random_next: u16 = cb.methodref("java/util/Random", "nextInt", "(I)I");
    let random_seed: u16 = cb.long(RANDOM_SEED);
    let to_chars: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.class("java/lang/String");
    let str_chars_init: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");

    let mut dec: Vec<u8> = Vec::new();
    dec.push(0xBB);
    dec.extend_from_slice(&random_class.to_be_bytes());
    dec.push(0x59);
    dec.push(0x14);
    dec.extend_from_slice(&random_seed.to_be_bytes());
    dec.push(0xB7);
    dec.extend_from_slice(&random_init.to_be_bytes());
    dec.push(0x4C);
    dec.push(0x2B);
    dec.push(0x10);
    dec.push(127);
    dec.push(0xB6);
    dec.extend_from_slice(&random_next.to_be_bytes());
    dec.push(0x3D);
    dec.push(0x2A);
    dec.push(0xB6);
    dec.extend_from_slice(&to_chars.to_be_bytes());
    dec.push(0x4E);
    dec.push(0x03);
    dec.push(0x36);
    dec.push(0x04);
    let loop_start: usize = dec.len();
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x2D);
    dec.push(0xBE);
    dec.push(0xA2);
    let loop_exit_branch: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    dec.push(0x2D);
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x2D);
    dec.push(0x15);
    dec.push(0x04);
    dec.push(0x34);
    dec.push(0x1C);
    dec.push(0x82);
    dec.push(0x92);
    dec.push(0x55);
    dec.push(0x84);
    dec.push(0x04);
    dec.push(0x01);
    dec.push(0xA7);
    let loop_back_branch: usize = dec.len();
    dec.extend_from_slice(&[0, 0]);
    let loop_end: usize = dec.len();
    dec.push(0xBB);
    dec.extend_from_slice(&new_string.to_be_bytes());
    dec.push(0x59);
    dec.push(0x2D);
    dec.push(0xB7);
    dec.extend_from_slice(&str_chars_init.to_be_bytes());
    dec.push(0xB0);
    patch(&mut dec, loop_exit_branch, loop_end);
    patch(&mut dec, loop_back_branch, loop_start);

    let dec_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: dec_name,
        descriptor_index: dec_desc,
        attributes: vec![code_attr(code_name, 7, 5, &dec)],
    };

    let lit: u16 = cb.string(&cipher);
    let caller_name_idx: u16 = cb.utf8("load");
    let caller_desc: u16 = cb.utf8("()Ljava/lang/String;");
    let self_dec: u16 = cb.methodref(owner, "dec", "(Ljava/lang/String;)Ljava/lang/String;");
    let mut caller: Vec<u8> = Vec::new();
    caller.push(0x13);
    caller.extend_from_slice(&lit.to_be_bytes());
    caller.push(0xB8);
    caller.extend_from_slice(&self_dec.to_be_bytes());
    caller.push(0xB0);
    let caller_method_info: MethodInfo = MethodInfo {
        access_flags: 0x0009,
        name_index: caller_name_idx,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 2, 1, &caller)],
    };

    let cf: ClassFile = assemble(cb, this_class, vec![dec_method, caller_method_info]);
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    assert_eq!(report.decrypt_methods, 1);
    assert_eq!(report.call_sites, 1);
    assert!(
        !report.runtime_key_wall,
        "a literal-seeded java.util.Random decrypt is statically replayable"
    );
    assert_eq!(
        report.recovered.values().next().map(String::as_str),
        Some(plain)
    );
}

#[test]
fn env_keyed_decrypt_walls_with_reason() {
    let owner: &str = "com/example/Env";
    let mut cb: ClassBuilder = ClassBuilder::new();
    let code_name: u16 = cb.utf8("Code");
    let this_class: u16 = cb.class(owner);
    let dec_name: u16 = cb.utf8("dec");
    let dec_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let getprop: u16 = cb.methodref(
        "java/lang/System",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;",
    );
    let key_name: u16 = cb.string("license.key");
    let to_chars: u16 = cb.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cb.class("java/lang/String");
    let str_chars_init: u16 = cb.methodref("java/lang/String", "<init>", "([C)V");

    let mut dec: Vec<u8> = Vec::new();
    dec.push(0x13);
    dec.extend_from_slice(&key_name.to_be_bytes());
    dec.push(0xB8);
    dec.extend_from_slice(&getprop.to_be_bytes());
    dec.push(0x57);
    dec.push(0x2A);
    dec.push(0xB6);
    dec.extend_from_slice(&to_chars.to_be_bytes());
    dec.push(0x4C);
    dec.push(0xBB);
    dec.extend_from_slice(&new_string.to_be_bytes());
    dec.push(0x59);
    dec.push(0x2B);
    dec.push(0xB7);
    dec.extend_from_slice(&str_chars_init.to_be_bytes());
    dec.push(0xB0);
    let dec_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: dec_name,
        descriptor_index: dec_desc,
        attributes: vec![code_attr(code_name, 4, 3, &dec)],
    };

    let lit: u16 = cb.string("\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}");
    let caller_name_idx: u16 = cb.utf8("load");
    let caller_desc: u16 = cb.utf8("()Ljava/lang/String;");
    let self_dec: u16 = cb.methodref(owner, "dec", "(Ljava/lang/String;)Ljava/lang/String;");
    let mut caller: Vec<u8> = Vec::new();
    caller.push(0x13);
    caller.extend_from_slice(&lit.to_be_bytes());
    caller.push(0xB8);
    caller.extend_from_slice(&self_dec.to_be_bytes());
    caller.push(0xB0);
    let caller_method_info: MethodInfo = MethodInfo {
        access_flags: 0x0009,
        name_index: caller_name_idx,
        descriptor_index: caller_desc,
        attributes: vec![code_attr(code_name, 2, 1, &caller)],
    };

    let cf: ClassFile = assemble(cb, this_class, vec![dec_method, caller_method_info]);
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    assert!(
        report.runtime_key_wall,
        "a System.getProperty-keyed decrypt must wall, not fabricate"
    );
    assert!(report.recovered.is_empty());
    assert!(report.runtime_key_wall_reason.is_some());
}

fn lin_static_decrypt(cb: &mut ClassBuilder, owner: &str, code: &[u8]) -> ClassFile {
    let code_name: u16 = cb.utf8("Code");
    let this_class: u16 = cb.class(owner);
    let dec_name: u16 = cb.utf8("dec");
    let dec_desc: u16 = cb.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let dec_method: MethodInfo = MethodInfo {
        access_flags: 0x000A,
        name_index: dec_name,
        descriptor_index: dec_desc,
        attributes: vec![code_attr(code_name, 8, 6, code)],
    };
    let mut taken: ClassBuilder = ClassBuilder::new();
    std::mem::swap(cb, &mut taken);
    ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: taken.cp,
        access_flags: 0,
        this_class,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![dec_method],
        attributes: Vec::new(),
    }
}

#[test]
fn switch_target_resolves_table_and_lookup_and_default() {
    let tbl: Instruction = Instruction {
        pc: 100,
        opcode: 0xAA,
        mnemonic: "tableswitch",
        wide: false,
        operands: Operands::TableSwitch {
            default: 40,
            low: 0,
            high: 2,
            offsets: vec![10, 20, 30],
        },
    };
    assert_eq!(switch_target(&tbl, 0), Ok(110));
    assert_eq!(switch_target(&tbl, 2), Ok(130));
    assert_eq!(
        switch_target(&tbl, 9),
        Ok(140),
        "out-of-range key takes the default"
    );
    assert_eq!(switch_target(&tbl, -1), Ok(140));

    let lk: Instruction = Instruction {
        pc: 200,
        opcode: 0xAB,
        mnemonic: "lookupswitch",
        wide: false,
        operands: Operands::LookupSwitch {
            default: 5,
            pairs: vec![(7, 11), (99, 22)],
        },
    };
    assert_eq!(switch_target(&lk, 7), Ok(211));
    assert_eq!(switch_target(&lk, 99), Ok(222));
    assert_eq!(
        switch_target(&lk, 1),
        Ok(205),
        "unmatched key takes the default"
    );
}

#[test]
fn step_cap_bounds_a_self_looping_decrypt() {
    let owner: &str = "com/example/Loop";
    let mut cb: ClassBuilder = ClassBuilder::new();
    let mut dec: Vec<u8> = Vec::new();
    dec.push(0xA7);
    dec.extend_from_slice(&0i16.to_be_bytes());
    patch(&mut dec, 1, 0);
    let cf: ClassFile = lin_static_decrypt(&mut cb, owner, &dec);
    let methods: Vec<DecryptMethod> = find_decrypt_methods(&cf);
    let method: &DecryptMethod = methods.first().expect("dec");
    let caller: CallerContext = CallerContext::new(owner.to_owned(), "m".to_owned());
    let err: EvalError = evaluate_decrypt(&cf, method, "anything", 0, &caller)
        .expect_err("an infinite self-loop must be bounded, not hang");
    assert_eq!(
        err,
        EvalError::StepLimitExceeded,
        "the concrete evaluator must terminate a non-returning loop at the step cap"
    );
}

#[test]
fn long_store_load_index_covers_all_categories() {
    for op in 0x3Fu8..=0x4A {
        assert!(
            store_local_index(
                &Instruction {
                    pc: 0,
                    opcode: op,
                    mnemonic: "",
                    wide: false,
                    operands: Operands::None,
                },
                op,
            )
            .is_ok(),
            "store slot mapping must cover lstore_n/fstore_n/dstore_n opcode {op:#x}"
        );
    }
    for op in 0x1Eu8..=0x29 {
        assert!(
            load_local_index(
                &Instruction {
                    pc: 0,
                    opcode: op,
                    mnemonic: "",
                    wide: false,
                    operands: Operands::None,
                },
                op,
            )
            .is_ok(),
            "load slot mapping must cover lload_n/fload_n/dload_n opcode {op:#x}"
        );
    }
}
