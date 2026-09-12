#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_jvm::{
    Attribute, ClassFile, ConstantPoolEntry, MethodInfo, StringDecryptStub, StringRecoveryReport,
    emulate_string_decrypt, find_string_decrypt_methods, recover_strings,
};

struct Cp {
    entries: Vec<ConstantPoolEntry>,
}

impl Cp {
    fn new() -> Self {
        Self {
            entries: vec![ConstantPoolEntry::Placeholder],
        }
    }

    fn push(&mut self, e: ConstantPoolEntry) -> u16 {
        self.entries.push(e);
        u16::try_from(self.entries.len() - 1).unwrap()
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

fn xor_string_decrypt(key: u8, tochararray: u16, new_string: u16, string_class: u16) -> Vec<u8> {
    let mut c: Vec<u8> = Vec::new();
    c.push(0x2A);
    c.push(0xB6);
    c.extend_from_slice(&tochararray.to_be_bytes());
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
    c.extend_from_slice(&new_string.to_be_bytes());
    c.push(0xB0);

    let exit_target: i16 =
        i16::try_from(exit_pc).unwrap() - i16::try_from(exit_branch_pos - 1).unwrap();
    c[exit_branch_pos..exit_branch_pos + 2].copy_from_slice(&exit_target.to_be_bytes());
    let back_target: i16 =
        i16::try_from(loop_start).unwrap() - i16::try_from(back_pos - 1).unwrap();
    c[back_pos..back_pos + 2].copy_from_slice(&back_target.to_be_bytes());
    c
}

#[test]
fn recover_strings_emulates_string_input_decryptor_over_real_secrets() {
    let key: u8 = 0x6B;
    let secrets: &[&str] = &[
        "jdbc:mysql://10.0.0.5:3306/payments",
        "AKIA0000EXAMPLEKEY77",
        "Bearer eyJhbGciOiJIUzI1NiJ9",
        "ROLE_ADMIN",
    ];

    let mut cp: Cp = Cp::new();
    let code_name: u16 = cp.utf8("Code");
    let decrypt_name: u16 = cp.utf8("a");
    let decrypt_desc: u16 = cp.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let tochararray: u16 = cp.methodref("java/lang/String", "toCharArray", "()[C");
    let new_string: u16 = cp.methodref("java/lang/String", "<init>", "([C)V");
    let string_class: u16 = cp.class("java/lang/String");
    let self_decrypt: u16 = cp.methodref("App", "a", "(Ljava/lang/String;)Ljava/lang/String;");

    let mut caller_code: Vec<u8> = Vec::new();
    for s in secrets {
        let enc: String = s
            .encode_utf16()
            .map(|u| u ^ u16::from(key))
            .map(|u| char::from_u32(u32::from(u)).unwrap())
            .collect();
        let lit: u16 = cp.string(&enc);
        caller_code.push(0x13);
        caller_code.extend_from_slice(&lit.to_be_bytes());
        caller_code.push(0xB8);
        caller_code.extend_from_slice(&self_decrypt.to_be_bytes());
        caller_code.push(0x57);
    }
    caller_code.push(0xB1);

    let caller_name: u16 = cp.utf8("run");
    let caller_desc: u16 = cp.utf8("()V");
    let decrypt_code: Vec<u8> = xor_string_decrypt(key, tochararray, new_string, string_class);

    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp.entries,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![
            MethodInfo {
                access_flags: 0x0008,
                name_index: decrypt_name,
                descriptor_index: decrypt_desc,
                attributes: vec![code_attr(code_name, 3, &decrypt_code)],
            },
            MethodInfo {
                access_flags: 0x0008,
                name_index: caller_name,
                descriptor_index: caller_desc,
                attributes: vec![code_attr(code_name, 1, &caller_code)],
            },
        ],
        attributes: Vec::new(),
    };

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    assert_eq!(stubs.len(), 1, "exactly one String-input decrypt method");

    let report: StringRecoveryReport = recover_strings(&cf);
    let recovered: Vec<&String> = report.recovered.values().collect();
    for secret in secrets {
        assert!(
            recovered.iter().any(|s| s.as_str() == *secret),
            "expected '{secret}' recovered statically, got {recovered:?}"
        );
    }
    assert_eq!(
        report.recovered.len(),
        secrets.len(),
        "all encrypted literals recovered without running the class"
    );
    assert!(!report.runtime_key_wall);
}

#[test]
fn runtime_derived_key_is_honestly_walled() {
    let mut cp: Cp = Cp::new();
    let code_name: u16 = cp.utf8("Code");
    let decrypt_name: u16 = cp.utf8("a");
    let decrypt_desc: u16 = cp.utf8("(Ljava/lang/String;)Ljava/lang/String;");
    let nano: u16 = cp.methodref("java/lang/System", "nanoTime", "()J");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xB8);
    code.extend_from_slice(&nano.to_be_bytes());
    code.push(0x88);
    code.push(0x57);
    code.push(0x2A);
    code.push(0xB0);

    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp.entries,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![MethodInfo {
            access_flags: 0x0008,
            name_index: decrypt_name,
            descriptor_index: decrypt_desc,
            attributes: vec![code_attr(code_name, 2, &code)],
        }],
        attributes: Vec::new(),
    };

    let report: StringRecoveryReport = recover_strings(&cf);
    assert!(
        report.runtime_key_wall,
        "time-derived key must flag the runtime-key wall, not fabricate plaintext"
    );

    let stubs: Vec<StringDecryptStub> = find_string_decrypt_methods(&cf);
    let result: Result<String, _> = emulate_string_decrypt(&cf, &stubs[0], "anything", 0);
    assert!(
        result.is_err(),
        "emulator must refuse to evaluate a runtime-dependent decryptor"
    );
}
