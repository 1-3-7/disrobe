#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_jvm::{
    Attribute, ClassFile, ConstantPoolEntry, MethodInfo, ProtectorPeelReport, zelix_protector,
};
use disrobe_pass_jvm::{DecryptStub, emulate_char_array, find_char_array_decrypt};

fn xor_decrypt_code(key: u8) -> Vec<u8> {
    let mut code: Vec<u8> = vec![
        0x2A, 0xBE, 0xBC, 0x05, 0x3C, 0x03, 0x3D, 0x1C, 0x2A, 0xBE, 0xA2,
    ];
    let cond_branch_pos: usize = code.len();
    code.extend_from_slice(&[0x00, 0x00]);
    code.extend_from_slice(&[
        0x2B, 0x1C, 0x2A, 0x1C, 0x34, 0x10, key, 0x82, 0x55, 0x84, 0x02, 0x01, 0xA7,
    ]);
    let goto_pos: usize = code.len();
    code.extend_from_slice(&[0x00, 0x00]);
    let end_pc: usize = code.len();
    code.extend_from_slice(&[0x2B, 0xB0]);

    let cond_target: i16 =
        i16::try_from(end_pc).unwrap() - i16::try_from(cond_branch_pos - 1).unwrap();
    code[cond_branch_pos..cond_branch_pos + 2].copy_from_slice(&cond_target.to_be_bytes());
    let goto_target: i16 = 7i16 - i16::try_from(goto_pos - 1).unwrap();
    code[goto_pos..goto_pos + 2].copy_from_slice(&goto_target.to_be_bytes());
    code
}

fn code_attribute(code: &[u8]) -> Vec<u8> {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&4u16.to_be_bytes());
    info.extend_from_slice(&4u16.to_be_bytes());
    info.extend_from_slice(&(code.len() as u32).to_be_bytes());
    info.extend_from_slice(code);
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info
}

#[derive(Default)]
struct Pool {
    entries: Vec<ConstantPoolEntry>,
}

impl Pool {
    fn push(&mut self, entry: ConstantPoolEntry) -> u16 {
        if self.entries.is_empty() {
            self.entries.push(ConstantPoolEntry::Placeholder);
        }
        self.entries.push(entry);
        u16::try_from(self.entries.len() - 1).expect("small constant pool")
    }

    fn utf8(&mut self, text: &str) -> u16 {
        self.push(ConstantPoolEntry::Utf8(text.to_owned()))
    }

    fn class(&mut self, name: &str) -> u16 {
        let name_index: u16 = self.utf8(name);
        self.push(ConstantPoolEntry::Class { name_index })
    }

    fn string(&mut self, text: &str) -> (u16, u16) {
        let utf8_index: u16 = self.utf8(text);
        (
            self.push(ConstantPoolEntry::String { utf8_index }),
            utf8_index,
        )
    }

    fn method_ref(&mut self, owner: &str, name: &str, descriptor: &str) -> u16 {
        let class_index: u16 = self.class(owner);
        let name_index: u16 = self.utf8(name);
        let descriptor_index: u16 = self.utf8(descriptor);
        let name_and_type_index: u16 = self.push(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        });
        self.push(ConstantPoolEntry::Methodref {
            class_index,
            name_and_type_index,
        })
    }
}

fn xor_text(text: &str, key: u8) -> String {
    String::from_utf16(
        &text
            .encode_utf16()
            .map(|c: u16| c ^ u16::from(key))
            .collect::<Vec<u16>>(),
    )
    .expect("utf16")
}

fn with_operand(code: &mut Vec<u8>, opcode: u8, index: u16) {
    code.push(opcode);
    code.extend_from_slice(&index.to_be_bytes());
}

struct StubClass {
    class: ClassFile,
    plain_utf8: Vec<u16>,
}

fn stub_class(key: u8, secrets: &[&str], plain: &[&str]) -> StubClass {
    let mut pool: Pool = Pool::default();
    let this_class: u16 = pool.class("Vault");
    let super_class: u16 = pool.class("java/lang/Object");
    let code_name: u16 = pool.utf8("Code");
    let decrypt_name: u16 = pool.utf8("decrypt");
    let decrypt_descriptor: u16 = pool.utf8("([C)[C");
    let load_name: u16 = pool.utf8("load");
    let load_descriptor: u16 = pool.utf8("()V");
    let to_char_array: u16 = pool.method_ref("java/lang/String", "toCharArray", "()[C");
    let decrypt_ref: u16 = pool.method_ref("Vault", "decrypt", "([C)[C");

    let mut load: Vec<u8> = Vec::new();
    for secret in secrets {
        let (string_index, _): (u16, u16) = pool.string(&xor_text(secret, key));
        with_operand(&mut load, 0x13, string_index);
        with_operand(&mut load, 0xB6, to_char_array);
        with_operand(&mut load, 0xB8, decrypt_ref);
        load.push(0x57);
    }
    let mut plain_utf8: Vec<u16> = Vec::new();
    for (position, text) in plain.iter().enumerate() {
        let (string_index, utf8_index): (u16, u16) = pool.string(text);
        plain_utf8.push(utf8_index);
        with_operand(&mut load, 0x13, string_index);
        if position % 2 == 1 {
            with_operand(&mut load, 0xB6, to_char_array);
        }
        load.push(0x57);
    }
    load.push(0xB1);

    let class: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: pool.entries,
        access_flags: 0x0021,
        this_class,
        super_class,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: vec![
            MethodInfo {
                access_flags: 0x0008,
                name_index: decrypt_name,
                descriptor_index: decrypt_descriptor,
                attributes: vec![Attribute {
                    name_index: code_name,
                    info: code_attribute(&xor_decrypt_code(key)),
                }],
            },
            MethodInfo {
                access_flags: 0x0008,
                name_index: load_name,
                descriptor_index: load_descriptor,
                attributes: vec![Attribute {
                    name_index: code_name,
                    info: code_attribute(&load),
                }],
            },
        ],
        attributes: Vec::new(),
    };
    StubClass { class, plain_utf8 }
}

#[test]
fn peel_recovers_strings_by_emulating_embedded_stub() {
    let key: u8 = 0x3F;
    let secrets: &[&str] = &[
        "jdbc:postgresql://db/prod",
        "X-Api-Key: 9f8e7d",
        "ROLE_SUPERUSER",
    ];
    let built: StubClass = stub_class(key, secrets, &[]);

    let stub: DecryptStub = find_char_array_decrypt(&built.class).expect("embedded stub found");
    let probe: Vec<u16> = "ab".encode_utf16().map(|c| c ^ u16::from(key)).collect();
    let probe_out: Vec<u16> = emulate_char_array(&stub, &probe).expect("emulate");
    assert_eq!(String::from_utf16(&probe_out).unwrap(), "ab");

    let report: ProtectorPeelReport = zelix_protector::peel(&built.class);
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for secret in secrets {
        assert!(
            recovered.iter().any(|s: &String| s == secret),
            "expected '{secret}' recovered via stub emulation, got {recovered:?}"
        );
    }
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("decrypt-stub emulation")),
        "peel must record that recovery used stub emulation"
    );
}

#[test]
fn the_stub_decrypts_only_constants_passed_to_it() {
    let key: u8 = 0x3F;
    let plain: [&str; 2] = ["hello", "config"];
    for text in plain {
        let through_stub: String = xor_text(text, key);
        assert!(
            through_stub != text && through_stub.chars().all(|c: char| c.is_ascii_graphic()),
            "the control constant {text:?} must decrypt to readable text {through_stub:?}, so \
             only the call-site rule keeps it out of the recovered set"
        );
    }
    let built: StubClass = stub_class(key, &["ROLE_SUPERUSER"], &plain);
    let report: ProtectorPeelReport = zelix_protector::peel(&built.class);
    assert_eq!(
        report.strings_recovered.values().collect::<Vec<&String>>(),
        vec!["ROLE_SUPERUSER"],
        "{report:?}"
    );
    for utf8_index in &built.plain_utf8 {
        assert!(
            !report.strings_recovered.contains_key(utf8_index),
            "a constant never handed to the decrypt stub was rewritten: {report:?}"
        );
    }
}
