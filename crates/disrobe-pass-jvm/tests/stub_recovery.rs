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
    info
}

#[test]
fn peel_recovers_strings_by_emulating_embedded_stub() {
    let key: u8 = 0x3F;
    let secrets: &[&str] = &[
        "jdbc:postgresql://db/prod",
        "X-Api-Key: 9f8e7d",
        "ROLE_SUPERUSER",
    ];

    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8("decrypt".into()));
    cp.push(ConstantPoolEntry::Utf8("([C)[C".into()));
    cp.push(ConstantPoolEntry::Utf8("Code".into()));
    for s in secrets {
        let enc: String = String::from_utf16(
            &s.encode_utf16()
                .map(|c| c ^ u16::from(key))
                .collect::<Vec<u16>>(),
        )
        .expect("utf16");
        cp.push(ConstantPoolEntry::Utf8(enc));
    }

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
            access_flags: 0x0008,
            name_index: 1,
            descriptor_index: 2,
            attributes: vec![Attribute {
                name_index: 3,
                info: code_attribute(&xor_decrypt_code(key)),
            }],
        }],
        attributes: Vec::new(),
    };

    let stub: DecryptStub = find_char_array_decrypt(&cf).expect("embedded stub found");
    let probe: Vec<u16> = "ab".encode_utf16().map(|c| c ^ u16::from(key)).collect();
    let probe_out: Vec<u16> = emulate_char_array(&stub, &probe).expect("emulate");
    assert_eq!(String::from_utf16(&probe_out).unwrap(), "ab");

    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
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
