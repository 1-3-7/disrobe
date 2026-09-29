#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use crate::dex::{DexFile, parse as parse_dex};
use crate::dex_builder::{
    CLINIT_KEY_TABLE_DERIVED_KEY, ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef, Reloc,
    base64_xor_chain_sample, chained_double_decrypt_sample, clinit_key_table_sample,
    dexguard_reflect_sample, insn, native_call_wall_sample, stringbuilder_decrypt_sample,
    xor_bytearray_callsite_sample,
};

const TWO_SITE_CLASS: &str = "Lcom/disrobe/sample/GenericTwoSiteFuel;";

#[derive(Default)]
struct Asm {
    units: Vec<u16>,
    relocations: Vec<Reloc>,
}

impl Asm {
    fn emit(&mut self, units: Vec<u16>) {
        self.units.extend(units);
    }

    fn emit_type(&mut self, units: Vec<u16>, descriptor: &str) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(units);
        self.relocations.push(Reloc::TypeIndex {
            unit,
            descriptor: descriptor.to_owned(),
        });
    }

    fn emit_method(&mut self, units: Vec<u16>, method: &MethodRef) {
        let unit: usize = self.units.len() + 1;
        self.units.extend(units);
        self.relocations.push(Reloc::MethodIndex {
            unit,
            method: method.clone(),
        });
    }

    fn if_ge_forward(&mut self, a: u8, b: u8) -> usize {
        let pos: usize = self.units.len();
        self.emit(insn::fmt22t(0x35, a, b, 0));
        pos
    }

    fn patch_forward(&mut self, branch_pos: usize) {
        let rel: i16 = i16::try_from(self.units.len() - branch_pos).expect("short branch");
        self.units[branch_pos + 1] = rel as u16;
    }

    fn goto_back(&mut self, target: usize) {
        let rel: i8 = i8::try_from(target as i64 - self.units.len() as i64).expect("short goto");
        self.units.push(0x28 | (u16::from(rel as u8) << 8));
    }
}

fn byte_array_decryptor(name: &str) -> MethodRef {
    MethodRef {
        class: TWO_SITE_CLASS.to_owned(),
        proto: ProtoRef {
            return_type: "Ljava/lang/String;".to_owned(),
            params: vec!["[B".to_owned(), "I".to_owned()],
        },
        name: name.to_owned(),
    }
}

fn xor_decryptor_method(method: MethodRef, stretch_rounds_high16: Option<i16>) -> EncodedMethod {
    let string_init: MethodRef = MethodRef {
        class: "Ljava/lang/String;".to_owned(),
        proto: ProtoRef {
            return_type: "V".to_owned(),
            params: vec!["[B".to_owned()],
        },
        name: "<init>".to_owned(),
    };
    let mut asm: Asm = Asm::default();
    if let Some(rounds) = stretch_rounds_high16 {
        asm.emit(insn::fmt21s(0x15, 0, rounds));
        asm.emit(insn::fmt11n(0x12, 2, 0));
        asm.emit(insn::fmt11n(0x12, 3, 0));
        let stretch_start: usize = asm.units.len();
        let stretch_exit: usize = asm.if_ge_forward(2, 0);
        asm.emit(insn::fmt22b(0xDA, 3, 3, 31));
        asm.emit(insn::fmt12x(0xB0, 3, 6));
        asm.emit(insn::fmt12x(0xB7, 3, 2));
        asm.emit(insn::fmt22b(0xD8, 2, 2, 1));
        asm.goto_back(stretch_start);
        asm.patch_forward(stretch_exit);
    }
    asm.emit(insn::fmt12x(0x21, 0, 5));
    asm.emit_type(insn::fmt22c(0x23, 1, 0, 0), "[B");
    asm.emit(insn::fmt11n(0x12, 2, 0));
    let loop_start: usize = asm.units.len();
    let loop_exit: usize = asm.if_ge_forward(2, 0);
    asm.emit(insn::fmt23x(0x48, 3, 5, 2));
    asm.emit(insn::fmt12x(0xB7, 3, 6));
    asm.emit(insn::fmt23x(0x4F, 3, 1, 2));
    asm.emit(insn::fmt22b(0xD8, 2, 2, 1));
    asm.goto_back(loop_start);
    asm.patch_forward(loop_exit);
    asm.emit_type(insn::fmt21c(0x22, 4, 0), "Ljava/lang/String;");
    asm.emit_method(insn::fmt35c_two(0x70, 4, 1, 0), &string_init);
    asm.emit(insn::fmt11x(0x11, 4));
    EncodedMethod {
        method,
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 7,
        ins_size: 2,
        outs_size: 2,
        insns: asm.units,
        relocations: asm.relocations,
        tries: Vec::new(),
    }
}

fn stretched_then_plain_call_sites_sample(
    stretch_rounds_high16: i16,
    stretched_site: (&MethodRef, &[u8], u8),
    plain_site: (&MethodRef, &[u8], u8),
) -> Vec<u8> {
    let mut caller: Asm = Asm::default();
    let mut payload_refs: Vec<(usize, &[u8])> = Vec::new();
    for (decryptor, cipher, key) in [stretched_site, plain_site] {
        caller.emit(insn::fmt21s(
            0x13,
            0,
            i16::try_from(cipher.len()).expect("short cipher"),
        ));
        caller.emit_type(insn::fmt22c(0x23, 0, 0, 0), "[B");
        payload_refs.push((caller.units.len(), cipher));
        caller.emit(insn::fmt31t(0x26, 0, 0));
        caller.emit(insn::fmt21s(0x13, 1, i16::from(key)));
        caller.emit_method(insn::fmt35c_two(0x71, 0, 1, 0), decryptor);
        caller.emit(insn::fmt11x(0x0C, 2));
    }
    caller.emit(insn::fmt10x(0x0E));
    for (fill_pos, cipher) in payload_refs {
        if !caller.units.len().is_multiple_of(2) {
            caller.units.push(0x0000);
        }
        let rel: u32 = u32::try_from(caller.units.len() - fill_pos).expect("payload offset");
        caller.units[fill_pos + 1] = (rel & 0xFFFF) as u16;
        caller.units[fill_pos + 2] = (rel >> 16) as u16;
        let size: u32 = u32::try_from(cipher.len()).expect("payload size");
        caller.emit(vec![0x0300, 1, (size & 0xFFFF) as u16, (size >> 16) as u16]);
        for pair in cipher.chunks(2) {
            let hi: u8 = pair.get(1).copied().unwrap_or(0);
            caller.units.push(u16::from(pair[0]) | (u16::from(hi) << 8));
        }
    }
    let caller_method: EncodedMethod = EncodedMethod {
        method: MethodRef {
            class: TWO_SITE_CLASS.to_owned(),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: Vec::new(),
            },
            name: "useSecrets".to_owned(),
        },
        access_flags: 0x000A,
        is_direct: true,
        registers_size: 3,
        ins_size: 0,
        outs_size: 2,
        insns: caller.units,
        relocations: caller.relocations,
        tries: Vec::new(),
    };
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: TWO_SITE_CLASS.to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![
            xor_decryptor_method(stretched_site.0.clone(), Some(stretch_rounds_high16)),
            xor_decryptor_method(plain_site.0.clone(), None),
            caller_method,
        ],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn recovered_strings(report: &GenericStringRecovery) -> Vec<String> {
    report
        .call_sites
        .iter()
        .filter_map(|c: &CallSiteRecovery| match &c.outcome {
            CallSiteOutcome::Recovered(s) => Some(s.clone()),
            CallSiteOutcome::Skipped(_) => None,
        })
        .collect()
}

#[test]
fn recovery_report_preserves_partial_code_failure() {
    let (dex, bytes): (DexFile, Vec<u8>) = crate::dex::partial_code_failure_fixture();
    let report: GenericStringRecovery = recover(&dex, &bytes);
    assert!(!report.code_scan_complete);
    assert_eq!(report.decode_error_count, 1);
}

#[test]
fn legacy_recovery_report_defaults_to_incomplete_code_scan() {
    let json: &str = r#"{"candidates_found":0,"call_sites":[]}"#;
    let report: GenericStringRecovery = serde_json::from_str(json).expect("legacy recovery report");
    assert!(!report.code_scan_complete);
    assert_eq!(report.decode_error_count, 0);
}

#[test]
fn recovers_multiple_distinct_byte_array_xor_call_sites_from_a_dex_we_build() {
    let pairs: [(&str, u8); 3] = [
        ("https://api.example.com/v2/session", 0x37),
        ("X-Correlation-Id", 0x37),
        ("expected-hmac-mismatch", 0x5A),
    ];
    let owned: Vec<(Vec<u8>, u8)> = pairs
        .iter()
        .map(|(plain, key): &(&str, u8)| {
            (
                plain.bytes().map(|b: u8| b ^ key).collect::<Vec<u8>>(),
                *key,
            )
        })
        .collect();
    let call_site_pairs: Vec<(&[u8], u8)> = owned
        .iter()
        .map(|(cipher, key): &(Vec<u8>, u8)| (cipher.as_slice(), *key))
        .collect();
    let dex_bytes: Vec<u8> = xor_bytearray_callsite_sample(&call_site_pairs);
    let dex: DexFile =
        parse_dex(&dex_bytes).expect("the hand-built dex must parse with the real parser");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        report.candidates_found >= 1,
        "the ([BI)String decrypt method must be identified as a candidate"
    );
    let recovered: Vec<String> = recovered_strings(&report);
    for (plain, _) in pairs {
        assert!(
            recovered.iter().any(|s: &String| s == plain),
            "missing {plain:?} in {recovered:?} (call sites: {:?})",
            report.call_sites
        );
    }
    assert_eq!(
        report.recovered_count(),
        pairs.len(),
        "every distinct constant-argument call site must be individually recovered"
    );
}

#[test]
fn flipping_one_ciphertext_byte_changes_the_recovered_output() {
    let plain: &str = "perturbation-check-string";
    let key: u8 = 0x37;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();

    let baseline_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key)]);
    let baseline_dex_file: DexFile = parse_dex(&baseline_dex).expect("parses");
    let baseline: GenericStringRecovery = recover(&baseline_dex_file, &baseline_dex);
    let baseline_recovered: Vec<String> = recovered_strings(&baseline);
    assert!(baseline_recovered.iter().any(|s: &String| s == plain));

    let mut flipped_cipher: Vec<u8> = cipher;
    flipped_cipher[0] ^= 0xFF;
    let flipped_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&flipped_cipher, key)]);
    let flipped_dex_file: DexFile = parse_dex(&flipped_dex).expect("parses");
    let flipped: GenericStringRecovery = recover(&flipped_dex_file, &flipped_dex);
    let flipped_recovered: Vec<String> = recovered_strings(&flipped);

    assert_ne!(
        baseline_recovered, flipped_recovered,
        "a single flipped ciphertext byte must change the recovered output; the test would \
         otherwise be measuring the fixture, not the interpreter"
    );
}

#[test]
fn flipping_the_key_changes_the_recovered_output() {
    let plain: &str = "perturbation-check-string";
    let key: u8 = 0x37;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();

    let baseline_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key)]);
    let baseline_dex_file: DexFile = parse_dex(&baseline_dex).expect("parses");
    let baseline: GenericStringRecovery = recover(&baseline_dex_file, &baseline_dex);
    let baseline_recovered: Vec<String> = recovered_strings(&baseline);
    assert!(baseline_recovered.iter().any(|s: &String| s == plain));

    let flipped_dex: Vec<u8> = xor_bytearray_callsite_sample(&[(&cipher, key ^ 0x01)]);
    let flipped_dex_file: DexFile = parse_dex(&flipped_dex).expect("parses");
    let flipped: GenericStringRecovery = recover(&flipped_dex_file, &flipped_dex);
    let flipped_recovered: Vec<String> = recovered_strings(&flipped);

    assert_ne!(
        baseline_recovered, flipped_recovered,
        "a flipped key must change the recovered output"
    );
}

#[test]
fn recovers_a_clinit_initialized_key_table_by_executing_clinit_under_the_same_budget() {
    let plain: &str = "clinit-derived-key-table";
    let cipher: Vec<u8> = plain
        .bytes()
        .map(|b: u8| b ^ CLINIT_KEY_TABLE_DERIVED_KEY)
        .collect();
    let dex_bytes: Vec<u8> = clinit_key_table_sample(&[&cipher]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "the static KEY field is computed inside <clinit> (0x50 ^ 0x41) and must be executed, \
         not defaulted; missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_stringbuilder_based_decrypt_call_site() {
    let plain: &str = "stringbuilder-decrypt-path";
    let key: u8 = 0x63;
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
    let dex_bytes: Vec<u8> = stringbuilder_decrypt_sample(&[(&cipher, key)]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_base64_then_xor_call_site() {
    let plain: &str = "base64-then-xor";
    let key: u8 = 0x2A;
    let dex_bytes: Vec<u8> = base64_xor_chain_sample(&[(plain, key)]);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "missing {plain:?} in {recovered:?} (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn recovers_a_chained_double_decryption_across_two_call_sites() {
    let plain: &str = "chainedok";
    let k1: u8 = 0x05;
    let k2: u8 = 0x0A;
    let intermediate_bytes: Vec<u8> = plain.bytes().map(|b: u8| b ^ k2).collect();
    let cipher: Vec<u8> = intermediate_bytes.iter().map(|&b: &u8| b ^ k1).collect();
    let dex_bytes: Vec<u8> = chained_double_decrypt_sample(&cipher, k1, k2);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        report.candidates_found >= 2,
        "both stage1([B)String and stage2(String)String must be identified as candidates"
    );
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.iter().any(|s: &String| s == plain),
        "the second call site's argument is the runtime result of the first call, not a dex \
         literal; recovering it proves chained-decryption propagation; got {recovered:?} \
         (call sites: {:?})",
        report.call_sites
    );
}

#[test]
fn walls_on_a_native_unresolvable_key_dependency_with_a_typed_reason() {
    let cipher: Vec<u8> = b"unreachable-because-native-key".to_vec();
    let dex_bytes: Vec<u8> = native_call_wall_sample(&cipher);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    assert!(
        !report.call_sites.is_empty(),
        "the call site with a constant byte[] argument must still be reported, walled not silently dropped"
    );
    assert!(
        report
            .call_sites
            .iter()
            .all(|c: &CallSiteRecovery| matches!(c.outcome, CallSiteOutcome::Skipped(_))),
        "every call site here depends on an unresolved native key and must be a typed skip, \
         never a fabricated plaintext: {:?}",
        report.call_sites
    );
    assert!(
        report
            .call_sites
            .iter()
            .any(|c: &CallSiteRecovery| matches!(
                &c.outcome,
                CallSiteOutcome::Skipped(SkipReason::UnsupportedCall(m)) if m.contains("nativeKey")
            )),
        "the skip reason must name the unresolved native call: {:?}",
        report.call_sites
    );
}

#[test]
fn walls_on_a_reflection_invoked_decrypt_with_no_direct_constant_call_site() {
    let plaintexts: [&str; 2] = ["reflective-only", "no-direct-call-site"];
    let dex_bytes: Vec<u8> = dexguard_reflect_sample(&plaintexts, 0x66);
    let dex: DexFile = parse_dex(&dex_bytes).expect("parses");

    let report: GenericStringRecovery = recover(&dex, &dex_bytes);
    let recovered: Vec<String> = recovered_strings(&report);
    assert!(
        recovered.is_empty(),
        "the only call site into decrypt() is via reflection (Method.invoke), which this engine \
         does not model; it must never fabricate a plaintext here: {recovered:?}"
    );
}

fn site_outcome<'r>(
    report: &'r GenericStringRecovery,
    decrypt_method: &str,
) -> &'r CallSiteOutcome {
    let sites: Vec<&CallSiteRecovery> = report
        .call_sites
        .iter()
        .filter(|c: &&CallSiteRecovery| c.decrypt_method == decrypt_method)
        .collect();
    assert_eq!(
        sites.len(),
        1,
        "exactly one call site into {decrypt_method}: {:?}",
        report.call_sites
    );
    &sites[0].outcome
}

#[test]
fn a_fuel_exhausting_first_call_site_leaves_the_second_site_on_the_same_class_recoverable() {
    let stretched_plain: &str = "stretched-key-derivation";
    let plain: &str = "second-site-plaintext";
    let stretched_key: u8 = 0x21;
    let key: u8 = 0x4C;
    let stretched_cipher: Vec<u8> = stretched_plain
        .bytes()
        .map(|b: u8| b ^ stretched_key)
        .collect();
    let cipher: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
    let stretched: MethodRef = byte_array_decryptor("stretchedDecrypt");
    let decrypt: MethodRef = byte_array_decryptor("decrypt");

    let cheap_dex: Vec<u8> = stretched_then_plain_call_sites_sample(
        0,
        (&stretched, &stretched_cipher, stretched_key),
        (&decrypt, &cipher, key),
    );
    let cheap: GenericStringRecovery = recover(&parse_dex(&cheap_dex).expect("parses"), &cheap_dex);
    assert_eq!(cheap.candidates_found, 2, "{:?}", cheap.call_sites);
    assert_eq!(
        site_outcome(&cheap, "stretchedDecrypt"),
        &CallSiteOutcome::Recovered(stretched_plain.to_owned()),
        "with zero stretch rounds the first decryptor is an ordinary XOR decryptor"
    );

    let costly_dex: Vec<u8> = stretched_then_plain_call_sites_sample(
        0x4000,
        (&stretched, &stretched_cipher, stretched_key),
        (&decrypt, &cipher, key),
    );
    let costly: GenericStringRecovery =
        recover(&parse_dex(&costly_dex).expect("parses"), &costly_dex);
    assert_eq!(costly.candidates_found, 2, "{:?}", costly.call_sites);
    assert_eq!(
        site_outcome(&costly, "stretchedDecrypt"),
        &CallSiteOutcome::Skipped(SkipReason::BudgetExhausted),
        "2^30 stretch rounds at six steps each exceed the per-site step fuel"
    );
    assert_eq!(
        site_outcome(&costly, "decrypt"),
        &CallSiteOutcome::Recovered(plain.to_owned()),
        "the second call site shares the class interpreter but must start with its own fuel"
    );
}
