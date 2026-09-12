use crate::dalvik_strdec::{self, DecryptedString, DexStringRecovery};
use crate::dex::{self, DexFile};
use crate::error::{Error, Result};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexGuardAuthorization(());

impl DexGuardAuthorization {
    #[inline]
    #[must_use]
    pub const fn user_attested() -> Self {
        Self(())
    }
}

pub fn peel(
    dex_bytes: &[u8],
    authorization: Option<DexGuardAuthorization>,
) -> Result<ProtectorPeelReport> {
    peel_with_native_libraries(dex_bytes, &[], authorization)
}

pub fn peel_with_native_libraries(
    dex_bytes: &[u8],
    native_libs: &[(&str, &[u8])],
    authorization: Option<DexGuardAuthorization>,
) -> Result<ProtectorPeelReport> {
    if authorization.is_none() {
        return Err(Error::DexGuardRequiresAuthorization);
    }
    if dex_bytes.len() < 8 || &dex_bytes[..4] != b"dex\n" {
        return Err(Error::DexGuardNotDex);
    }
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::DexGuard);
    let dex: DexFile = dex::parse(dex_bytes)?;
    let _: Vec<crate::dex::CodeItem> = dex::parse_code_items(&dex, dex_bytes).into_complete()?;
    apply_string_recovery(&dex, dex_bytes, native_libs, &mut report)?;

    if report.strings_recovered.is_empty()
        && !report
            .notes
            .iter()
            .any(|n: &String| n.contains("runtime-only"))
    {
        report.notes.push(
            "no static string decryptor recovered from this dex; table decryptors are evaluated \
             when the encrypted table and key derivation are present, while native-backed keys \
             require the APK's bundled library bytes and JNI surface."
                .to_string(),
        );
    }

    report.strings_residual = scan_residual_encrypted_dex_strings(dex_bytes);
    Ok(report)
}

fn apply_string_recovery(
    dex: &DexFile,
    dex_bytes: &[u8],
    native_libs: &[(&str, &[u8])],
    report: &mut ProtectorPeelReport,
) -> Result<()> {
    let native_keys: Vec<crate::dalvik_strdec::NativeIntKey> =
        crate::jni::extract_static_int_keys(dex, dex_bytes, native_libs)?;
    let recoveries: Vec<DexStringRecovery> =
        dalvik_strdec::recover_with_native_keys(dex, dex_bytes, &native_keys);
    if recoveries.is_empty() {
        return Ok(());
    }
    let mut total_recovered: usize = 0;
    let mut total_sites: usize = 0;
    let mut next_key: u16 = 0;
    for recovery in &recoveries {
        for entry in &recovery.recovered {
            let DecryptedString {
                table_index: _,
                plaintext,
            } = entry;
            report.strings_recovered.insert(next_key, plaintext.clone());
            next_key = next_key.wrapping_add(1);
            total_recovered += 1;
        }
        total_sites += recovery.reflective_call_sites.len();
        if recovery.runtime_key_wall
            && let Some(reason) = &recovery.runtime_key_wall_reason
        {
            report.notes.push(reason.clone());
        }
        report.notes.extend(recovery.notes.iter().cloned());
    }
    if total_recovered > 0 {
        report.status = PeelStatus::CipherRecovered;
        report.notes.push(format!(
            "recovered {total_recovered} string(s) by statically evaluating the dex's own \
             reflection-invoked decrypt routine over its encrypted static table (the class's \
             <clinit> is run to rebuild the String[] table, then the decrypt body is executed \
             per index against the dalvik register machine)."
        ));
    }
    if total_sites > 0 {
        let mut members: Vec<String> = recoveries
            .iter()
            .flat_map(|r: &DexStringRecovery| {
                r.reflective_call_sites
                    .iter()
                    .map(|s| s.resolved_member.clone())
            })
            .collect();
        members.sort();
        members.dedup();
        report.notes.push(format!(
            "resolved {total_sites} reflective call site(s) (Class.getDeclaredMethod + \
             Method.invoke) to their concrete target(s): {}",
            members.join(", ")
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CffAnalysis {
    pub suspected_flattened_methods: usize,
    pub dispatcher_switch_methods: usize,
    pub methods_unflattened: usize,
    pub dispatchers_resolved: usize,
    pub edges_redirected: usize,
    pub dead_branches_folded: usize,
    pub residual_dispatcher_edges: usize,
    pub notes: Vec<String>,
}

pub fn undo_cff(
    dex_bytes: &[u8],
    authorization: Option<DexGuardAuthorization>,
) -> Result<CffAnalysis> {
    if authorization.is_none() {
        return Err(Error::DexGuardRequiresAuthorization);
    }
    if dex_bytes.len() < 8 || &dex_bytes[..4] != b"dex\n" {
        return Err(Error::DexGuardNotDex);
    }
    let dex: crate::dex::DexFile = crate::dex::parse(dex_bytes)?;
    let items: Vec<crate::dex::CodeItem> =
        crate::dex::parse_code_items(&dex, dex_bytes).into_complete()?;
    let (report, _methods): (
        crate::dalvik_dexguard::DalvikCffReport,
        Vec<crate::dalvik_dexguard::DalvikMethodCff>,
    ) = crate::dalvik_dexguard::unflatten_dex_methods(&items);

    let suspected_flattened_methods: usize = report.flattened_methods as usize;
    let dispatcher_switch_methods: usize = report.dispatchers_resolved as usize
        + report
            .residual_dispatcher_edges
            .min(report.flattened_methods) as usize;
    let methods_unflattened: usize = report.methods_unflattened as usize;

    let mut notes: Vec<String> = Vec::new();
    if report.flattened_methods == 0 {
        notes.push(
            "AUTH-GATED detect-only: no DexGuard switch-on-state control-flow flattening present \
             in this dex; the un-flattener found no state-register dispatcher to rebuild."
                .to_string(),
        );
    } else {
        notes.push(format!(
            "our implementation un-flattened {} of {} DexGuard-style flattened method(s): \
             {} state-register dispatcher(s) resolved, {} predecessor edge(s) redirected to their \
             real successor, {} opaque conditional(s) folded, {} dispatcher block(s) pruned.",
            report.methods_unflattened,
            report.flattened_methods,
            report.dispatchers_resolved,
            report.edges_redirected,
            report.dead_branches_folded,
            report.dispatcher_blocks_pruned,
        ));
        if report.residual_dispatcher_edges > 0 {
            notes.push(format!(
                "{} dispatcher edge(s) remain unresolved; their state register is not written by a \
                 single static const before reaching the switch (computed or cross-block state).",
                report.residual_dispatcher_edges,
            ));
        }
    }
    notes.extend(report.unhandled_shapes);
    notes.push(
        "commercial-sample gap: DexGuard is enterprise-gated with no free tier, so this is \
         validated structurally against our own Dalvik CFG builder (recovered edge-set == clean \
         method's CFG), not yet against an enterprise DexGuard binary or an ART behavioral diff."
            .to_string(),
    );

    Ok(CffAnalysis {
        suspected_flattened_methods,
        dispatcher_switch_methods,
        methods_unflattened,
        dispatchers_resolved: report.dispatchers_resolved as usize,
        edges_redirected: report.edges_redirected as usize,
        dead_branches_folded: report.dead_branches_folded as usize,
        residual_dispatcher_edges: report.residual_dispatcher_edges as usize,
        notes,
    })
}

#[must_use]
pub fn scan_residual_encrypted_dex_strings(dex_bytes: &[u8]) -> usize {
    if dex_bytes.len() < 0x70 {
        return 0;
    }
    let string_ids_size: u32 = u32::from_le_bytes([
        dex_bytes[0x38],
        dex_bytes[0x39],
        dex_bytes[0x3A],
        dex_bytes[0x3B],
    ]);
    let string_ids_off: u32 = u32::from_le_bytes([
        dex_bytes[0x3C],
        dex_bytes[0x3D],
        dex_bytes[0x3E],
        dex_bytes[0x3F],
    ]);
    let base: usize = string_ids_off as usize;
    let count: usize = string_ids_size as usize;
    if base.saturating_add(count.saturating_mul(4)) > dex_bytes.len() {
        return 0;
    }
    let mut encrypted: usize = 0;
    for i in 0..count {
        let off_pos: usize = base + i * 4;
        let data_off: u32 = u32::from_le_bytes([
            dex_bytes[off_pos],
            dex_bytes[off_pos + 1],
            dex_bytes[off_pos + 2],
            dex_bytes[off_pos + 3],
        ]);
        let data_pos: usize = data_off as usize;
        if data_pos >= dex_bytes.len() {
            continue;
        }
        let Ok((size, p)): crate::error::Result<(u32, usize)> =
            crate::dex::read_uleb128(dex_bytes, data_pos)
        else {
            continue;
        };
        let str_end: usize = p.saturating_add(size as usize).min(dex_bytes.len());
        if p >= str_end {
            continue;
        }
        let slice: &[u8] = &dex_bytes[p..str_end];
        let non_print: usize = slice
            .iter()
            .filter(|b: &&u8| **b < 0x20 || **b > 0x7E)
            .count();
        if slice.len() >= 4 && (non_print as f64 / slice.len() as f64) > 0.5 {
            encrypted += 1;
        }
    }
    encrypted
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};
    use object::write::{Object, StandardSection, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

    #[test]
    fn residual_string_scan_rejects_uleb128_wider_than_u32() {
        let mut dex: Vec<u8> = vec![0u8; 0x90];
        dex[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes());
        dex[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes());
        dex[0x70..0x74].copy_from_slice(&0x74u32.to_le_bytes());
        dex[0x74..0x79].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
        dex[0x79..0x80].fill(0x01);
        assert_eq!(scan_residual_encrypted_dex_strings(&dex), 0);
    }

    fn build_aarch64_key_so(symbol: &str, key: u16) -> Vec<u8> {
        let mut obj: Object =
            Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
        let text: object::write::SectionId = obj.section_id(StandardSection::Text);
        let mut body: Vec<u8> = Vec::new();
        let mov: u32 = 0x5280_0000 | (u32::from(key) << 5);
        body.extend_from_slice(&mov.to_le_bytes());
        body.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        let offset: u64 = obj.append_section_data(text, body.as_slice(), 4);
        obj.add_symbol(Symbol {
            name: symbol.as_bytes().to_vec(),
            value: offset,
            size: body.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        obj.write().expect("write elf .so")
    }

    fn malformed_body_dex() -> Vec<u8> {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Invalid;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Invalid;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "body".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x0014],
                relocations: Vec::new(),
            }],
        });
        builder.build()
    }

    #[test]
    fn no_auth_yields_error() {
        let bytes: &[u8] = b"dex\n035\x00";
        let err: Error = peel(bytes, None).expect_err("auth required");
        assert!(matches!(err, Error::DexGuardRequiresAuthorization));
    }

    #[test]
    fn non_dex_input_rejected() {
        let bytes: &[u8] = b"not a dex file at all";
        let err: Error =
            peel(bytes, Some(DexGuardAuthorization::user_attested())).expect_err("not dex");
        assert!(matches!(err, Error::DexGuardNotDex));
    }

    #[test]
    fn malformed_method_body_refuses_negative_conclusions() {
        let bytes: Vec<u8> = malformed_body_dex();
        let authorization: Option<DexGuardAuthorization> =
            Some(DexGuardAuthorization::user_attested());
        assert!(peel(&bytes, authorization).is_err());
        assert!(undo_cff(&bytes, authorization).is_err());
    }

    #[test]
    fn malformed_dex_header_is_refused_before_negative_conclusion() {
        let mut bytes: Vec<u8> = b"dex\n035\x00".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 0x80));
        let error: Error = peel(&bytes, Some(DexGuardAuthorization::user_attested()))
            .expect_err("malformed header");
        assert!(matches!(error, Error::BadDexEndian(0)));
    }

    #[test]
    fn peels_class_name_keyed_static_table_from_built_sample() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "pbkdf2-sha256-310000",
        ];
        let dex: Vec<u8> = crate::dex_builder::dexguard_name_keyed_sample(&plaintexts);
        let report: ProtectorPeelReport =
            peel(&dex, Some(DexGuardAuthorization::user_attested())).expect("ok");
        assert_eq!(report.status, PeelStatus::CipherRecovered);
        let recovered: Vec<&String> = report.strings_recovered.values().collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|s: &&String| s.as_str() == expected),
                "the DexGuard peel must surface the class-name-keyed plaintext {expected:?}; got \
                 {recovered:?}"
            );
        }
    }

    #[test]
    fn peels_seeded_random_static_table_from_built_sample() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "AES/CBC/PKCS5Padding",
        ];
        let dex: Vec<u8> = crate::dex_builder::dexguard_seeded_random_sample(&plaintexts);
        let report: ProtectorPeelReport =
            peel(&dex, Some(DexGuardAuthorization::user_attested())).expect("ok");
        assert_eq!(report.status, PeelStatus::CipherRecovered);
        let recovered: Vec<&String> = report.strings_recovered.values().collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|s: &&String| s.as_str() == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
    }

    #[test]
    fn peels_reflection_string_decryptor_from_a_javac_and_d8_built_dex() {
        let plaintexts: [&str; 6] = crate::dex_builder::DEXGUARD_REFLECT_TOOLCHAIN_PLAINTEXT;
        let dex: &[u8] = crate::dex_builder::DEXGUARD_REFLECT_TOOLCHAIN_DEX;
        let report: ProtectorPeelReport =
            peel(dex, Some(DexGuardAuthorization::user_attested())).expect("ok");
        assert_eq!(report.status, PeelStatus::CipherRecovered);
        let recovered: Vec<&String> = report.strings_recovered.values().collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|s: &&String| s.as_str() == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
        assert!(
            report
                .notes
                .iter()
                .any(|n: &String| n.contains("reflective call site"))
        );
    }

    #[test]
    fn peels_native_backed_static_table_from_bundled_library() {
        let plaintexts: [&str; 3] = [
            "content://com.bank.app/accounts",
            "X-Device-Attestation",
            "AES/CBC/PKCS5Padding",
        ];
        let dex: Vec<u8> = crate::dex_builder::dexguard_native_key_sample(&plaintexts, 0x4D);
        let parsed: DexFile = dex::parse(&dex).expect("parse native-key dex");
        let native: crate::dex::NativeMethod = crate::dex::extract_native_methods(&parsed, &dex)
            .expect("native method scan")
            .into_iter()
            .find(|method: &crate::dex::NativeMethod| method.method == "nativeKey")
            .expect("native key method");
        let so: Vec<u8> = build_aarch64_key_so(&native.jni_short_symbol, 0x4D);
        assert!(
            disrobe_binfmt::parse_native(&so).is_ok(),
            "authored native key fixture must be a parseable ELF"
        );
        let report: ProtectorPeelReport = peel_with_native_libraries(
            &dex,
            &[("lib/arm64-v8a/libdgkeys.so", so.as_slice())],
            Some(DexGuardAuthorization::user_attested()),
        )
        .expect("native-key peel");
        assert_eq!(report.status, PeelStatus::CipherRecovered);
        let recovered: Vec<&String> = report.strings_recovered.values().collect();
        for expected in plaintexts {
            assert!(
                recovered.iter().any(|s: &&String| s.as_str() == expected),
                "missing {expected:?} in {recovered:?}"
            );
        }
        assert!(
            report
                .notes
                .iter()
                .any(|note: &String| note.contains("native integer key"))
        );
    }
}
