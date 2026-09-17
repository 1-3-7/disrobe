#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stderr
)]

use disrobe_pass_native::packers::stub_pack_oracle::{
    PackedImage, SectionSpec, StubKind, build_packed,
};
use disrobe_pass_native::{
    AsProtectRecovery, MorphineRecovery, NPackRecovery, NeoLiteRecovery, Packer,
    PolyCryptorRecovery, UnpackerStatus, WarzoneCrypterRecovery, detect_packers, morphine_layout,
    unpack_asprotect_emulated, unpack_morphine_emulated, unpack_neolite_emulated,
    unpack_npack_emulated, unpack_polycryptor_emulated, unpack_warzone_crypter_emulated,
};

fn sample(len: usize, tag: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(tag);
        out.extend_from_slice(b" original recoverable content; ");
    }
    out.truncate(len);
    out
}

fn pe_with_section(name: &[u8]) -> Vec<u8> {
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let mut buf: Vec<u8> = vec![0u8; sec_table + 40 + 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x80 + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    let len: usize = name.len().min(8);
    buf[sec_table..sec_table + len].copy_from_slice(&name[..len]);
    buf
}

fn pe_with_marker(marker: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = pe_with_section(b".text");
    let body: usize = buf.len().saturating_sub(0x100);
    buf[body..body + marker.len()].copy_from_slice(marker);
    buf
}

#[test]
fn asprotect_detect_stays_green_and_is_stub_eval_pending() {
    let buf: Vec<u8> = pe_with_marker(b".asprotect");
    assert!(
        detect_packers(&buf)
            .iter()
            .any(|h| h.packer == Packer::AsProtect),
        "ASProtect detection must stay green",
    );
    assert_eq!(
        Packer::AsProtect.unpacker_status(),
        UnpackerStatus::StubEvalPending,
        "ASProtect ships a stub emulator validated against a synthetic stub; real-sample recovery \
         is unproven so the catalog advertises Partial, not Full",
    );
}

#[test]
fn morphine_detect_stays_green_and_is_stub_eval_pending() {
    let buf: Vec<u8> = pe_with_section(b"morphine");
    assert!(
        detect_packers(&buf)
            .iter()
            .any(|h| h.packer == Packer::Morphine),
        "Morphine detection must stay green",
    );
    assert_eq!(
        Packer::Morphine.unpacker_status(),
        UnpackerStatus::StubEvalPending,
    );
}

#[test]
fn asprotect_emulator_inverts_a_synthetic_decrypt_stub() {
    eprintln!(
        "wiring/sanity test: build_packed emits a real x86 stream-decrypt stub that the unpacker \
         emulates blind (non-circular inversion of a synthetic stub); this is NOT real ASProtect \
         recovery - a captured ASProtect sample uses a polymorphic native VM-stub that is \
         commercial and not in the corpus, so this proves the emulator engine, not real-sample \
         recovery"
    );
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1600, b"asprotect"),
    }];
    let p: PackedImage = build_packed(
        &secs,
        0x1000,
        b".aspr",
        StubKind::StreamDecrypt {
            key0: 0x44,
            key_step: 0x29,
        },
    );
    let rec: AsProtectRecovery =
        unpack_asprotect_emulated(&p.bytes, Some(&p.original)).expect("recovery");
    assert!(
        rec.reached_oep,
        "the synthetic decrypt stub must reach the OEP"
    );
    assert!(
        (rec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
        "the emulator must invert the synthetic stub byte-exact; got {:?}",
        rec.unpack.content_recovery_pct
    );
}

#[test]
fn morphine_emulator_inverts_a_synthetic_decrypt_stub() {
    eprintln!(
        "wiring/sanity test: build_packed emits a real x86 stream-decrypt stub that the unpacker \
         emulates blind (non-circular inversion of a synthetic stub); this is NOT real Morphine \
         recovery - a captured Morphine sample uses a polymorphic native stub not in the corpus, \
         so this proves the emulator engine, not real-sample recovery"
    );
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1400, b"morphine"),
    }];
    let p: PackedImage = build_packed(
        &secs,
        0x1000,
        b".morph",
        StubKind::StreamDecrypt {
            key0: 0x88,
            key_step: 0x17,
        },
    );
    let rec: MorphineRecovery =
        unpack_morphine_emulated(&p.bytes, Some(&p.original)).expect("recovery");
    assert!(rec.reached_oep);
    assert!((rec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,);
    let layout = morphine_layout(&p.bytes).expect("layout");
    assert_eq!(layout.section_count, 2);
}

#[test]
fn asprotect_and_morphine_emulators_invert_a_polymorphic_decrypt_stub() {
    eprintln!(
        "wiring/sanity test: build_packed emits a polymorphic x86 stream-decrypt stub (per-seed \
         register permutation, junk identity sequences, push/ret OEP transfer) that the unpacker \
         emulates blind. This proves the emulator survives the per-build stub mutation documented \
         for the real ASProtect/Morphine decryptors, not just one fixed layout; it is still the \
         engine proof, NOT vendor-sample recovery (the real protectors are not in the corpus)"
    );
    for seed in 0u8..4 {
        let asp_secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: sample(1600, b"asprotect"),
        }];
        let asp: PackedImage = build_packed(
            &asp_secs,
            0x1000,
            b".aspr",
            StubKind::StreamDecryptPoly {
                key0: 0x44u8.wrapping_add(seed.wrapping_mul(5)),
                key_step: 0x29u8.wrapping_add(seed.wrapping_mul(3)),
                seed,
            },
        );
        let arec: AsProtectRecovery =
            unpack_asprotect_emulated(&asp.bytes, Some(&asp.original)).expect("asprotect recovery");
        assert!(
            arec.reached_oep,
            "seed {seed}: polymorphic ASProtect-shape stub must reach the OEP",
        );
        assert!(
            (arec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
            "seed {seed}: emulator must invert the polymorphic ASProtect-shape stub byte-exact; got {:?}",
            arec.unpack.content_recovery_pct,
        );

        let morph_secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: sample(1400, b"morphine"),
        }];
        let morph: PackedImage = build_packed(
            &morph_secs,
            0x1000,
            b".morph",
            StubKind::StreamDecryptPoly {
                key0: 0x88u8.wrapping_add(seed.wrapping_mul(9)),
                key_step: 0x17u8.wrapping_add(seed.wrapping_mul(13)),
                seed,
            },
        );
        let mrec: MorphineRecovery = unpack_morphine_emulated(&morph.bytes, Some(&morph.original))
            .expect("morphine recovery");
        assert!(
            mrec.reached_oep,
            "seed {seed}: polymorphic Morphine-shape stub must reach the OEP",
        );
        assert!(
            (mrec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
            "seed {seed}: emulator must invert the polymorphic Morphine-shape stub byte-exact; got {:?}",
            mrec.unpack.content_recovery_pct,
        );
    }
}

#[test]
fn npack_and_neolite_emulators_invert_a_synthetic_lz_stub() {
    eprintln!(
        "wiring/sanity test: a real x86 LZ-decompress stub emulated blind; this proves the \
         emulator engine, NOT real nPack/NeoLite recovery (no captured samples in the corpus)"
    );
    let npack_secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1500, b"npack"),
    }];
    let np: PackedImage = build_packed(&npack_secs, 0x1000, b".nPack", StubKind::LzDecompress);
    let nrec: NPackRecovery =
        unpack_npack_emulated(&np.bytes, Some(&np.original)).expect("npack recovery");
    assert!(nrec.reached_oep, "nPack LZ stub must reach the OEP");
    assert!(nrec.unpack.content_recovery_pct.unwrap_or(0.0) > 99.0);

    let neo_secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1500, b"neolite"),
    }];
    let neo: PackedImage = build_packed(&neo_secs, 0x1000, b"neolite", StubKind::LzDecompress);
    let neorec: NeoLiteRecovery =
        unpack_neolite_emulated(&neo.bytes, Some(&neo.original)).expect("neolite recovery");
    assert!(neorec.reached_oep, "NeoLite LZ stub must reach the OEP");
    assert!(neorec.unpack.content_recovery_pct.unwrap_or(0.0) > 99.0);
}

#[test]
fn polycryptor_and_warzone_are_stub_eval_pending_clr_crypters_delegate_to_dotnet() {
    assert_eq!(
        Packer::PolyCryptor.unpacker_status(),
        UnpackerStatus::StubEvalPending,
        "PolyCryptor is a native XOR/stream crypter; the emulator inverts a synthetic decrypt stub \
         but recovery on a captured sample is unproven, so it is Partial not Full",
    );
    assert_eq!(
        Packer::WarzoneCrypter.unpacker_status(),
        UnpackerStatus::StubEvalPending,
        "the Warzone crypter emulator is validated on a synthetic stub; real-sample recovery is \
         unproven, so it is Partial not Full",
    );
    assert_eq!(
        Packer::DotNetPatcher.unpacker_status(),
        UnpackerStatus::DelegatedToDotnet,
        "DotNetPatcher is a managed wrapper and must route through the .NET pass",
    );
    assert_eq!(
        Packer::NetCryptor.unpacker_status(),
        UnpackerStatus::DelegatedToDotnet,
        "NetCryptor is a managed wrapper and must route through the .NET pass",
    );
}

#[test]
fn polycryptor_emulator_inverts_a_synthetic_decrypt_stub() {
    eprintln!(
        "wiring/sanity test: a real x86 stream-decrypt stub emulated blind; proves the emulator \
         engine, NOT real PolyCryptor recovery (no captured sample in the corpus)"
    );
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1600, b"polycryptor"),
    }];
    let p: PackedImage = build_packed(
        &secs,
        0x1000,
        b".pc0",
        StubKind::StreamDecrypt {
            key0: 0x73,
            key_step: 0x2F,
        },
    );
    let rec: PolyCryptorRecovery =
        unpack_polycryptor_emulated(&p.bytes, Some(&p.original)).expect("recovery");
    assert!(
        rec.reached_oep,
        "the synthetic decrypt stub must reach the OEP"
    );
    assert!(
        (rec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
        "the emulator must invert the synthetic stub byte-exact; got {:?}",
        rec.unpack.content_recovery_pct
    );
}

#[test]
fn warzone_crypter_emulator_inverts_a_synthetic_decrypt_stub() {
    eprintln!(
        "wiring/sanity test: a real x86 stream-decrypt stub emulated blind; proves the emulator \
         engine, NOT real Warzone crypter recovery (no captured sample in the corpus)"
    );
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample(1400, b"warzone"),
    }];
    let p: PackedImage = build_packed(
        &secs,
        0x1000,
        b".wz0",
        StubKind::StreamDecrypt {
            key0: 0xC4,
            key_step: 0x6B,
        },
    );
    let rec: WarzoneCrypterRecovery =
        unpack_warzone_crypter_emulated(&p.bytes, Some(&p.original)).expect("recovery");
    assert!(
        rec.reached_oep,
        "the synthetic decrypt stub must reach the OEP"
    );
    assert!(
        (rec.unpack.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
        "the emulator must invert the synthetic stub byte-exact; got {:?}",
        rec.unpack.content_recovery_pct
    );
}

#[test]
fn stub_eval_pending_wall_reason_is_honest_and_distinct() {
    let pending: &str = UnpackerStatus::StubEvalPending.wall_reason();
    assert!(
        pending.contains("real-sample recovery is unproven"),
        "the StubEvalPending wall reason must state plainly that vendor-sample recovery is \
         unproven, not imply a Full recovery claim; got {pending:?}",
    );
    assert!(
        pending.contains("native-VM") && pending.contains("import table"),
        "the reason must name the two layers a captured ASProtect sample adds over the core \
         decrypt-to-oep shape (native-VM stub + runtime import rebuild); got {pending:?}",
    );
    assert_ne!(
        pending,
        UnpackerStatus::Implemented.wall_reason(),
        "a pending wall reason must differ from the implemented sentinel",
    );
    assert_eq!(
        Packer::AsProtect.unpacker_status().wall_reason(),
        pending,
        "ASProtect must surface the StubEvalPending wall reason verbatim",
    );
    for status in [
        UnpackerStatus::DetectOnly,
        UnpackerStatus::GreyZoneDetectOnly,
        UnpackerStatus::GreyZoneDetectAndCarve,
    ] {
        assert!(
            status.wall_reason().contains("wall"),
            "{status:?} must declare the concrete wall reason text",
        );
    }
    assert!(
        UnpackerStatus::DelegatedToDotnet
            .wall_reason()
            .contains("dotnet.classify"),
        "delegated CLR wrappers must name the recovery pass"
    );
}

#[test]
fn unpackers_reject_non_pe_without_fabricating_recovery() {
    assert!(unpack_asprotect_emulated(b"not a pe", None).is_err());
    assert!(unpack_morphine_emulated(b"not a pe", None).is_err());
    assert!(unpack_npack_emulated(b"not a pe", None).is_err());
    assert!(unpack_neolite_emulated(b"not a pe", None).is_err());
    assert!(unpack_polycryptor_emulated(b"not a pe", None).is_err());
    assert!(unpack_warzone_crypter_emulated(b"not a pe", None).is_err());
}
