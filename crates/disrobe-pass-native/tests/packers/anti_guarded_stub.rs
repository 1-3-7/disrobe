#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_core::neutralize::RuntimeCheck;
use disrobe_pass_native::packers::emulated_unpack::{
    EmulatedUnpack, EmulationConfig, MAX_IMPORT_THUNKS, MAX_TLS_CALLBACKS, emulate_unpack_stub,
};
use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::packers::stub_pack_oracle::{
    GUARD_K32_ILT, GUARD_TLS_CALLBACKS, GUARD_TLS_DIR, GUARD_TLS_MARKER, GUARDED_IMPORT_NAMES,
    GUARDED_STUB_SIZE, PackedImage, SectionSpec, StubKind, build_packed,
};

const TEXT_RVA: u32 = 0x1000;
const STUB_NAME: &[u8] = b".guard";
const STEP_CAP: u64 = 200_000;

fn text_body() -> Vec<u8> {
    let line: &[u8] =
        b"guarded payload row: decrypt me only once every runtime check is satisfied. ";
    let mut body: Vec<u8> = Vec::new();
    while body.len() < 2_000 {
        body.extend_from_slice(line);
    }
    body.truncate(2_000);
    body
}

fn guarded(inverted: bool) -> PackedImage {
    let text: Vec<u8> = text_body();
    build_packed(
        &[SectionSpec {
            name: b".text",
            rva: TEXT_RVA,
            body: text,
        }],
        TEXT_RVA,
        STUB_NAME,
        StubKind::GuardedStreamDecrypt {
            key0: 0x5A,
            key_step: 3,
            inverted,
        },
    )
}

fn emulate(packed: &[u8], original: &[u8], stub_rva: u32) -> EmulatedUnpack {
    let img: PeImage = parse_pe_image(packed).expect("authored packed image parses");
    emulate_unpack_stub(
        packed,
        &img,
        stub_rva,
        Some(original),
        &EmulationConfig {
            stub_section_names: &[STUB_NAME],
            content_exclude: &[],
            step_cap: STEP_CAP,
        },
    )
    .expect("emulation runs")
}

fn stub_file_offset(packed: &[u8], stub_rva: u32) -> usize {
    let img: PeImage = parse_pe_image(packed).expect("parses");
    let section = img
        .section_containing_rva(stub_rva)
        .expect("stub section present");
    section.raw_pointer as usize + (stub_rva - section.virtual_address) as usize
}

#[test]
fn guarded_stub_unpacks_to_the_original_bytes_once_every_check_is_served() {
    let p: PackedImage = guarded(false);
    let text: Vec<u8> = text_body();
    let img: PeImage = parse_pe_image(&p.bytes).expect("parses");
    assert_eq!(
        img.data_directories
            .get(9)
            .map(|d| (d.virtual_address, d.size)),
        Some((p.stub_rva + GUARD_TLS_DIR, 24)),
        "the authored image declares its TLS directory: {:?}",
        img.data_directories
    );
    let u: EmulatedUnpack = emulate(&p.bytes, &p.original, p.stub_rva);
    assert!(
        u.reached_oep(),
        "the guarded stub must pass its checks and reach the OEP: {} tls={:?} imports={}/{:?} events={:#?}",
        u.exit_reason,
        u.tls_callbacks,
        u.resolved_imports,
        u.unresolved_imports,
        u.neutralized
    );
    assert_eq!(u.oep_rva, Some(TEXT_RVA));
    let start: usize = TEXT_RVA as usize;
    assert_eq!(
        &u.recovered_memory_image[start..start + text.len()],
        text.as_slice(),
        "the decrypted content must equal the pre-pack bytes"
    );
    assert!(
        u.content_recovery_pct
            .is_some_and(|pct: f64| pct >= 100.0 - 1e-9),
        "{:?}",
        u.content_recovery_pct
    );
    assert_eq!(u.resolved_imports, GUARDED_IMPORT_NAMES.len());
    assert!(
        u.unresolved_imports.is_empty(),
        "{:?}",
        u.unresolved_imports
    );
    assert_eq!(u.tls_callbacks.len(), 1);
    assert!(u.tls_callbacks[0].returned, "{:?}", u.tls_callbacks[0]);
    let marker: usize = (p.stub_rva + GUARD_TLS_MARKER) as usize;
    assert_eq!(
        u.recovered_memory_image[marker], 1,
        "the TLS callback must have run before the entry point and set its marker"
    );

    let expected: BTreeSet<RuntimeCheck> = BTreeSet::from([
        RuntimeCheck::IsDebuggerPresent,
        RuntimeCheck::PebBeingDebugged,
        RuntimeCheck::PebNtGlobalFlag,
        RuntimeCheck::HeapFlags,
        RuntimeCheck::RdtscDelta,
        RuntimeCheck::CpuidHypervisorBit,
        RuntimeCheck::NtQueryInformationProcessDebugPort,
        RuntimeCheck::TickCountDelta,
        RuntimeCheck::VectoredExceptionHandler,
        RuntimeCheck::Int2dTrap,
        RuntimeCheck::TlsCallback,
    ]);
    let seen: BTreeSet<RuntimeCheck> = u.neutralized_checks().into_iter().collect();
    assert_eq!(
        seen, expected,
        "every neutralised check is named: {:#?}",
        u.neutralized
    );
    assert_eq!(u.neutralized_dropped, 0);
    let stub_lo: u64 = u.image_base + u64::from(p.stub_rva);
    let stub_hi: u64 = stub_lo + GUARDED_STUB_SIZE as u64;
    for event in &u.neutralized {
        assert!(
            event.anchor.address >= stub_lo && event.anchor.address < stub_hi,
            "evidence must anchor inside the stub section: {event:?}"
        );
        assert!(!event.anchor.pattern.is_empty() && !event.outcome.is_empty());
    }
}

#[test]
fn inverted_guards_keep_the_stub_from_reaching_the_oep() {
    let p: PackedImage = guarded(true);
    let text: Vec<u8> = text_body();
    let u: EmulatedUnpack = emulate(&p.bytes, &p.original, p.stub_rva);
    assert!(
        !u.reached_oep(),
        "with every guard inverted the first satisfied check must trap the stub: {}",
        u.exit_reason
    );
    let start: usize = TEXT_RVA as usize;
    assert_ne!(
        &u.recovered_memory_image[start..start + text.len()],
        text.as_slice(),
        "the payload must stay encrypted when the stub traps"
    );
}

#[test]
fn removing_the_tls_directory_leaves_the_marker_unset_and_the_stub_trapped() {
    let p: PackedImage = guarded(false);
    let mut mutated: Vec<u8> = p.bytes.clone();
    let img: PeImage = parse_pe_image(&mutated).expect("parses");
    let opt: usize = img.pe_header_offset as usize + 4 + 20;
    let tls_entry: usize = opt + 96 + 9 * 8;
    mutated[tls_entry..tls_entry + 8].fill(0);
    let u: EmulatedUnpack = emulate(&mutated, &p.original, p.stub_rva);
    assert!(u.tls_callbacks.is_empty());
    assert!(
        !u.reached_oep(),
        "without the TLS callback the marker check must fail: {}",
        u.exit_reason
    );
    assert!(
        !u.neutralized_checks().contains(&RuntimeCheck::TlsCallback),
        "{:?}",
        u.neutralized_checks()
    );
}

#[test]
fn a_tls_callback_array_past_the_cap_is_bounded_and_out_of_image_callbacks_are_refused() {
    let p: PackedImage = guarded(false);
    let mut mutated: Vec<u8> = p.bytes.clone();
    let stub_off: usize = stub_file_offset(&mutated, p.stub_rva);
    let callbacks: usize = stub_off + GUARD_TLS_CALLBACKS as usize;
    let callback_va: u32 = u32::from_le_bytes(
        mutated[callbacks..callbacks + 4]
            .try_into()
            .expect("four bytes"),
    );
    let text_off: usize = stub_file_offset(&mutated, TEXT_RVA);
    let text_va: u32 = 0x0040_0000 + TEXT_RVA;
    let tls_dir: usize = stub_off + GUARD_TLS_DIR as usize;
    mutated[tls_dir + 12..tls_dir + 16].copy_from_slice(&text_va.to_le_bytes());
    let count: usize = 64;
    assert!(
        count > MAX_TLS_CALLBACKS,
        "the fixture leaves room past the cap"
    );
    for i in 0..count {
        let at: usize = text_off + i * 4;
        let value: u32 = if i == 3 { 0x7000_0000 } else { callback_va };
        mutated[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let u: EmulatedUnpack = emulate(&mutated, &p.original, p.stub_rva);
    assert_eq!(
        u.tls_callbacks.len(),
        MAX_TLS_CALLBACKS,
        "callback execution stops at the cap: {:?}",
        u.tls_callbacks
    );
    assert!(
        !u.tls_callbacks[3].returned
            && u.tls_callbacks[3]
                .outcome
                .contains("outside the mapped image"),
        "{:?}",
        u.tls_callbacks[3]
    );
    assert!(u.tls_callbacks[0].returned);
}

#[test]
fn an_import_lookup_table_without_a_terminator_is_bounded() {
    let p: PackedImage = guarded(false);
    let mut mutated: Vec<u8> = p.bytes.clone();
    let stub_off: usize = stub_file_offset(&mutated, p.stub_rva);
    let ilt: usize = stub_off + GUARD_K32_ILT as usize;
    let name_rva: u32 = u32::from_le_bytes(mutated[ilt..ilt + 4].try_into().expect("four bytes"));
    let end: usize = stub_off + GUARDED_STUB_SIZE;
    let mut at: usize = ilt;
    while at + 4 <= end {
        mutated[at..at + 4].copy_from_slice(&name_rva.to_le_bytes());
        at += 4;
    }
    let img: PeImage = parse_pe_image(&mutated).expect("parses");
    let out: EmulatedUnpack = emulate_unpack_stub(
        &mutated,
        &img,
        p.stub_rva,
        None,
        &EmulationConfig {
            stub_section_names: &[STUB_NAME],
            content_exclude: &[],
            step_cap: 20_000,
        },
    )
    .expect("a hostile import table never panics");
    assert!(
        out.resolved_imports + out.unresolved_imports.len() <= 2 * MAX_IMPORT_THUNKS,
        "resolution walked {} + {} entries",
        out.resolved_imports,
        out.unresolved_imports.len()
    );
}
