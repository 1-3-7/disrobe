#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

mod common;

use disrobe_pass_dotnet::peel::maxtocode::peel_maxtocode;
use disrobe_pass_dotnet::peel::native_surface::{
    NativeArch, NativeStubSurface, surface_native_stub,
};
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};

use crate::common::protector_pe::{build_maxtocode_pe, tiny_method_body};

const STUB_X86: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8B, 0x45, 0x08, 0x33, 0xC9, 0xC9, 0xC3,
];

const STUB_MNEMONICS: &[&str] = &["push", "mov", "sub", "mov", "xor", "leave", "ret"];

fn plain_method() -> Vec<u8> {
    tiny_method_body(&[0x16, 0x2A])
}

fn maxtocode_image_with_native_stub() -> Vec<u8> {
    build_maxtocode_pe(3, &plain_method(), STUB_X86, None)
}

#[test]
fn maxtocode_native_section_disassembles_byte_exact_to_known_x86_prologue() {
    let image: Vec<u8> = maxtocode_image_with_native_stub();
    let surface: NativeStubSurface = surface_native_stub(&image, &[".mtc", ".maxtc", ".text1"])
        .expect("the .mtc native section must be located and disassembled");

    assert_eq!(
        surface.section_name, ".mtc",
        "native surfacing must target the MaxToCode native loader section by name"
    );
    assert_eq!(
        surface.arch,
        NativeArch::X86,
        "the PE32 carrier must drive a 32-bit x86 decode"
    );

    let decoded: Vec<&str> = surface
        .disasm
        .iter()
        .take(STUB_MNEMONICS.len())
        .map(|line: &String| {
            line.split_whitespace()
                .nth(2)
                .expect("each disasm line has an address, hex, mnemonic")
        })
        .collect();
    assert_eq!(
        decoded, STUB_MNEMONICS,
        "the surfaced native disassembly must match the assembled x86 prologue mnemonic-for-mnemonic \
         (non-circular: the byte sequence is fixed and known, the decoder is iced-x86); disasm={:?}",
        surface.disasm
    );
}

#[test]
fn maxtocode_native_stub_decode_is_clean_over_the_known_window() {
    let image: Vec<u8> = maxtocode_image_with_native_stub();
    let surface: NativeStubSurface =
        surface_native_stub(&image, &[".mtc", ".maxtc", ".text1"]).expect("surface");

    assert!(
        surface.instructions_decoded >= STUB_MNEMONICS.len() as u32,
        "every instruction of the known prologue must decode; got {}",
        surface.instructions_decoded
    );
    assert!(
        surface.decode_clean,
        "the bounded window must decode with no trailing undecoded bytes"
    );
    assert!(
        surface.disasm[0].contains("00404000"),
        "the first instruction address must be image_base(0x400000)+mtc_rva, not a synthetic base; \
         line={}",
        surface.disasm[0]
    );
}

#[test]
fn peel_maxtocode_surfaces_the_native_loader_and_still_walls_the_bodies() {
    let image: Vec<u8> = maxtocode_image_with_native_stub();
    let report: PeelReport = peel_maxtocode(&image).expect("peel");

    assert_eq!(
        report.strategy,
        PeelStrategy::DetectOnlyNativeOrVm,
        "surfacing native code must not promote the body recovery past the native-key wall"
    );
    assert_eq!(
        report.recovered_decoders, 0,
        "no managed body is recovered; the native key is computed by the unmanaged loader"
    );

    let surface: &NativeStubSurface = report
        .native_surface
        .as_ref()
        .expect("the report must carry the surfaced native loader disassembly, not stay silent");
    assert_eq!(surface.section_name, ".mtc");
    assert!(surface.instructions_decoded >= STUB_MNEMONICS.len() as u32);

    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("native surfacing") && n.contains(".mtc")),
        "the report must plainly state that the native loader was surfaced; notes={:?}",
        report.notes
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("NATIVE-KEY WALL")),
        "the body-recovery wall must remain stated alongside the native surfacing; notes={:?}",
        report.notes
    );
}

#[test]
fn surfacing_returns_none_when_no_named_or_executable_section_matches() {
    let image: Vec<u8> = maxtocode_image_with_native_stub();
    let surface: Option<NativeStubSurface> =
        surface_native_stub(&image, &[".nonexistent_section_xyz"]);
    assert!(
        surface.is_none(),
        "with no named hit and the only executable section being the managed-metadata .text, the \
         data-only .mtc must not be force-disassembled; surfacing honestly returns nothing rather \
         than presenting decoded data bytes as code"
    );
}
