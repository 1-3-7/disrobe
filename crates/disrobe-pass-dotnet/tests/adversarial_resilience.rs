#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_dotnet::cil::{disassemble, parse_method_body};
use disrobe_pass_dotnet::cil_emulator::{StubInput, emulate_stub};
use disrobe_pass_dotnet::decompile::decompile_assembly;
use disrobe_pass_dotnet::metadata::StreamHeader;
use disrobe_pass_dotnet::tables::parse_tables;
use disrobe_pass_dotnet::{analyze, recover_static_decoders};

#[test]
fn analyze_rejects_empty_input() {
    assert!(analyze(&[]).is_err());
}

#[test]
fn analyze_rejects_truncated_dos_header() {
    assert!(analyze(&[0x4D, 0x5A]).is_err());
}

#[test]
fn analyze_rejects_random_bytes() {
    let junk: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let _ = analyze(&junk);
}

#[test]
fn parse_tables_rejects_oob_stream_header() {
    let bytes: Vec<u8> = vec![0u8; 32];
    let header: StreamHeader = StreamHeader {
        offset: 16,
        size: 1024,
    };
    assert!(parse_tables(&bytes, header).is_err());
}

#[test]
fn parse_tables_rejects_giant_row_counts() {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.push(2);
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    let valid: u64 = 1;
    bytes.extend_from_slice(&valid.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let header: StreamHeader = StreamHeader {
        offset: 0,
        size: u32::try_from(bytes.len()).unwrap(),
    };
    assert!(parse_tables(&bytes, header).is_err());
}

#[test]
fn disassemble_rejects_truncated_two_byte_opcode() {
    assert!(disassemble(&[0xFE]).is_err());
}

#[test]
fn parse_method_body_rejects_oversized_code_size() {
    let mut bytes: Vec<u8> = Vec::new();
    let flags_size: u16 = 3u16 << 12 | 0x03;
    bytes.extend_from_slice(&flags_size.to_le_bytes());
    bytes.extend_from_slice(&8u16.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    assert!(parse_method_body(&bytes).is_err());
}

#[test]
fn emulator_halts_on_self_branch_loop() {
    let body = parse_method_body(&[(1u8 << 2) | 0x02, 0x2A]).expect("tiny ret");
    let _ = emulate_stub(&body, &StubInput::default());
}

#[test]
fn emulator_bounds_oversized_newarr() {
    let mut code: Vec<u8> = vec![0x20];
    code.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    code.push(0x8D);
    code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
    code.push(0x2A);
    let mut tiny: Vec<u8> = vec![(u8::try_from(code.len()).unwrap() << 2) | 0x02];
    tiny.extend_from_slice(&code);
    let body = parse_method_body(&tiny).expect("tiny body");
    assert!(
        emulate_stub(&body, &StubInput::default()).is_err(),
        "oversized newarr must be rejected, not allocated"
    );
}

#[test]
fn recover_static_decoders_rejects_non_managed() {
    let junk: Vec<u8> = vec![0x4D, 0x5A, 0, 0, 0, 0];
    assert!(recover_static_decoders(&junk).is_err());
}

#[test]
fn decompile_assembly_rejects_non_managed() {
    assert!(decompile_assembly(&[0u8; 128]).is_err());
}

#[test]
fn bit_flipped_real_dll_never_panics() {
    let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/HelloApp.dll");
    let base: Vec<u8> = std::fs::read(&path).expect("fixture");
    let mut rng: u32 = 0x1234_5678;
    for _ in 0..200 {
        let mut m: Vec<u8> = base.clone();
        for _ in 0..8 {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            let pos: usize = (rng as usize) % m.len();
            m[pos] ^= 0xFF;
        }
        let _ = analyze(&m);
        let _ = decompile_assembly(&m);
        let _ = recover_static_decoders(&m);
    }
}
