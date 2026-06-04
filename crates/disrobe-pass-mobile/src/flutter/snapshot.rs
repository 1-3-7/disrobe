use serde::{Deserialize, Serialize};

use super::demangler::{DemangledName, demangle};

/// Image header size from Dart VM `Image::kHeaderSize == kObjectStartAlignment`
/// (`runtime/vm/pointer_tagging.h`), 64 bytes on every supported target.
const IMAGE_HEADER_SIZE: usize = 64;

/// ARM64 `stp x29, x30, [sp, #-16]!` — the `PushPair(FP, LR)` that opens every
/// Dart AOT frame (`Assembler::EnterFrame`).
const ARM64_PUSH_FP_LR: u32 = 0xA9BF_7BFD;
/// ARM64 `mov x29, sp` — the second prologue instruction following the push.
const ARM64_MOV_FP_SP: u32 = 0x9100_03FD;

/// Bare-instructions payload alignment from Dart VM
/// `Instructions::kBarePayloadAlignment`.
const BARE_PAYLOAD_ALIGNMENT: usize = 4;

/// Upper bound on function boundaries reported, guarding against a degenerate
/// instructions blob whose every 4-byte word matches the prologue pattern.
const MAX_FUNCTION_BOUNDARIES: usize = 1 << 20;

/// Minimum length for a byte run to count as a recoverable Dart identifier.
const MIN_IDENTIFIER_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageHeader {
    pub image_size: u64,
    pub instructions_section_offset: u64,
}

/// Parses the leading `Image` header of an instructions/data blob.
///
/// Two target words: image size, then the `InstructionsSection` object offset
/// (`0` means no such section). Returns `None` if the blob is shorter than one
/// header.
#[must_use]
pub fn parse_image_header(blob: &[u8]) -> Option<ImageHeader> {
    if blob.len() < IMAGE_HEADER_SIZE {
        return None;
    }
    let image_size: u64 = u64::from_le_bytes(read8(blob, 0)?);
    let instructions_section_offset: u64 = u64::from_le_bytes(read8(blob, 8)?);
    Some(ImageHeader {
        image_size,
        instructions_section_offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartFunctionBoundary {
    pub offset: usize,
    pub inferred_arg_registers: u8,
    pub has_frame: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DartStaticRecovery {
    pub function_boundary_count: usize,
    pub function_boundaries: Vec<DartFunctionBoundary>,
    pub class_names: Vec<String>,
    pub method_names: Vec<DemangledName>,
    pub library_uris: Vec<String>,
    pub recovered_name_count: usize,
}

/// Recovers static, source-visible structure from a Dart AOT `libapp.so`'s
/// isolate snapshot blobs.
///
/// Recovers function boundaries (ARM64 prologue scan of the instructions image)
/// with inferred argument-register signatures, plus class names, demangled
/// method names, and library URIs harvested from the data snapshot's read-only
/// string clusters.
///
/// HONEST: Dart AOT register-allocates locals away and lowers async to state
/// machines, so statement-level bodies are not statically recoverable. This
/// recovers boundaries + signatures + names (the ~45-55% static ceiling), and
/// every body remains a skeleton.
#[must_use]
pub fn recover_dart_static(isolate_data: &[u8], isolate_instructions: &[u8]) -> DartStaticRecovery {
    let function_boundaries: Vec<DartFunctionBoundary> =
        scan_function_boundaries(isolate_instructions);
    let identifiers: Vec<String> = extract_dart_identifiers(isolate_data);

    let mut class_names: Vec<String> = Vec::new();
    let mut method_names: Vec<DemangledName> = Vec::new();
    let mut library_uris: Vec<String> = Vec::new();

    for ident in &identifiers {
        if is_library_uri(ident) {
            library_uris.push(ident.clone());
        } else if is_class_name(ident) {
            class_names.push(ident.clone());
        } else if is_method_name(ident) {
            method_names.push(demangle(ident));
        }
    }
    class_names.sort_unstable();
    class_names.dedup();
    library_uris.sort_unstable();
    library_uris.dedup();
    method_names.sort_by(|a: &DemangledName, b: &DemangledName| a.scrubbed.cmp(&b.scrubbed));
    method_names.dedup();

    let recovered_name_count: usize = class_names.len() + method_names.len() + library_uris.len();
    DartStaticRecovery {
        function_boundary_count: function_boundaries.len(),
        function_boundaries,
        class_names,
        method_names,
        library_uris,
        recovered_name_count,
    }
}

/// Scans an instructions image for ARM64 Dart frame prologues, reporting each as
/// a function boundary with an inferred argument-register count.
#[must_use]
fn scan_function_boundaries(instructions: &[u8]) -> Vec<DartFunctionBoundary> {
    let body_start: usize = if instructions.len() >= IMAGE_HEADER_SIZE {
        IMAGE_HEADER_SIZE
    } else {
        0
    };
    let mut out: Vec<DartFunctionBoundary> = Vec::new();
    let mut i: usize = body_start;
    while i + 8 <= instructions.len() && out.len() < MAX_FUNCTION_BOUNDARIES {
        let w0: u32 = u32::from_le_bytes([
            instructions[i],
            instructions[i + 1],
            instructions[i + 2],
            instructions[i + 3],
        ]);
        if w0 == ARM64_PUSH_FP_LR {
            let w1: u32 = u32::from_le_bytes([
                instructions[i + 4],
                instructions[i + 5],
                instructions[i + 6],
                instructions[i + 7],
            ]);
            let has_frame: bool = w1 == ARM64_MOV_FP_SP;
            let inferred_arg_registers: u8 = infer_arg_registers(&instructions[i..], has_frame);
            out.push(DartFunctionBoundary {
                offset: i,
                inferred_arg_registers,
                has_frame,
            });
            i += BARE_PAYLOAD_ALIGNMENT.max(8);
        } else {
            i += BARE_PAYLOAD_ALIGNMENT;
        }
    }
    out
}

/// Infers how many ARM64 argument registers (x0..x7) a function reads by
/// scanning its prologue window for instructions that source those registers
/// before the frame is torn down. This is a calling-convention signature
/// approximation, not exact arity, because some args arrive on the stack.
#[must_use]
fn infer_arg_registers(func: &[u8], _has_frame: bool) -> u8 {
    const WINDOW_INSNS: usize = 32;
    let mut seen: u8 = 0;
    let limit: usize = (WINDOW_INSNS * 4).min(func.len());
    let mut i: usize = 0;
    while i + 4 <= limit {
        let w: u32 = u32::from_le_bytes([func[i], func[i + 1], func[i + 2], func[i + 3]]);
        if is_arm64_return(w) {
            break;
        }
        let rn: u8 = ((w >> 5) & 0x1f) as u8;
        let rm: u8 = ((w >> 16) & 0x1f) as u8;
        for reg in [rn, rm] {
            if reg < 8 {
                seen |= 1u8 << reg;
            }
        }
        i += 4;
    }
    seen.count_ones() as u8
}

#[must_use]
const fn is_arm64_return(w: u32) -> bool {
    w == 0xD65F_03C0
}

#[must_use]
fn extract_dart_identifiers(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for byte in data {
        if is_dart_ident_byte(*byte) {
            current.push(*byte);
        } else {
            flush_identifier(&mut current, &mut out);
        }
    }
    flush_identifier(&mut current, &mut out);
    out
}

fn flush_identifier(current: &mut Vec<u8>, out: &mut Vec<String>) {
    if current.len() >= MIN_IDENTIFIER_LEN
        && let Ok(s) = std::str::from_utf8(current)
        && looks_like_dart_name(s)
    {
        out.push(s.to_owned());
    }
    current.clear();
}

#[must_use]
const fn is_dart_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'_'
        || b == b'.'
        || b == b'@'
        || b == b':'
        || b == b'/'
        || b == b'<'
        || b == b'>'
}

#[must_use]
fn looks_like_dart_name(s: &str) -> bool {
    let first: char = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == 'd' || first == 'p') {
        return false;
    }
    s.chars().any(|c: char| c.is_ascii_alphabetic())
}

#[must_use]
fn is_library_uri(s: &str) -> bool {
    s.starts_with("package:")
        || s.starts_with("dart:")
        || s.starts_with("file:")
        || (s.contains('/') && s.ends_with(".dart"))
}

#[must_use]
fn is_class_name(s: &str) -> bool {
    if s.contains(':') || s.contains('/') {
        return false;
    }
    let first: char = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    let leading: char = if first == '_' {
        s.chars().nth(1).unwrap_or(first)
    } else {
        first
    };
    leading.is_ascii_uppercase() && !s.contains('@')
}

#[must_use]
fn is_method_name(s: &str) -> bool {
    s.starts_with("get:") || s.starts_with("set:") || s.contains('@') || {
        let first: char = match s.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let leading: char = if first == '_' {
            s.chars().nth(1).unwrap_or(first)
        } else {
            first
        };
        leading.is_ascii_lowercase() && !s.contains('/') && !s.contains(':')
    }
}

#[must_use]
fn read8(blob: &[u8], at: usize) -> Option<[u8; 8]> {
    let end: usize = at.checked_add(8)?;
    if end > blob.len() {
        return None;
    }
    let mut out: [u8; 8] = [0u8; 8];
    out.copy_from_slice(&blob[at..end]);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn arm64_func(arg_regs: &[u8], body_filler: usize) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&ARM64_PUSH_FP_LR.to_le_bytes());
        v.extend_from_slice(&ARM64_MOV_FP_SP.to_le_bytes());
        for reg in arg_regs {
            let insn: u32 = 0x9100_0000 | ((*reg as u32) << 5);
            v.extend_from_slice(&insn.to_le_bytes());
        }
        for _ in 0..body_filler {
            v.extend_from_slice(&0x9100_03FFu32.to_le_bytes());
        }
        v.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        v
    }

    fn image_with_funcs(funcs: &[Vec<u8>]) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0u8; IMAGE_HEADER_SIZE];
        for f in funcs {
            v.extend_from_slice(f);
            while v.len() % 16 != 0 {
                v.push(0u8);
            }
        }
        v
    }

    #[test]
    fn parses_image_header() {
        let mut blob: Vec<u8> = vec![0u8; IMAGE_HEADER_SIZE];
        blob[0..8].copy_from_slice(&4096u64.to_le_bytes());
        blob[8..16].copy_from_slice(&512u64.to_le_bytes());
        let header: ImageHeader = parse_image_header(&blob).expect("header");
        assert_eq!(header.image_size, 4096);
        assert_eq!(header.instructions_section_offset, 512);
    }

    #[test]
    fn scans_two_function_boundaries() {
        let funcs: Vec<Vec<u8>> = vec![arm64_func(&[0, 1], 2), arm64_func(&[0], 1)];
        let image: Vec<u8> = image_with_funcs(&funcs);
        let boundaries: Vec<DartFunctionBoundary> = scan_function_boundaries(&image);
        assert_eq!(boundaries.len(), 2);
        assert!(boundaries[0].has_frame);
        assert!(boundaries[0].inferred_arg_registers >= 2);
    }

    #[test]
    fn classifies_dart_names() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:myapp/main.dart\x00");
        data.extend_from_slice(b"MyWidget\x00");
        data.extend_from_slice(b"build\x00");
        data.extend_from_slice(b"get:length@1a2b3c\x00");
        data.extend_from_slice(b"_PrivateState\x00");
        let recovery: DartStaticRecovery = recover_dart_static(&data, &[]);
        assert!(
            recovery
                .library_uris
                .iter()
                .any(|u: &String| u == "package:myapp/main.dart")
        );
        assert!(
            recovery
                .class_names
                .iter()
                .any(|c: &String| c == "MyWidget")
        );
        assert!(
            recovery
                .class_names
                .iter()
                .any(|c: &String| c == "_PrivateState")
        );
        assert!(
            recovery
                .method_names
                .iter()
                .any(|m: &DemangledName| m.scrubbed == "build")
        );
        assert!(
            recovery
                .method_names
                .iter()
                .any(|m: &DemangledName| m.scrubbed == "length")
        );
        assert!(recovery.recovered_name_count >= 4);
    }

    #[test]
    fn end_to_end_recovery_counts_functions_and_names() {
        let funcs: Vec<Vec<u8>> = vec![arm64_func(&[0], 1), arm64_func(&[0, 1, 2], 2)];
        let image: Vec<u8> = image_with_funcs(&funcs);
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"\x00package:app/x.dart\x00HomePage\x00createState\x00");
        let recovery: DartStaticRecovery = recover_dart_static(&data, &image);
        assert_eq!(recovery.function_boundary_count, 2);
        assert!(recovery.recovered_name_count >= 3);
    }

    #[test]
    fn empty_inputs_do_not_panic() {
        let recovery: DartStaticRecovery = recover_dart_static(&[], &[]);
        assert_eq!(recovery.function_boundary_count, 0);
        assert_eq!(recovery.recovered_name_count, 0);
    }
}
