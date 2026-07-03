#![allow(clippy::doc_markdown)]
use crate::debug::dbg_kv;
use crate::error::Result;
use crate::peel::maxtocode_bodies::{
    MAXTOCODE_SECTION_NAMES, MaxKeyOrigin, MaxToCodeRecovery, recover_maxtocode_bodies,
};
use crate::peel::native_surface::surface_native_stub;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["MaxtoCode", "NetSafe"];

const BASE_RATIONALE: &str = "MaxToCode sets every protected MethodDef RVA to 0 and stores the ciphertext for each body in \
     an added native-loaded section, restoring the bodies at JIT time through an unmanaged loader \
     hooked into the EE/JIT layer (the path dynamic dumpers such as RE-Max take by running the \
     process and capturing the JIT-restored bodies). The per-method key is computed inside that \
     native DLL, so the original CIL is not present in the static metadata; static recovery extends \
     to the zero-RVA method enumeration and the located encrypted section (name/rva/size/sha), while \
     the bodies stay walled on the native JIT-hook loader.";

pub fn peel_maxtocode(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport =
        detect_only_native(Protector::MaxToCode, bytes, WATERMARKS, BASE_RATIONALE)?;
    let recovery: MaxToCodeRecovery =
        recover_maxtocode_bodies(bytes).unwrap_or_else(|_| MaxToCodeRecovery::empty());
    dbg_kv("maxtocode-wall", || {
        format!(
            "zero_rva_methods={} method_total={} protected_rids={} section={} bodies_recovered={}/{} wall={}",
            recovery.zero_rva_methods,
            recovery.method_total,
            recovery.protected_method_rids.len(),
            recovery.section_name.as_deref().unwrap_or("none"),
            recovery.bodies_recovered,
            recovery.bodies_total,
            match recovery.key_origin {
                MaxKeyOrigin::None => "not-maxtocode",
                MaxKeyOrigin::NativeStubWall => "native-jit-hook-loader",
            }
        )
    });
    report.recovered_decoders = recovery.bodies_recovered;
    report.notes.push(format_recovery_note(&recovery));
    if let Some(surface) = surface_native_stub(bytes, MAXTOCODE_SECTION_NAMES) {
        report.notes.push(format!(
            "MaxToCode native surfacing: disassembled the native loader section {} at \
             rva=0x{:x} (file_off=0x{:x}, {} bytes) over a {}-byte window, {} instruction(s) \
             decoded (clean={}). This is the unmanaged JIT-hooked loader that restores the \
             encrypted bodies at runtime; it is surfaced as native machine code, the managed \
             bodies stay walled.",
            surface.section_name,
            surface.section_rva,
            surface.section_file_offset,
            surface.section_size,
            surface.disasm_window_bytes,
            surface.instructions_decoded,
            surface.decode_clean,
        ));
        report.native_surface = Some(surface);
    }
    Ok(report)
}

fn format_recovery_note(recovery: &MaxToCodeRecovery) -> String {
    let section: String = match (&recovery.section_name, recovery.section_size) {
        (Some(name), Some(size)) => format!(
            "encrypted section {name} size={size} (opaque ciphertext, framing not statically known)"
        ),
        _ => "no MaxToCode encrypted section located".to_string(),
    };
    let wall: &str = match recovery.key_origin {
        MaxKeyOrigin::None => "no zero-RVA managed methods (assembly not MaxToCode-encrypted)",
        MaxKeyOrigin::NativeStubWall => {
            "NATIVE-KEY WALL: per-method key is computed inside the unmanaged JIT-hooked loader DLL, \
             so it is absent from the static metadata"
        }
    };
    format!(
        "MaxToCode static recovery: zero_rva_methods={} method_total={} protected-rids={} \
         {section} bodies_recovered={}/{} ({wall})",
        recovery.zero_rva_methods,
        recovery.method_total,
        recovery.protected_method_rids.len(),
        recovery.bodies_recovered,
        recovery.bodies_total,
    )
}
