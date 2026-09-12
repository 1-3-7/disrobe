#![allow(clippy::doc_markdown)]
use crate::debug::dbg_kv;
use crate::error::Result;
use crate::peel::ilprotector_bodies::{IlProtectorRecovery, KeyOrigin, recover_ilprotector_bodies};
use crate::peel::native_surface::surface_native_stub;
use crate::peel::{PeelReport, detect_only_native};
use crate::protectors::Protector;

const WATERMARKS: &[&str] = &["Protect32.dll", "Protect64.dll", "ILProtector"];

const ILP_NATIVE_SECTIONS: &[&str] = &[".taz", ".text0", ".ilp"];

const BASE_RATIONALE: &str = "ILProtector replaces every protected method body with an Invoke-stub (ldsfld <delegate>; \
     ldc.i4 <method-id>; call Invoke; ret) and stores the ciphertext for each body in an embedded \
     managed resource reached through the CLI resources directory. The plaintext IL is produced only \
     by invoking the assembly's own runtime decrypt delegate (the path any dynamic unpacker takes by \
     loading and dynamically running the protected assembly), so it is not present in the static \
     file; static recovery extends to the invoke-stub enumeration and the located encrypted-body \
     resource (offset/size/sha), while the bodies stay walled on the runtime decrypt delegate.";

pub fn peel_ilprotector(bytes: &[u8]) -> Result<PeelReport> {
    let mut report: PeelReport =
        detect_only_native(Protector::Ilprotector, bytes, WATERMARKS, BASE_RATIONALE)?;
    let recovery: IlProtectorRecovery =
        recover_ilprotector_bodies(bytes).unwrap_or_else(|_| IlProtectorRecovery::empty());
    dbg_kv("ilprotector-wall", || {
        format!(
            "invoke_stubs={} protected_ids={} resource@{} bodies_recovered={}/{} wall={}",
            recovery.stub_methods_total,
            recovery.protected_method_ids.len(),
            recovery
                .resource_offset
                .map_or_else(|| "none".to_string(), |o: u32| format!("0x{o:x}")),
            recovery.bodies_recovered,
            recovery.bodies_total,
            match recovery.key_origin {
                KeyOrigin::None => "not-ilprotector",
                KeyOrigin::NativeRuntimeWall => "runtime-decrypt-delegate",
            }
        )
    });
    report.recovered_decoders = recovery.bodies_recovered;
    report.notes.push(format_recovery_note(&recovery));
    if let Some(surface) = surface_native_stub(bytes, ILP_NATIVE_SECTIONS) {
        report.notes.push(format!(
            "ILProtector native surfacing: disassembled the native loader stub in section {} at \
             rva=0x{:x} (file_off=0x{:x}, {} bytes) over a {}-byte window, {} instruction(s) \
             decoded (clean={}). This is the unmanaged Protect32/Protect64.dll support code that \
             guards the runtime decrypt path; it is surfaced as native machine code, the managed \
             bodies stay walled on the runtime delegate.",
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

fn format_recovery_note(recovery: &IlProtectorRecovery) -> String {
    let resource: String = match (recovery.resource_offset, recovery.resource_size) {
        (Some(off), Some(size)) => {
            format!(
                "encrypted-body resource at file offset 0x{off:x} size={size} (opaque ciphertext, \
                 framing not statically known)"
            )
        }
        _ => "no embedded encrypted-body resource located".to_string(),
    };
    let wall: &str = match recovery.key_origin {
        KeyOrigin::None => "no Invoke-stubs found (assembly not ILProtector-encrypted)",
        KeyOrigin::NativeRuntimeWall => {
            "RUNTIME-DELEGATE WALL: the plaintext IL is produced only by invoking the assembly's own \
             runtime decrypt delegate, so it is absent from the static file"
        }
    };
    format!(
        "ILProtector static recovery: invoke-stubs={} protected-method-ids={} {resource} \
         bodies_recovered={}/{} ({wall})",
        recovery.stub_methods_total,
        recovery.protected_method_ids.len(),
        recovery.bodies_recovered,
        recovery.bodies_total,
    )
}
