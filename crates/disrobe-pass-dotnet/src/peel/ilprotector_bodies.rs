#![allow(clippy::doc_markdown)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::error::Result;
use crate::metadata::{MetadataRoot, StreamHeader, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::tables::{ManifestResourceRow, MethodDefRow, Tables, parse_tables};

pub const ILPROTECTOR_RESOURCE_NAMES: &[&str] = &["Protect", "Protect.Net", "ProtectData"];

pub const ILPROTECTOR_NATIVE_HELPERS: &[&str] = &["Protect32.dll", "Protect64.dll"];

pub const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;

pub const ILP_INVOKE_INDEX_MAX: u32 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IlProtectorRecovery {
    pub stub_methods_total: u32,
    pub stub_methods_classified: u32,
    pub protected_method_ids: Vec<u32>,
    pub resource_located: bool,
    pub resource_offset: Option<u32>,
    pub resource_size: Option<u32>,
    pub resource_sha256: Option<[u8; 32]>,
    pub bodies_recovered: u32,
    pub bodies_total: u32,
    pub recovered_bodies: Vec<RecoveredBody>,
    pub key_origin: KeyOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBody {
    pub method_id: u32,
    pub il: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyOrigin {
    None,
    NativeRuntimeWall,
}

impl IlProtectorRecovery {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            stub_methods_total: 0,
            stub_methods_classified: 0,
            protected_method_ids: Vec::new(),
            resource_located: false,
            resource_offset: None,
            resource_size: None,
            resource_sha256: None,
            bodies_recovered: 0,
            bodies_total: 0,
            recovered_bodies: Vec::new(),
            key_origin: KeyOrigin::None,
        }
    }

    #[must_use]
    pub const fn recovery_ratio(&self) -> Option<(u32, u32)> {
        if self.bodies_total == 0 {
            None
        } else {
            Some((self.bodies_recovered, self.bodies_total))
        }
    }
}

pub fn recover_ilprotector_bodies(image: &[u8]) -> Result<IlProtectorRecovery> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let table_header: &StreamHeader =
        match root.streams.get("#~").or_else(|| root.streams.get("#-")) {
            Some(h) => h,
            None => return Ok(IlProtectorRecovery::empty()),
        };
    let tables: Tables = parse_tables(metadata_slice, *table_header)?;

    let strings_map: std::collections::BTreeMap<u32, String> = root
        .streams
        .get("#Strings")
        .map(|h: &StreamHeader| crate::metadata::read_strings_heap(metadata_slice, *h))
        .unwrap_or_default();

    let mut recovery: IlProtectorRecovery = IlProtectorRecovery::empty();

    let stub_ids: Vec<u32> = classify_stub_bodies(image, &pe, &tables.methods);
    recovery.stub_methods_total = u32::try_from(stub_ids.len()).unwrap_or(u32::MAX);
    recovery.stub_methods_classified = recovery.stub_methods_total;
    recovery.protected_method_ids = stub_ids;

    let resource: Option<EmbeddedResource> =
        locate_embedded_resource(image, &pe, &clr, &tables, &strings_map);
    if let Some(r) = resource {
        recovery.resource_located = true;
        recovery.resource_offset = Some(r.file_offset_u32());
        recovery.resource_size = Some(r.size_u32());
        recovery.resource_sha256 = Some(sha256(&r.bytes));
    }

    recovery.bodies_total = recovery.stub_methods_classified;
    if recovery.bodies_total == 0 {
        recovery.key_origin = KeyOrigin::None;
        return Ok(recovery);
    }

    recovery.key_origin = KeyOrigin::NativeRuntimeWall;
    Ok(recovery)
}

fn classify_stub_bodies(image: &[u8], pe: &PeImage, methods: &[MethodDefRow]) -> Vec<u32> {
    let mut ids: Vec<u32> = Vec::new();
    for method in methods {
        if method.rva == 0 {
            continue;
        }
        let Some(off): Option<usize> = pe.rva_to_offset(method.rva) else {
            continue;
        };
        if off >= image.len() {
            continue;
        }
        let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
            continue;
        };
        if let Some(index) = invoke_stub_index(&body) {
            ids.push(index);
        }
    }
    ids.sort_unstable();
    ids
}

#[must_use]
pub fn invoke_stub_index(body: &MethodBody) -> Option<u32> {
    let instrs: &[Instruction] = &body.instructions;
    if instrs.len() < 3 {
        return None;
    }
    let loads_field: bool = matches!(instrs[0].name.as_str(), "ldsfld" | "ldfld");
    if !loads_field {
        return None;
    }
    let index: u32 = ldc_i4_value(&instrs[1])?;
    if index > ILP_INVOKE_INDEX_MAX {
        return None;
    }
    let has_invoke: bool = instrs
        .iter()
        .any(|i: &Instruction| matches!(i.name.as_str(), "call" | "callvirt"));
    let returns: bool = instrs
        .iter()
        .any(|i: &Instruction| matches!(i.name.as_str(), "ret" | "throw"));
    if has_invoke && returns {
        Some(index)
    } else {
        None
    }
}

fn ldc_i4_value(instr: &Instruction) -> Option<u32> {
    match (&instr.name[..], &instr.operand) {
        ("ldc.i4", OperandValue::I32(v)) => Some(*v as u32),
        ("ldc.i4.s", OperandValue::U8(v)) => Some(i32::from(*v as i8) as u32),
        (name, OperandValue::None) => ldc_i4_short(name),
        _ => None,
    }
}

fn ldc_i4_short(name: &str) -> Option<u32> {
    Some(match name {
        "ldc.i4.0" => 0,
        "ldc.i4.1" => 1,
        "ldc.i4.2" => 2,
        "ldc.i4.3" => 3,
        "ldc.i4.4" => 4,
        "ldc.i4.5" => 5,
        "ldc.i4.6" => 6,
        "ldc.i4.7" => 7,
        "ldc.i4.8" => 8,
        _ => return None,
    })
}

#[derive(Debug, Clone)]
struct EmbeddedResource {
    file_offset: usize,
    bytes: Vec<u8>,
}

impl EmbeddedResource {
    fn file_offset_u32(&self) -> u32 {
        u32::try_from(self.file_offset).unwrap_or(u32::MAX)
    }

    fn size_u32(&self) -> u32 {
        u32::try_from(self.bytes.len()).unwrap_or(u32::MAX)
    }
}

fn locate_embedded_resource(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    tables: &Tables,
    strings: &std::collections::BTreeMap<u32, String>,
) -> Option<EmbeddedResource> {
    if clr.resources.rva == 0 || clr.resources.size == 0 {
        return None;
    }
    let resources_base: usize = pe.rva_to_offset(clr.resources.rva)?;
    let row: &ManifestResourceRow = tables.manifest_resources.iter().find(|r| {
        r.implementation.is_none()
            && strings
                .get(&r.name)
                .is_some_and(|n: &String| is_ilprotector_resource_name(n))
    })?;
    let entry_off: usize = resources_base.checked_add(row.offset as usize)?;
    if entry_off.checked_add(4)? > image.len() {
        return None;
    }
    let len: usize = u32::from_le_bytes([
        image[entry_off],
        image[entry_off + 1],
        image[entry_off + 2],
        image[entry_off + 3],
    ]) as usize;
    if len == 0 || len > MAX_RESOURCE_BYTES {
        return None;
    }
    let data_off: usize = entry_off.checked_add(4)?;
    if data_off.checked_add(len)? > image.len() {
        return None;
    }
    Some(EmbeddedResource {
        file_offset: data_off,
        bytes: image[data_off..data_off + len].to_vec(),
    })
}

#[must_use]
pub fn is_ilprotector_resource_name(name: &str) -> bool {
    ILPROTECTOR_RESOURCE_NAMES.contains(&name)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::generic_array::GenericArray<u8, _> = hasher.finalize();
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn invoke_stub_index_matches_ldsfld_ldc_call_ret() {
        let mut code: Vec<u8> = vec![0x7E];
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x1F);
        code.push(0x2A);
        code.push(0x28);
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        assert_eq!(invoke_stub_index(&body), Some(42));
    }

    #[test]
    fn invoke_stub_rejects_plain_arithmetic_body() {
        let body: MethodBody = body_from(&[0x02, 0x1F, 0x5A, 0x61, 0x2A]);
        assert_eq!(invoke_stub_index(&body), None);
    }

    #[test]
    fn resource_name_matcher_accepts_real_names_only() {
        assert!(is_ilprotector_resource_name("Protect"));
        assert!(is_ilprotector_resource_name("Protect.Net"));
        assert!(!is_ilprotector_resource_name("Resources.resources"));
        assert!(!is_ilprotector_resource_name("ProtectFoo"));
    }

    #[test]
    fn empty_recovery_has_no_ratio() {
        let r: IlProtectorRecovery = IlProtectorRecovery::empty();
        assert_eq!(r.recovery_ratio(), None);
        assert_eq!(r.key_origin, KeyOrigin::None);
    }

    #[test]
    fn recover_on_clean_baseline_finds_no_stubs() {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let bytes: Vec<u8> = std::fs::read(&path).expect("fixture");
        let r: IlProtectorRecovery = recover_ilprotector_bodies(&bytes).expect("scan");
        assert_eq!(r.bodies_recovered, 0);
    }
}
