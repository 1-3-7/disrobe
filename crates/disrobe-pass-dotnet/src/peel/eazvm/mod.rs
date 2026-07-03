pub mod disasm;
pub mod dispatch;
pub mod grade;
pub mod lift;
pub mod names;
pub mod opcodes;
pub mod resource;
pub mod stream;

use crate::metadata::{
    MetadataRoot, StreamHeader, parse_metadata_root, parse_table_stream, read_strings_heap,
};
use crate::model::{AssemblyModel, Resolver};
use crate::pe::{ClrHeader, DataDirectory, PeImage, parse, parse_clr_header};
use crate::tables::{Tables, parse_tables};

use disasm::{VirtualInstr, decode_stream};
use dispatch::{OpcodeMap, is_vm_stub, recover_opcode_map, stub_position_string};
use lift::{LiftedBody, lift};
use resource::{decrypt_position_string, decrypt_region};
use stream::{EazMethodInfo, parse_method_info};

#[derive(Debug, Clone)]
pub struct EazVmDetection {
    pub embedded_resource_present: bool,
    pub dispatch_table_present: bool,
    pub identified_opcodes: u32,
    pub stub_count: u32,
}

#[derive(Debug, Clone)]
pub struct EazVmMethod {
    pub name: String,
    pub metadata_token: u32,
    pub position: i64,
    pub info: EazMethodInfo,
    pub lifted: LiftedBody,
}

#[derive(Debug, Clone)]
pub struct EazVmRecovery {
    pub detection: EazVmDetection,
    pub resource_key: i32,
    pub methods: Vec<EazVmMethod>,
    pub undecoded: Vec<String>,
    pub undecoded_count: usize,
    pub first_failure: Option<EazVmDecodeFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EazVmDecodeFailure {
    pub method: String,
    pub reason: EazVmFailureReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EazVmFailureReason {
    NoPositionString,
    PositionDecryptFailed,
    RegionDecodeFailed,
}

impl EazVmFailureReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoPositionString => "no encrypted position string on the stub",
            Self::PositionDecryptFailed => {
                "position-key decrypt failed for every candidate stub constant"
            }
            Self::RegionDecodeFailed => "resource region decrypt, parse, or lift failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EazVmError {
    NotDotNet,
    NoResource,
    NoDispatchTable,
    NoStubs,
}

const RESOURCE_NAME: &str = "EazVirtualizedStream";

fn parse_image(image: &[u8]) -> Option<(PeImage, ClrHeader, MetadataRoot)> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    Some((pe, clr, root))
}

fn manifest_resource_offset(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
    name: &str,
) -> Option<u32> {
    let metadata: &[u8] = pe
        .slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
        .ok()?;
    let table_header: StreamHeader = *root.streams.get("#~").or_else(|| root.streams.get("#-"))?;
    let strings_header: StreamHeader = *root.streams.get("#Strings")?;
    let tables: Tables = parse_tables(metadata, table_header).ok()?;
    let strings: std::collections::BTreeMap<u32, String> =
        read_strings_heap(metadata, strings_header);
    for row in &tables.manifest_resources {
        let row_name: &str = strings.get(&row.name).map_or("", String::as_str);
        if row_name == name {
            return Some(row.offset);
        }
    }
    let _ = parse_table_stream;
    None
}

fn read_embedded_resource(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
) -> Option<Vec<u8>> {
    let dir: DataDirectory = clr.resources;
    if dir.rva == 0 || dir.size == 0 {
        return None;
    }
    let offset: u32 = manifest_resource_offset(image, pe, clr, root, RESOURCE_NAME)?;
    let base: usize = pe.rva_to_offset(dir.rva.checked_add(offset)?)?;
    let len_bytes: &[u8] = image.get(base..base.checked_add(4)?)?;
    let len: usize =
        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let start: usize = base.checked_add(4)?;
    image
        .get(start..start.checked_add(len)?)
        .map(<[u8]>::to_vec)
}

#[must_use]
pub fn detect(image: &[u8]) -> EazVmDetection {
    let Some((pe, clr, root)) = parse_image(image) else {
        return EazVmDetection {
            embedded_resource_present: false,
            dispatch_table_present: false,
            identified_opcodes: 0,
            stub_count: 0,
        };
    };
    let resolver: Option<Resolver> = Resolver::build(image, &pe, &clr, &root).ok();
    let resource_present: bool = read_embedded_resource(image, &pe, &clr, &root).is_some();
    let map: Option<OpcodeMap> = recover_opcode_map(image, &pe, &clr, &root).ok();
    let identified: u32 = map.as_ref().map_or(0, |m: &OpcodeMap| {
        u32::try_from(m.len()).unwrap_or(u32::MAX)
    });
    let stub_count: u32 = resolver.as_ref().map_or(0, |r: &Resolver| {
        let model: AssemblyModel = r.model();
        let mut count: u32 = 0;
        for ty in &model.types {
            for method in &ty.methods {
                if is_vm_stub(image, &pe, ty, method) {
                    count += 1;
                }
            }
        }
        count
    });
    EazVmDetection {
        embedded_resource_present: resource_present,
        dispatch_table_present: map.is_some(),
        identified_opcodes: identified,
        stub_count,
    }
}

pub fn devirtualize(image: &[u8]) -> Result<EazVmRecovery, EazVmError> {
    let (pe, clr, root): (PeImage, ClrHeader, MetadataRoot) =
        parse_image(image).ok_or(EazVmError::NotDotNet)?;
    let resolver: Resolver =
        Resolver::build(image, &pe, &clr, &root).map_err(|_| EazVmError::NotDotNet)?;
    let model: AssemblyModel = resolver.model();

    let encrypted_resource: Vec<u8> =
        read_embedded_resource(image, &pe, &clr, &root).ok_or(EazVmError::NoResource)?;
    let map: OpcodeMap =
        recover_opcode_map(image, &pe, &clr, &root).map_err(|_| EazVmError::NoDispatchTable)?;
    let resource_key: i32 = recover_resource_key(image, &pe, &model);

    let position_keys: Vec<i32> = position_key_candidates(image, &pe, &model);

    let mut methods: Vec<EazVmMethod> = Vec::new();
    let mut undecoded: Vec<String> = Vec::new();
    let mut first_failure: Option<EazVmDecodeFailure> = None;

    for ty in &model.types {
        for method in &ty.methods {
            if !is_vm_stub(image, &pe, ty, method) {
                continue;
            }
            match decode_stub(
                image,
                &pe,
                method,
                &resolver,
                &encrypted_resource,
                resource_key,
                &position_keys,
                &map,
            ) {
                Ok(decoded) => methods.push(decoded),
                Err(reason) => {
                    undecoded.push(method.name.clone());
                    if first_failure.is_none() {
                        first_failure = Some(EazVmDecodeFailure {
                            method: method.name.clone(),
                            reason,
                        });
                    }
                }
            }
        }
    }

    if methods.is_empty() && undecoded.is_empty() {
        return Err(EazVmError::NoStubs);
    }

    methods.sort_by(|a: &EazVmMethod, b: &EazVmMethod| a.name.cmp(&b.name));
    undecoded.sort();

    let detection: EazVmDetection = EazVmDetection {
        embedded_resource_present: true,
        dispatch_table_present: true,
        identified_opcodes: u32::try_from(map.len()).unwrap_or(u32::MAX),
        stub_count: u32::try_from(methods.len() + undecoded.len()).unwrap_or(u32::MAX),
    };

    let undecoded_count: usize = undecoded.len();

    Ok(EazVmRecovery {
        detection,
        resource_key,
        methods,
        undecoded,
        undecoded_count,
        first_failure,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_stub(
    image: &[u8],
    pe: &PeImage,
    method: &crate::model::MethodModel,
    resolver: &Resolver,
    encrypted_resource: &[u8],
    resource_key: i32,
    position_keys: &[i32],
    map: &OpcodeMap,
) -> Result<EazVmMethod, EazVmFailureReason> {
    let position_string: String = stub_position_string(image, pe, method, resolver)
        .ok_or(EazVmFailureReason::NoPositionString)?;

    let positions: Vec<i64> = decode_position_candidates(&position_string, position_keys);
    if positions.is_empty() {
        return Err(EazVmFailureReason::PositionDecryptFailed);
    }

    for position in positions {
        if let Some((info, lifted)) = decode_one(encrypted_resource, resource_key, position, map) {
            return Ok(EazVmMethod {
                name: method.name.clone(),
                metadata_token: method.token,
                position,
                info,
                lifted,
            });
        }
    }

    Err(EazVmFailureReason::RegionDecodeFailed)
}

#[must_use]
pub fn decode_position_candidates(position_string: &str, candidates: &[i32]) -> Vec<i64> {
    let mut positions: Vec<i64> = Vec::new();
    for key in candidates {
        if let Ok(position) = decrypt_position_string(position_string, *key)
            && position >= 0
            && !positions.contains(&position)
        {
            positions.push(position);
        }
    }
    positions
}

#[must_use]
pub fn decode_position_with_candidates(position_string: &str, candidates: &[i32]) -> Option<i64> {
    decode_position_candidates(position_string, candidates)
        .into_iter()
        .next()
}

fn decode_one(
    encrypted_resource: &[u8],
    resource_key: i32,
    position: i64,
    map: &OpcodeMap,
) -> Option<(EazMethodInfo, LiftedBody)> {
    let start: u64 = u64::try_from(position).ok()?;
    let remaining: usize = encrypted_resource
        .len()
        .checked_sub(usize::try_from(start).ok()?)?;
    let region: Vec<u8> = decrypt_region(encrypted_resource, resource_key, start, remaining)?;
    let info: EazMethodInfo = parse_method_info(&region).ok()?;
    let virtuals: Vec<VirtualInstr> = decode_stream(&info.code, map).ok()?;
    let lifted: LiftedBody = lift(&virtuals).ok()?;
    Some((info, lifted))
}

fn recover_resource_key(image: &[u8], pe: &PeImage, model: &AssemblyModel) -> i32 {
    stub_constants(image, pe, model)
        .first()
        .copied()
        .unwrap_or(0)
}

fn position_key_candidates(image: &[u8], pe: &PeImage, model: &AssemblyModel) -> Vec<i32> {
    let consts: Vec<i32> = stub_constants(image, pe, model);
    let mut ordered: Vec<i32> = Vec::with_capacity(consts.len());
    if let Some(primary) = consts.get(1).copied()
        && !ordered.contains(&primary)
    {
        ordered.push(primary);
    }
    for value in &consts {
        if !ordered.contains(value) {
            ordered.push(*value);
        }
    }
    if ordered.is_empty() {
        ordered.push(0);
    }
    ordered
}

fn stub_constants(image: &[u8], pe: &PeImage, model: &AssemblyModel) -> Vec<i32> {
    use crate::cil::{MethodBody, parse_method_body};
    use dispatch::ldc_i4_value;
    for ty in &model.types {
        for method in &ty.methods {
            if !is_vm_stub(image, pe, ty, method) {
                continue;
            }
            let Some(off): Option<usize> = pe.rva_to_offset(method.rva) else {
                continue;
            };
            let Some(slice): Option<&[u8]> = image.get(off..) else {
                continue;
            };
            let Ok(body): Result<MethodBody, _> = parse_method_body(slice) else {
                continue;
            };
            let consts: Vec<i32> = body.instructions.iter().filter_map(ldc_i4_value).collect();
            if consts.len() >= 2 {
                return consts;
            }
        }
    }
    Vec::new()
}

#[must_use]
pub fn lookup_method<'a>(recovery: &'a EazVmRecovery, name: &str) -> Option<&'a EazVmMethod> {
    recovery
        .methods
        .iter()
        .find(|m: &&EazVmMethod| m.name == name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn eazvm_image() -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/eazvm/EazSample.eazvm.dll");
        std::fs::read(path).unwrap()
    }

    #[test]
    fn detects_eazvm_structure() {
        let image: Vec<u8> = eazvm_image();
        let d: EazVmDetection = detect(&image);
        assert!(
            d.embedded_resource_present,
            "eazvm sample must carry the embedded virtualized stream"
        );
        assert!(
            d.dispatch_table_present,
            "the virtual->CIL dispatch table must be recoverable"
        );
        assert_eq!(d.identified_opcodes, 48, "all 48 handlers identified");
        assert_eq!(d.stub_count, 5, "five methods were virtualized");
    }

    #[test]
    fn devirtualizes_all_methods() {
        let image: Vec<u8> = eazvm_image();
        let recovery: EazVmRecovery = devirtualize(&image).expect("devirtualize");
        assert!(
            recovery.undecoded.is_empty(),
            "no method should fail to decode; undecoded={:?}",
            recovery.undecoded
        );
        assert_eq!(recovery.methods.len(), 5);
        for expected in ["Add", "Classify", "Max3", "Poly", "SumTo"] {
            let m: &EazVmMethod =
                lookup_method(&recovery, expected).expect("recovered method present");
            assert!(
                !m.lifted.instrs.is_empty(),
                "method {expected} lifted to no instructions"
            );
        }
    }

    #[test]
    fn recovered_method_names_come_from_vm_body() {
        let image: Vec<u8> = eazvm_image();
        let recovery: EazVmRecovery = devirtualize(&image).expect("devirtualize");
        for m in &recovery.methods {
            assert_eq!(
                m.name, m.info.name,
                "the by-name VM body identifier must match the recovered stub method name"
            );
        }
    }

    #[test]
    fn writes_recovered_cil_artifact() {
        use std::fmt::Write as _;
        let image: Vec<u8> = eazvm_image();
        let recovery: EazVmRecovery = devirtualize(&image).expect("devirtualize");
        let mut out: String = String::new();
        for m in &recovery.methods {
            let ret: &str = if m.info.returns_void { "void" } else { "i4" };
            writeln!(
                out,
                "method {} params={} locals={} ret={}",
                m.name, m.info.param_count, m.info.local_count, ret
            )
            .unwrap();
            for line in m.lifted.render() {
                writeln!(out, "{line}").unwrap();
            }
            writeln!(out, "end").unwrap();
        }
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/eazvm/EazSample.recovered.cil");
        std::fs::write(&path, out).expect("write recovered cil artifact");
    }

    #[test]
    fn full_decode_surfaces_zero_undecoded_and_no_failure() {
        let image: Vec<u8> = eazvm_image();
        let recovery: EazVmRecovery = devirtualize(&image).expect("devirtualize");
        assert_eq!(
            recovery.undecoded_count, 0,
            "every stub decodes; undecoded={:?}",
            recovery.undecoded
        );
        assert_eq!(
            recovery.undecoded_count,
            recovery.undecoded.len(),
            "the surfaced count must track the undecoded list"
        );
        assert!(
            recovery.first_failure.is_none(),
            "a fully-decoded sample must carry no first-failure reason; got {:?}",
            recovery.first_failure
        );
    }

    #[test]
    fn failure_reasons_render_human_strings() {
        assert_eq!(
            EazVmFailureReason::NoPositionString.as_str(),
            "no encrypted position string on the stub"
        );
        assert!(
            EazVmFailureReason::PositionDecryptFailed
                .as_str()
                .contains("candidate")
        );
        assert!(
            EazVmFailureReason::RegionDecodeFailed
                .as_str()
                .contains("region")
        );
    }

    fn encode_position_string(position: i64, key2: i32) -> String {
        use resource::crypt_byte;
        let raw: [u8; 8] = position.to_be_bytes();
        let mut enc: [u8; 8] = [0u8; 8];
        for (i, slot) in enc.iter_mut().enumerate() {
            *slot = crypt_byte(key2, i as u64, raw[i]);
        }
        base85_encode(&enc)
    }

    fn base85_encode(data: &[u8]) -> String {
        let mut s: String = String::new();
        let full: usize = data.len() / 4;
        for g in 0..full {
            let mut num: u32 = 0;
            for j in 0..4 {
                num = (num << 8) | u32::from(data[g * 4 + j]);
            }
            emit_group(&mut s, num, 5);
        }
        let rem: usize = data.len() % 4;
        if rem > 0 {
            let mut num: u32 = 0;
            for j in 0..4 {
                num <<= 8;
                if j < rem {
                    num |= u32::from(data[full * 4 + j]);
                }
            }
            emit_group(&mut s, num, rem + 1);
        }
        s
    }

    fn emit_group(s: &mut String, mut num: u32, count: usize) {
        let mut chars: [char; 5] = ['!'; 5];
        for slot in chars.iter_mut().rev() {
            *slot = char::from_u32(u32::from(b'!') + (num % 85)).unwrap_or('!');
            num /= 85;
        }
        for ch in chars.iter().take(count) {
            s.push(*ch);
        }
    }

    #[test]
    fn alternative_position_key_decodes_what_the_first_key_misses() {
        let correct_key2: i32 = 336_077_329;
        let wrong_key2: i32 = 0x0BAD_F00D;
        let position: i64 = 244;
        let position_string: String = encode_position_string(position, correct_key2);

        let single_key_only: Vec<i64> = decode_position_candidates(&position_string, &[wrong_key2]);
        assert!(
            !single_key_only.contains(&position),
            "the wrong first-position key must not yield the true position; got {single_key_only:?}"
        );

        let scanned: Vec<i64> =
            decode_position_candidates(&position_string, &[wrong_key2, correct_key2]);
        assert!(
            scanned.contains(&position),
            "scanning beyond the first ldc.i4 must recover the position the first key missed; \
             got {scanned:?}"
        );
        assert_eq!(
            scanned.last().copied(),
            Some(position),
            "the correct key is tried after the wrong one, so the true position lands last"
        );
    }

    #[test]
    fn candidate_scan_collects_every_distinct_valid_position() {
        let key_a: i32 = 336_077_329;
        let key_b: i32 = 12_345_678;
        let pos_a: i64 = 100;
        let ps: String = encode_position_string(pos_a, key_a);

        let positions: Vec<i64> = decode_position_candidates(&ps, &[key_a, key_a, key_b]);
        assert!(
            positions.contains(&pos_a),
            "the correct key must yield the real position; got {positions:?}"
        );
        let count_a: usize = positions.iter().filter(|p: &&i64| **p == pos_a).count();
        assert_eq!(count_a, 1, "duplicate keys must not duplicate a position");
    }
}
