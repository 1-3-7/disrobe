use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::error::Result;
use crate::metadata::MetadataRoot;
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage};

#[derive(Debug, Clone)]
pub struct VmStub {
    pub export_id: u32,
    pub metadata_token: u32,
    pub method_name: String,
    pub param_count: u32,
}

pub fn find_vm_stubs(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
) -> Result<Vec<VmStub>> {
    let resolver: Resolver = Resolver::build(image, pe, clr, root)?;
    let model: AssemblyModel = resolver.model();
    let mut stubs: Vec<VmStub> = Vec::new();

    for ty in &model.types {
        for method in &ty.methods {
            if let Some(stub) = classify_stub(image, pe, ty, method) {
                stubs.push(stub);
            }
        }
    }

    stubs.sort_by_key(|s: &VmStub| s.export_id);
    stubs.dedup_by_key(|s: &mut VmStub| s.export_id);
    Ok(stubs)
}

fn classify_stub(
    image: &[u8],
    pe: &PeImage,
    ty: &TypeModel,
    method: &MethodModel,
) -> Option<VmStub> {
    if method.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(method.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    let export_id: u32 = stub_export_id(&body.instructions)?;
    let param_count: u32 = u32::try_from(method.signature.params.len()).unwrap_or(0);
    let full_name: String = format!("{}::{}", ty.full_name, method.name);
    let short_name: String = method.name.clone();
    let _ = full_name;
    Some(VmStub {
        export_id,
        metadata_token: method.token,
        method_name: short_name,
        param_count,
    })
}

fn stub_export_id(instrs: &[Instruction]) -> Option<u32> {
    let mut ldtoken_index: Option<usize> = None;
    let mut has_newarr: bool = false;
    let mut has_call: bool = false;

    for (index, ins) in instrs.iter().enumerate() {
        match ins.name.as_str() {
            "ldtoken" if ldtoken_index.is_none() => ldtoken_index = Some(index),
            "newarr" => has_newarr = true,
            "call" => has_call = true,
            _ => {}
        }
    }

    let start: usize = ldtoken_index?;
    if !has_newarr || !has_call {
        return None;
    }

    for ins in instrs.iter().skip(start + 1) {
        if let Some(value) = ldc_i4_value(ins) {
            return u32::try_from(value).ok();
        }
        if ins.name == "newarr" {
            break;
        }
    }
    None
}

fn ldc_i4_value(ins: &Instruction) -> Option<i32> {
    match ins.name.as_str() {
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.m1" => Some(-1),
        "ldc.i4.s" | "ldc.i4" => match ins.operand {
            OperandValue::I32(v) => Some(v),
            OperandValue::U8(v) => Some(i32::from(v)),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pe::{parse, parse_clr_header};

    fn virtualized_exe() -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koivm.exe");
        std::fs::read(path).unwrap()
    }

    #[test]
    fn finds_six_stubs_with_ids_two_to_seven() {
        let image: Vec<u8> = virtualized_exe();
        let pe: PeImage = parse(&image).unwrap();
        let clr: ClrHeader = parse_clr_header(&image, &pe).unwrap();
        let root: MetadataRoot = crate::metadata::parse_metadata_root(&image, &pe, &clr).unwrap();
        let stubs: Vec<VmStub> = find_vm_stubs(&image, &pe, &clr, &root).unwrap();
        assert_eq!(stubs.len(), 6, "expected six VM stubs; got {stubs:?}");
        let ids: Vec<u32> = stubs.iter().map(|s: &VmStub| s.export_id).collect();
        assert_eq!(ids, vec![2, 3, 4, 5, 6, 7], "stub export ids");
    }

    #[test]
    fn stub_names_and_param_counts_match() {
        let image: Vec<u8> = virtualized_exe();
        let pe: PeImage = parse(&image).unwrap();
        let clr: ClrHeader = parse_clr_header(&image, &pe).unwrap();
        let root: MetadataRoot = crate::metadata::parse_metadata_root(&image, &pe, &clr).unwrap();
        let stubs: Vec<VmStub> = find_vm_stubs(&image, &pe, &clr, &root).unwrap();
        let add: &VmStub = stubs
            .iter()
            .find(|s: &&VmStub| s.method_name == "Add")
            .unwrap();
        assert_eq!(add.param_count, 2, "Add takes two parameters");
        let max3: &VmStub = stubs
            .iter()
            .find(|s: &&VmStub| s.method_name == "Max3")
            .unwrap();
        assert_eq!(max3.param_count, 3, "Max3 takes three parameters");
    }
}
