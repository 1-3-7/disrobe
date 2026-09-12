pub mod blocks;
pub mod decrypt;
pub mod grade;
pub mod interp;
pub mod predicate;
pub mod rebuild;

use serde::{Deserialize, Serialize};

use crate::cil::{MethodBody, parse_method_body};
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

use blocks::BlockGraph;
use predicate::PredicateOracle;
use rebuild::{Edge, Recovered};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeflattenSummary {
    pub flattened_methods: u32,
    pub deflattened_methods: u32,
    pub methods: Vec<MethodDeflatten>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDeflatten {
    pub method_token: u32,
    pub method_name: String,
    pub case_count: u32,
    pub recovered_blocks: u32,
    pub recovered_edges: u32,
    pub conditional_edges: u32,
    pub unresolved_blocks: u32,
    pub fully_resolved: bool,
}

#[derive(Debug, Clone)]
pub struct MethodRecovery {
    pub token: u32,
    pub name: String,
    pub graph: BlockGraph,
    pub recovered: Recovered,
}

#[must_use]
pub fn is_flattened(body: &MethodBody) -> bool {
    blocks::find_dispatcher(body).is_some()
}

#[must_use]
pub fn deflatten_body(body: &MethodBody) -> Option<(BlockGraph, Recovered)> {
    let graph: BlockGraph = blocks::build(body)?;
    let recovered: Recovered = rebuild::deflatten(&graph, body);
    Some((graph, recovered))
}

#[must_use]
pub fn deflatten_body_with_oracle(
    body: &MethodBody,
    oracle: &dyn interp::KeyOracle,
) -> Option<(BlockGraph, Recovered)> {
    let graph: BlockGraph = blocks::build(body)?;
    let recovered: Recovered = rebuild::deflatten_with_oracle(&graph, body, oracle);
    Some((graph, recovered))
}

#[must_use]
pub fn count_edges(recovered: &Recovered) -> (u32, u32) {
    let mut total: u32 = 0;
    let mut conditional: u32 = 0;
    for b in &recovered.blocks {
        match &b.edge {
            Edge::Goto(_) => total += 1,
            Edge::Cond { .. } => {
                total += 2;
                conditional += 1;
            }
            Edge::Return => {}
        }
    }
    (total, conditional)
}

pub fn analyze(image: &[u8]) -> Option<DeflattenSummary> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).ok()?;
    let model: AssemblyModel = resolver.model();
    let oracle: PredicateOracle = PredicateOracle::build(image, &pe, &model);

    let mut methods: Vec<MethodDeflatten> = Vec::new();
    let mut flattened: u32 = 0;
    let mut deflattened: u32 = 0;
    for ty in &model.types {
        for m in &ty.methods {
            let Some(rec): Option<MethodRecovery> = recover_method_with(image, &pe, ty, m, &oracle)
            else {
                continue;
            };
            flattened += 1;
            let (edges, conditional): (u32, u32) = count_edges(&rec.recovered);
            let unresolved: u32 = u32::try_from(rec.recovered.unresolved.len()).unwrap_or(u32::MAX);
            let fully_resolved: bool = rec.recovered.unresolved.is_empty();
            if fully_resolved {
                deflattened += 1;
            }
            methods.push(MethodDeflatten {
                method_token: rec.token,
                method_name: rec.name,
                case_count: rec.graph.dispatcher.case_count,
                recovered_blocks: u32::try_from(rec.recovered.blocks.len()).unwrap_or(u32::MAX),
                recovered_edges: edges,
                conditional_edges: conditional,
                unresolved_blocks: unresolved,
                fully_resolved,
            });
        }
    }
    if flattened == 0 {
        return None;
    }
    methods.sort_by_key(|m: &MethodDeflatten| m.method_token);
    Some(DeflattenSummary {
        flattened_methods: flattened,
        deflattened_methods: deflattened,
        methods,
    })
}

#[must_use]
pub fn recover_method(
    image: &[u8],
    pe: &PeImage,
    ty: &TypeModel,
    m: &MethodModel,
) -> Option<MethodRecovery> {
    if m.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(m.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    if !is_flattened(&body) {
        return None;
    }
    let clr: ClrHeader = parse_clr_header(image, pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, pe, &clr).ok()?;
    let resolver: Resolver = Resolver::build(image, pe, &clr, &root).ok()?;
    let model: AssemblyModel = resolver.model();
    let oracle: PredicateOracle = PredicateOracle::build(image, pe, &model);
    recover_method_with(image, pe, ty, m, &oracle)
}

#[must_use]
fn recover_method_with(
    image: &[u8],
    pe: &PeImage,
    ty: &TypeModel,
    m: &MethodModel,
    oracle: &PredicateOracle,
) -> Option<MethodRecovery> {
    if m.rva == 0 {
        return None;
    }
    let off: usize = pe.rva_to_offset(m.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    if !is_flattened(&body) {
        return None;
    }
    let (graph, recovered): (BlockGraph, Recovered) = deflatten_body_with_oracle(&body, oracle)?;
    let name: String = format!("{}::{}", ty.full_name, m.name);
    Some(MethodRecovery {
        token: m.token,
        name,
        graph,
        recovered,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn clean_sample_has_no_flattened_methods() {
        let image: Vec<u8> = load("../../corpus/dotnet/cff/CffSample.clean.exe");
        assert!(
            analyze(&image).is_none(),
            "the unobfuscated baseline must carry no switch dispatcher"
        );
    }

    #[test]
    fn ctrlflow_sample_is_detected_as_flattened() {
        let image: Vec<u8> = load("../../corpus/dotnet/cff/CffSample.ctrlflow.exe");
        let summary: DeflattenSummary =
            analyze(&image).expect("control-flow-flattened methods must be detected");
        assert!(
            summary.flattened_methods >= 4,
            "ConfuserEx flattened several methods; found {}",
            summary.flattened_methods
        );
    }
}
