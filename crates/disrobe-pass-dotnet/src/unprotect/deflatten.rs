use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{Instruction, MethodBody};
use crate::peel::deflatten::blocks::{BlockGraph, BlockId};
use crate::peel::deflatten::interp::{
    KeyOracle, is_conditional_branch, is_terminal, is_unconditional_branch,
};
use crate::peel::deflatten::rebuild::{
    Edge, Recovered, RecoveredBlock, RecoveredInstructionBlock, recover_payload_instructions,
};
use crate::peel::deflatten::{deflatten_body_with_oracle, is_flattened};

use super::body::{AssembleError, EmitBlock, Terminator, assemble};

#[derive(Debug, Clone)]
pub(crate) enum DeflattenOutcome {
    NotFlattened,
    Rebuilt(MethodBody),
    Residual(String),
}

#[must_use]
pub(crate) fn deflatten(body: &MethodBody, oracle: &dyn KeyOracle) -> DeflattenOutcome {
    if !is_flattened(body) {
        return DeflattenOutcome::NotFlattened;
    }
    if !body.exception_clauses.is_empty() {
        return DeflattenOutcome::Residual(
            "the switch dispatcher lies inside an exception region, which this rebuild does not model"
                .to_owned(),
        );
    }
    let switches: usize = body
        .instructions
        .iter()
        .filter(|i: &&Instruction| i.name == "switch")
        .count();
    if switches != 1 {
        return DeflattenOutcome::Residual(format!(
            "{switches} switch instructions share the method, so a user switch cannot be told from the dispatcher"
        ));
    }
    let Some((graph, recovered)): Option<(BlockGraph, Recovered)> =
        deflatten_body_with_oracle(body, oracle)
    else {
        return DeflattenOutcome::Residual(
            "the dispatcher block graph could not be built".to_owned(),
        );
    };
    if !recovered.unresolved.is_empty() {
        return DeflattenOutcome::Residual(format!(
            "{} dispatcher successors could not be resolved from the switch key",
            recovered.unresolved.len()
        ));
    }
    let Some(payloads): Option<Vec<RecoveredInstructionBlock>> =
        recover_payload_instructions(&graph, body, &recovered)
    else {
        return DeflattenOutcome::Residual(
            "the recovered block payloads do not project back onto the original instructions"
                .to_owned(),
        );
    };
    let ordered: Vec<&RecoveredBlock> = layout_order(&recovered);
    let mut index_of: BTreeMap<BlockId, usize> = BTreeMap::new();
    for (index, block) in ordered.iter().enumerate() {
        index_of.insert(block.id, index);
    }
    let payload_of: BTreeMap<BlockId, &Vec<Instruction>> = payloads
        .iter()
        .map(|p: &RecoveredInstructionBlock| (p.id, &p.instructions))
        .collect();
    let resolve = |target: BlockId| -> Option<usize> { index_of.get(&target).copied() };
    let mut emit: Vec<EmitBlock> = Vec::with_capacity(ordered.len());
    for block in &ordered {
        let Some(payload): Option<&&Vec<Instruction>> = payload_of.get(&block.id) else {
            return DeflattenOutcome::Residual(format!(
                "recovered block {} has no payload projection",
                block.id
            ));
        };
        let instructions: Vec<Instruction> = payload
            .iter()
            .filter(|i: &&Instruction| {
                let name: &str = i.name.as_str();
                !(is_conditional_branch(name) || is_unconditional_branch(name) || name == "switch")
            })
            .cloned()
            .collect();
        let terminator: Terminator = match &block.edge {
            Edge::Goto(target) => match resolve(*target) {
                Some(index) => Terminator::Goto(index),
                None => {
                    return DeflattenOutcome::Residual(format!(
                        "block {} jumps to dispatcher block {target}",
                        block.id
                    ));
                }
            },
            Edge::Cond {
                taken,
                fallthrough,
                predicate,
            } => match (resolve(*taken), resolve(*fallthrough)) {
                (Some(t), Some(f)) => Terminator::Cond {
                    opcode: predicate.opcode.clone(),
                    taken: t,
                    fallthrough: f,
                },
                _ => {
                    return DeflattenOutcome::Residual(format!(
                        "block {} branches to a dispatcher block",
                        block.id
                    ));
                }
            },
            Edge::Return => {
                let ends_terminal: bool = instructions
                    .last()
                    .is_some_and(|i: &Instruction| is_terminal(&i.name));
                if !ends_terminal {
                    return DeflattenOutcome::Residual(format!(
                        "block {} ends without a return or throw although the dispatcher marks it terminal",
                        block.id
                    ));
                }
                Terminator::None
            }
        };
        emit.push(EmitBlock {
            instructions,
            terminator,
        });
    }
    if ordered.first().map(|b: &&RecoveredBlock| b.id) != Some(recovered.entry) {
        return DeflattenOutcome::Residual(
            "the dispatcher entry block is not the first recovered block".to_owned(),
        );
    }
    match assemble(body, &emit) {
        Ok(rebuilt) => DeflattenOutcome::Rebuilt(rebuilt),
        Err(AssembleError::TooManyInstructions) => {
            DeflattenOutcome::Residual("the rebuilt body exceeds the instruction limit".to_owned())
        }
        Err(AssembleError::UnknownOpcode) => {
            DeflattenOutcome::Residual("a payload opcode has no encodable form".to_owned())
        }
        Err(AssembleError::DanglingLabel) => {
            DeflattenOutcome::Residual("a rebuilt branch targets no block".to_owned())
        }
        Err(AssembleError::OffsetOverflow) => {
            DeflattenOutcome::Residual("the rebuilt body does not fit a CIL offset".to_owned())
        }
    }
}

fn layout_order(recovered: &Recovered) -> Vec<&RecoveredBlock> {
    let by_id: BTreeMap<BlockId, &RecoveredBlock> = recovered
        .blocks
        .iter()
        .map(|b: &RecoveredBlock| (b.id, b))
        .collect();
    let mut postorder: Vec<BlockId> = Vec::with_capacity(recovered.blocks.len());
    let mut visited: BTreeSet<BlockId> = BTreeSet::new();
    let mut stack: Vec<(BlockId, bool)> = vec![(recovered.entry, false)];
    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            postorder.push(id);
            continue;
        }
        if !visited.insert(id) {
            continue;
        }
        stack.push((id, true));
        let Some(block): Option<&&RecoveredBlock> = by_id.get(&id) else {
            continue;
        };
        match &block.edge {
            Edge::Goto(target) => stack.push((*target, false)),
            Edge::Cond {
                taken, fallthrough, ..
            } => {
                stack.push((*taken, false));
                stack.push((*fallthrough, false));
            }
            Edge::Return => {}
        }
    }
    let mut ordered: Vec<&RecoveredBlock> = postorder
        .iter()
        .rev()
        .filter_map(|id: &BlockId| by_id.get(id).copied())
        .collect();
    ordered.extend(
        recovered
            .blocks
            .iter()
            .filter(|b: &&RecoveredBlock| !visited.contains(&b.id)),
    );
    ordered
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cil::parse_method_body;
    use crate::metadata::{MetadataRoot, parse_metadata_root};
    use crate::model::{AssemblyModel, Resolver};
    use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
    use crate::peel::deflatten::predicate::PredicateOracle;

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn every_flattened_method_of_the_ctrlflow_sample_rebuilds() {
        let image: Vec<u8> = load("../../corpus/dotnet/cff/CffSample.ctrlflow.exe");
        let pe: PeImage = parse(&image).unwrap();
        let clr: ClrHeader = parse_clr_header(&image, &pe).unwrap();
        let root: MetadataRoot = parse_metadata_root(&image, &pe, &clr).unwrap();
        let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root).unwrap();
        let model: AssemblyModel = resolver.model();
        let oracle: PredicateOracle = PredicateOracle::build(&image, &pe, &model);
        let mut rebuilt: usize = 0;
        for ty in &model.types {
            for m in &ty.methods {
                if m.rva == 0 {
                    continue;
                }
                let off: usize = pe.rva_to_offset(m.rva).unwrap();
                let body: MethodBody = parse_method_body(&image[off..]).unwrap();
                match deflatten(&body, &oracle) {
                    DeflattenOutcome::NotFlattened => {}
                    DeflattenOutcome::Rebuilt(new_body) => {
                        rebuilt += 1;
                        assert!(
                            new_body
                                .instructions
                                .iter()
                                .all(|i: &Instruction| i.name != "switch"),
                            "{}: the rebuilt body must carry no dispatcher switch",
                            m.name
                        );
                        assert!(
                            new_body.instructions.len() < body.instructions.len(),
                            "{}: the rebuilt body must be smaller than the flattened one",
                            m.name
                        );
                    }
                    DeflattenOutcome::Residual(reason) => {
                        panic!("{}: expected a full rebuild, got residual {reason}", m.name)
                    }
                }
            }
        }
        assert!(
            rebuilt >= 4,
            "the sample flattens several methods; rebuilt {rebuilt}"
        );
    }
}
