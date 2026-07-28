use std::collections::BTreeMap;

use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction};
use object::Object;
use serde::Serialize;

use crate::disasm_ir::{FunctionSpan, build_disasm_payload, function_spans};
use crate::error::{Error, Result};
use crate::flirt::crc16_flirt;
use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, InsnFlow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffArch {
    X86,
    X86_64,
    Other,
}

fn diff_arch(bytes: &[u8]) -> DiffArch {
    match object::File::parse(bytes).map(|f: object::File<'_>| f.architecture()) {
        Ok(object::Architecture::X86_64 | object::Architecture::X86_64_X32) => DiffArch::X86_64,
        Ok(object::Architecture::I386) => DiffArch::X86,
        _ => DiffArch::Other,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgFingerprint {
    pub block_count: usize,
    pub edge_count: usize,
    pub cyclomatic: u32,
    pub instruction_count: usize,
    pub block_sizes: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionPrint {
    pub name: String,
    pub address: u64,
    pub byte_length: usize,
    pub is_export: bool,
    pub content_hash: String,
    pub masked_hash: String,
    pub flirt_crc16: u16,
    pub cfg: CfgFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    BytesChanged,
    CfgChanged,
    Renamed,
    RelocatedOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedFunction {
    pub name_a: String,
    pub name_b: String,
    pub address_a: u64,
    pub address_b: u64,
    pub kind: ChangeKind,
    pub cfg_a: CfgFingerprint,
    pub cfg_b: CfgFingerprint,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BinDiffReport {
    pub schema: &'static str,
    pub total_a: usize,
    pub total_b: usize,
    pub identical: usize,
    pub added: Vec<FunctionPrint>,
    pub removed: Vec<FunctionPrint>,
    pub changed: Vec<ChangedFunction>,
    pub similarity: f64,
}

pub const BINDIFF_SCHEMA: &str = "disrobe.native.bindiff/v1";

fn function_partition(payload: &DisasmPayload, arch: DiffArch) -> Vec<FunctionPrint> {
    let spans: Vec<FunctionSpan> = function_spans(payload);
    let mut sorted: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
    sorted.sort_by_key(|i: &&DisasmInstruction| i.offset);

    let mut out: Vec<FunctionPrint> = Vec::with_capacity(spans.len());
    for span in spans {
        let insns: Vec<&DisasmInstruction> = sorted
            .iter()
            .copied()
            .filter(|i: &&DisasmInstruction| i.offset >= span.address && i.offset < span.end)
            .collect();
        if insns.is_empty() {
            continue;
        }
        out.push(build_print(
            span.name,
            span.address,
            span.is_export,
            &insns,
            arch,
        ));
    }
    out
}

fn build_print(
    name: String,
    address: u64,
    is_export: bool,
    insns: &[&DisasmInstruction],
    arch: DiffArch,
) -> FunctionPrint {
    let raw: Vec<u8> = insns
        .iter()
        .flat_map(|i: &&DisasmInstruction| i.bytes.iter().copied())
        .collect();
    let masked: Vec<u8> = masked_bytes(insns, arch);
    let cfg: CfgFingerprint = cfg_fingerprint(insns);
    FunctionPrint {
        name,
        address,
        byte_length: raw.len(),
        is_export,
        content_hash: blake3::hash(&raw).to_hex().to_string(),
        masked_hash: blake3::hash(&masked).to_hex().to_string(),
        flirt_crc16: crc16_flirt(&raw),
        cfg,
    }
}

fn masked_bytes(insns: &[&DisasmInstruction], arch: DiffArch) -> Vec<u8> {
    let bitness: u32 = match arch {
        DiffArch::X86 => 32,
        DiffArch::X86_64 => 64,
        DiffArch::Other => return mnemonic_stream(insns),
    };
    let mut out: Vec<u8> = Vec::new();
    for insn in insns {
        let mut decoder: Decoder<'_> =
            Decoder::with_ip(bitness, &insn.bytes, insn.offset, DecoderOptions::NONE);
        if !decoder.can_decode() {
            out.extend_from_slice(&insn.bytes);
            continue;
        }
        let mut decoded: Instruction = Instruction::default();
        decoder.decode_out(&mut decoded);
        if decoded.is_invalid() || decoded.len() != insn.bytes.len() {
            out.extend_from_slice(&insn.bytes);
            continue;
        }
        let offsets: ConstantOffsets = decoder.get_constant_offsets(&decoded);
        let mut masked: Vec<u8> = insn.bytes.clone();
        zero_range(
            &mut masked,
            offsets.displacement_offset(),
            offsets.displacement_size(),
            offsets.has_displacement(),
        );
        zero_range(
            &mut masked,
            offsets.immediate_offset(),
            offsets.immediate_size(),
            offsets.has_immediate(),
        );
        zero_range(
            &mut masked,
            offsets.immediate_offset2(),
            offsets.immediate_size2(),
            offsets.has_immediate2(),
        );
        out.extend_from_slice(&masked);
    }
    out
}

fn zero_range(buf: &mut [u8], off: usize, size: usize, present: bool) {
    if !present {
        return;
    }
    for i in off..off + size {
        if let Some(slot) = buf.get_mut(i) {
            *slot = 0;
        }
    }
}

fn mnemonic_stream(insns: &[&DisasmInstruction]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for insn in insns {
        out.extend_from_slice(insn.mnemonic.as_bytes());
        out.push(0);
    }
    out
}

fn cfg_fingerprint(insns: &[&DisasmInstruction]) -> CfgFingerprint {
    if insns.is_empty() {
        return CfgFingerprint {
            block_count: 0,
            edge_count: 0,
            cyclomatic: 1,
            instruction_count: 0,
            block_sizes: Vec::new(),
        };
    }
    let start: u64 = insns[0].offset;
    let end: u64 = insns.last().map_or(start, |i: &&DisasmInstruction| {
        i.offset + i.bytes.len() as u64
    });
    let contains = |addr: u64| addr >= start && addr < end;

    let mut leaders: Vec<u64> = vec![insns[0].offset];
    for (idx, insn) in insns.iter().enumerate() {
        match insn.flow {
            InsnFlow::ConditionalBranch => {
                if let Some(t) = insn.branch_target.filter(|t: &u64| contains(*t)) {
                    leaders.push(t);
                }
                if let Some(next) = insns.get(idx + 1) {
                    leaders.push(next.offset);
                }
            }
            InsnFlow::UnconditionalBranch | InsnFlow::IndirectBranch => {
                if let Some(t) = insn.branch_target.filter(|t: &u64| contains(*t)) {
                    leaders.push(t);
                }
            }
            _ => {}
        }
    }
    leaders.retain(|l: &u64| contains(*l));
    leaders.sort_unstable();
    leaders.dedup();

    let mut block_sizes: Vec<usize> = Vec::with_capacity(leaders.len());
    let mut edge_count: usize = 0;
    for (idx, leader) in leaders.iter().enumerate() {
        let block_end: u64 = leaders.get(idx + 1).copied().unwrap_or(end);
        let block_insns: Vec<&DisasmInstruction> = insns
            .iter()
            .copied()
            .filter(|i: &&DisasmInstruction| i.offset >= *leader && i.offset < block_end)
            .collect();
        block_sizes.push(block_insns.len());
        let Some(last): Option<&&DisasmInstruction> = block_insns.last() else {
            continue;
        };
        let fallthrough: Option<u64> = insns
            .iter()
            .find(|i: &&&DisasmInstruction| i.offset >= block_end)
            .map(|i: &&DisasmInstruction| i.offset);
        edge_count += successor_count(last, fallthrough, &leaders, contains);
    }

    let nodes: u32 = u32::try_from(leaders.len().max(1)).unwrap_or(u32::MAX);
    let edges: u32 = u32::try_from(edge_count).unwrap_or(u32::MAX);
    let cyclomatic: u32 = edges.saturating_sub(nodes).saturating_add(2);
    block_sizes.sort_unstable();
    CfgFingerprint {
        block_count: leaders.len(),
        edge_count,
        cyclomatic,
        instruction_count: insns.len(),
        block_sizes,
    }
}

fn successor_count(
    last: &DisasmInstruction,
    fallthrough: Option<u64>,
    leaders: &[u64],
    contains: impl Fn(u64) -> bool,
) -> usize {
    let in_fn = |addr: u64| contains(addr) && leaders.binary_search(&addr).is_ok();
    match last.flow {
        InsnFlow::ConditionalBranch => {
            let mut n: usize = 0;
            if last.branch_target.is_some_and(|t: u64| in_fn(t)) {
                n += 1;
            }
            if fallthrough.is_some_and(|f: u64| in_fn(f)) {
                n += 1;
            }
            n
        }
        InsnFlow::UnconditionalBranch => {
            usize::from(last.branch_target.is_some_and(|t: u64| in_fn(t)))
        }
        InsnFlow::IndirectBranch | InsnFlow::Return => 0,
        InsnFlow::Sequential | InsnFlow::Call | InsnFlow::IndirectCall | InsnFlow::Interrupt => {
            usize::from(fallthrough.is_some_and(|f: u64| in_fn(f)))
        }
    }
}

fn cfg_equal(a: &CfgFingerprint, b: &CfgFingerprint) -> bool {
    a.block_count == b.block_count
        && a.edge_count == b.edge_count
        && a.cyclomatic == b.cyclomatic
        && a.block_sizes == b.block_sizes
}

pub fn diff(image_a: &[u8], image_b: &[u8]) -> Result<BinDiffReport> {
    let payload_a: DisasmPayload = build_disasm_payload(image_a).map_err(wrap_a)?;
    let payload_b: DisasmPayload = build_disasm_payload(image_b).map_err(wrap_b)?;
    let arch_a: DiffArch = diff_arch(image_a);
    let arch_b: DiffArch = diff_arch(image_b);

    let funcs_a: Vec<FunctionPrint> = function_partition(&payload_a, arch_a);
    let funcs_b: Vec<FunctionPrint> = function_partition(&payload_b, arch_b);
    let total_a: usize = funcs_a.len();
    let total_b: usize = funcs_b.len();

    let mut content_index_b: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut name_index_b: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut masked_index_b: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, f) in funcs_b.iter().enumerate() {
        content_index_b
            .entry(f.content_hash.clone())
            .or_default()
            .push(idx);
        name_index_b.entry(f.name.clone()).or_default().push(idx);
        masked_index_b
            .entry(f.masked_hash.clone())
            .or_default()
            .push(idx);
    }

    let mut matched_b: Vec<bool> = vec![false; funcs_b.len()];
    let mut identical: usize = 0;
    let mut changed: Vec<ChangedFunction> = Vec::new();
    let mut removed: Vec<FunctionPrint> = Vec::new();

    for fa in &funcs_a {
        if let Some(bi) = take_match(&content_index_b, &fa.content_hash, &matched_b) {
            matched_b[bi] = true;
            identical += 1;
            continue;
        }
        let candidate: Option<usize> = take_match(&name_index_b, &fa.name, &matched_b)
            .or_else(|| take_match(&masked_index_b, &fa.masked_hash, &matched_b));
        match candidate {
            Some(bi) => {
                matched_b[bi] = true;
                let fb: &FunctionPrint = &funcs_b[bi];
                let kind: ChangeKind = classify_change(fa, fb);
                changed.push(ChangedFunction {
                    name_a: fa.name.clone(),
                    name_b: fb.name.clone(),
                    address_a: fa.address,
                    address_b: fb.address,
                    kind,
                    cfg_a: fa.cfg.clone(),
                    cfg_b: fb.cfg.clone(),
                });
            }
            None => removed.push(fa.clone()),
        }
    }

    let added: Vec<FunctionPrint> = funcs_b
        .iter()
        .enumerate()
        .filter(|(idx, _): &(usize, &FunctionPrint)| !matched_b[*idx])
        .map(|(_, f): (usize, &FunctionPrint)| f.clone())
        .collect();

    let denom: usize = total_a.max(total_b).max(1);
    let similarity: f64 = identical as f64 / denom as f64;

    Ok(BinDiffReport {
        schema: BINDIFF_SCHEMA,
        total_a,
        total_b,
        identical,
        added,
        removed,
        changed,
        similarity,
    })
}

fn take_match(index: &BTreeMap<String, Vec<usize>>, key: &str, matched: &[bool]) -> Option<usize> {
    index
        .get(key)?
        .iter()
        .copied()
        .find(|idx: &usize| !matched[*idx])
}

fn classify_change(a: &FunctionPrint, b: &FunctionPrint) -> ChangeKind {
    if a.content_hash != b.content_hash
        && a.masked_hash == b.masked_hash
        && a.byte_length == b.byte_length
    {
        return ChangeKind::RelocatedOnly;
    }
    if !cfg_equal(&a.cfg, &b.cfg) {
        return ChangeKind::CfgChanged;
    }
    if a.name != b.name && a.content_hash == b.content_hash {
        return ChangeKind::Renamed;
    }
    ChangeKind::BytesChanged
}

fn wrap_a(e: Error) -> Error {
    Error::Export {
        stage: "bindiff-parse-a",
        detail: e.to_string(),
    }
}

fn wrap_b(e: Error) -> Error {
    Error::Export {
        stage: "bindiff-parse-b",
        detail: e.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_support::{pe64_text_base, pe64_with_text};

    const SECOND_FN_OFFSET: usize = 0x20;
    const PATCH_IMM_OFFSET: usize = SECOND_FN_OFFSET + 4;

    fn two_function_text() -> Vec<u8> {
        let mut t: Vec<u8> = Vec::new();
        t.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        t.extend_from_slice(&[0x85, 0xC0]);
        t.extend_from_slice(&[0x74, 0x02]);
        t.extend_from_slice(&[0x31, 0xC0]);
        t.extend_from_slice(&[0x5D, 0xC3]);
        while t.len() < SECOND_FN_OFFSET {
            t.push(0xCC);
        }
        t.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        t.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
        t.extend_from_slice(&[0x5D, 0xC3]);
        while t.len() % 16 != 0 {
            t.push(0xCC);
        }
        t
    }

    #[test]
    fn diff_identical_binary_is_fully_identical() {
        let image: Vec<u8> = pe64_with_text(&two_function_text(), 0x1000);
        let report: BinDiffReport = diff(&image, &image).expect("diff");
        assert!(report.total_a >= 2, "must discover both functions");
        assert_eq!(report.total_a, report.total_b);
        assert_eq!(
            report.identical, report.total_a,
            "diff(bin, bin) must match every function"
        );
        assert!(report.added.is_empty(), "no functions added vs self");
        assert!(report.removed.is_empty(), "no functions removed vs self");
        assert!(report.changed.is_empty(), "no functions changed vs self");
        assert!((report.similarity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn diff_isolates_a_single_patched_function() {
        let text_a: Vec<u8> = two_function_text();
        let mut text_b: Vec<u8> = text_a.clone();
        text_b[PATCH_IMM_OFFSET + 1] = 0x09;

        let image_a: Vec<u8> = pe64_with_text(&text_a, 0x1000);
        let image_b: Vec<u8> = pe64_with_text(&text_b, 0x1000);

        let report: BinDiffReport = diff(&image_a, &image_b).expect("diff");
        assert!(report.total_a >= 2, "fixture must expose two functions");
        assert_eq!(report.total_a, report.total_b);
        assert_eq!(
            report.changed.len(),
            1,
            "exactly one function body changed; added={} removed={} changed={}",
            report.added.len(),
            report.removed.len(),
            report.changed.len()
        );
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(
            report.identical,
            report.total_a - 1,
            "every function except the patched one must still match"
        );
        let changed: &ChangedFunction = &report.changed[0];
        assert_eq!(
            changed.address_a,
            pe64_text_base() + 0x1000 + SECOND_FN_OFFSET as u64,
            "the changed function must be the second one (the imm32 mov), not the first"
        );
    }

    #[test]
    fn relocated_immediate_classified_as_relocated_only() {
        let mut a: Vec<u8> = Vec::new();
        a.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x11, 0x22, 0x33, 0x44, 0xC3]);
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x55, 0x66, 0x77, 0x88, 0xC3]);
        let insn_a: Vec<DisasmInstruction> = vec![
            DisasmInstruction {
                offset: 0x1000,
                bytes: a[..7].to_vec(),
                mnemonic: "mov".to_owned(),
                operands: vec!["rax".to_owned(), "0x44332211".to_owned()],
                flow: InsnFlow::Sequential,
                branch_target: None,
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x1007,
                bytes: vec![0xC3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ];
        let insn_b: Vec<DisasmInstruction> = vec![
            DisasmInstruction {
                offset: 0x1000,
                bytes: b[..7].to_vec(),
                mnemonic: "mov".to_owned(),
                operands: vec!["rax".to_owned(), "0x88776655".to_owned()],
                flow: InsnFlow::Sequential,
                branch_target: None,
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x1007,
                bytes: vec![0xC3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ];
        let refs_a: Vec<&DisasmInstruction> = insn_a.iter().collect();
        let refs_b: Vec<&DisasmInstruction> = insn_b.iter().collect();
        let pa: FunctionPrint =
            build_print("f".to_owned(), 0x1000, false, &refs_a, DiffArch::X86_64);
        let pb: FunctionPrint =
            build_print("f".to_owned(), 0x1000, false, &refs_b, DiffArch::X86_64);
        assert_ne!(pa.content_hash, pb.content_hash, "raw bytes differ");
        assert_eq!(
            pa.masked_hash, pb.masked_hash,
            "masking the imm32 must make the two identical"
        );
        assert_eq!(classify_change(&pa, &pb), ChangeKind::RelocatedOnly);
    }

    #[test]
    fn non_object_input_errors() {
        let err: Error = diff(b"not an object", b"also not").expect_err("reject");
        assert!(matches!(err, Error::Export { .. }));
    }
}
