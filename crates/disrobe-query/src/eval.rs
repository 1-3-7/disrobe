use crate::model::{Function, InsnClass, InsnView, Module, SymbolRef};
use crate::query::{
    CallSiteMatch, Capability, CapabilitySiteMatch, DecoderMatch, FunctionMatch, Query,
    QueryResult, XrefMatch,
};

const DECODER_MIN_BYTE_ARITH: u32 = 1;
const DECODER_MIN_MEMORY_OPS: u32 = 1;

fn count_u32(count: usize) -> u32 {
    u32::try_from(count).map_or(u32::MAX, |value: u32| value)
}

#[must_use]
pub fn evaluate(module: &Module, query: &Query) -> QueryResult {
    match query {
        Query::Functions => QueryResult::Functions {
            matches: module.functions().iter().map(function_match).collect(),
        },
        Query::CallsTo { target } => QueryResult::CallsTo {
            target: target.clone(),
            matches: calls_to(module, target),
        },
        Query::XrefsTo { symbol } => QueryResult::XrefsTo {
            symbol: symbol.clone(),
            matches: xrefs_to(module, symbol),
        },
        Query::StringDecoders => QueryResult::StringDecoders {
            matches: string_decoders(module),
        },
        Query::ComplexityOver { threshold } => QueryResult::ComplexityOver {
            threshold: *threshold,
            matches: complexity_over(module, *threshold),
        },
        Query::CapabilitySites { capability } => QueryResult::CapabilitySites {
            capability: *capability,
            matches: capability_sites(module, *capability),
        },
    }
}

fn function_match(f: &Function) -> FunctionMatch {
    FunctionMatch {
        name: f.name.clone(),
        address: f.address,
        instruction_count: f.instruction_count(),
        complexity: f.cyclomatic_complexity(),
        is_export: f.is_export,
    }
}

fn calls_to(module: &Module, target: &str) -> Vec<CallSiteMatch> {
    let Some(target_address): Option<u64> = module.symbol_address(target) else {
        return Vec::new();
    };
    let mut out: Vec<CallSiteMatch> = Vec::new();
    for f in module.functions() {
        for insn in &f.instructions {
            if insn.class == InsnClass::Call && insn.branch_target == Some(target_address) {
                out.push(CallSiteMatch {
                    caller: f.name.clone(),
                    call_offset: insn.offset,
                    target: target.to_owned(),
                    target_address,
                });
            }
        }
    }
    out.sort_by_key(|m: &CallSiteMatch| m.call_offset);
    out
}

fn xrefs_to(module: &Module, symbol: &str) -> Vec<XrefMatch> {
    let Some(address): Option<u64> = module.symbol_address(symbol) else {
        return Vec::new();
    };
    xrefs_to_address(module, address, symbol)
}

pub(crate) fn xrefs_to_address(module: &Module, address: u64, symbol: &str) -> Vec<XrefMatch> {
    collect_xrefs_to_address(module, address, symbol, usize::MAX).0
}

pub(crate) fn bounded_xrefs_to_address(
    module: &Module,
    address: u64,
    symbol: &str,
    limit: usize,
) -> Result<Vec<XrefMatch>, usize> {
    let (xrefs, exceeded): (Vec<XrefMatch>, bool) =
        collect_xrefs_to_address(module, address, symbol, limit);
    if exceeded { Err(limit) } else { Ok(xrefs) }
}

fn collect_xrefs_to_address(
    module: &Module,
    address: u64,
    symbol: &str,
    limit: usize,
) -> (Vec<XrefMatch>, bool) {
    let mut out: Vec<XrefMatch> = Vec::new();
    let exceeded: bool =
        for_each_xref_to_address(module, address, |f: &Function, insn: &InsnView| {
            if out.len() >= limit {
                return false;
            }
            out.push(XrefMatch {
                from_function: Some(f.name.clone()),
                from_offset: insn.offset,
                mnemonic: insn.mnemonic.clone(),
                to_symbol: symbol.to_owned(),
                to_address: address,
            });
            true
        });
    out.sort_by_key(|m: &XrefMatch| m.from_offset);
    (out, exceeded)
}

pub(crate) fn for_each_xref_to_address<F>(module: &Module, address: u64, mut visit: F) -> bool
where
    F: FnMut(&Function, &InsnView) -> bool,
{
    for function in module.functions() {
        for instruction in &function.instructions {
            if references_address(instruction, address) && !visit(function, instruction) {
                return true;
            }
        }
    }
    false
}

fn references_address(insn: &InsnView, address: u64) -> bool {
    if insn.branch_target == Some(address) {
        return true;
    }
    insn.operands
        .iter()
        .any(|op: &String| operand_contains_address(op, address))
}

fn operand_contains_address(operand: &str, address: u64) -> bool {
    let hex_prefixed: String = format!("0x{address:x}");
    let hex_suffixed: String = format!("{address:x}h");
    operand
        .split(['[', ']', '+', '-', '*', ' ', ',', '(', ')'])
        .any(|tok: &str| {
            tok.eq_ignore_ascii_case(&hex_prefixed) || tok.eq_ignore_ascii_case(&hex_suffixed)
        })
}

fn complexity_over(module: &Module, threshold: u32) -> Vec<FunctionMatch> {
    let mut out: Vec<FunctionMatch> = module
        .functions()
        .iter()
        .filter(|f: &&Function| f.cyclomatic_complexity() > threshold)
        .map(function_match)
        .collect();
    out.sort_by(|a: &FunctionMatch, b: &FunctionMatch| {
        b.complexity
            .cmp(&a.complexity)
            .then(a.address.cmp(&b.address))
    });
    out
}

fn string_decoders(module: &Module) -> Vec<DecoderMatch> {
    let mut out: Vec<DecoderMatch> = Vec::new();
    for f in module.functions() {
        let loop_back_edges: u32 = count_loop_back_edges(f);
        if loop_back_edges == 0 {
            continue;
        }
        let byte_arith_count: usize = f
            .instructions
            .iter()
            .filter(|i: &&InsnView| is_byte_arith(i))
            .count();
        let memory_count: usize = f
            .instructions
            .iter()
            .filter(|i: &&InsnView| touches_memory(i))
            .count();
        let byte_arith_ops: u32 = count_u32(byte_arith_count);
        let memory_ops: u32 = count_u32(memory_count);
        if byte_arith_ops >= DECODER_MIN_BYTE_ARITH && memory_ops >= DECODER_MIN_MEMORY_OPS {
            out.push(DecoderMatch {
                name: f.name.clone(),
                address: f.address,
                loop_back_edges,
                byte_arith_ops,
                memory_ops,
            });
        }
    }
    out.sort_by_key(|m: &DecoderMatch| m.address);
    out
}

fn count_loop_back_edges(f: &Function) -> u32 {
    let edges: usize = f
        .instructions
        .iter()
        .filter(|i: &&InsnView| {
            matches!(
                i.class,
                InsnClass::ConditionalJump | InsnClass::UnconditionalJump
            ) && i
                .branch_target
                .is_some_and(|t: u64| t <= i.offset && f.contains_offset(t))
        })
        .count();
    count_u32(edges)
}

fn is_byte_arith(insn: &InsnView) -> bool {
    let m: &str = insn.mnemonic.as_str();
    let arith: bool = is_byte_arith_mnemonic(m);
    if !arith {
        return false;
    }
    insn.operands.iter().any(|op: &String| {
        starts_with_ascii_ignore_case(op, "byte ")
            || contains_ascii_ignore_case(op, "byte ptr")
            || is_byte_register(op)
    })
}

const fn is_byte_arith_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        m if m.eq_ignore_ascii_case("xor")
            || m.eq_ignore_ascii_case("add")
            || m.eq_ignore_ascii_case("sub")
            || m.eq_ignore_ascii_case("rol")
            || m.eq_ignore_ascii_case("ror")
            || m.eq_ignore_ascii_case("shl")
            || m.eq_ignore_ascii_case("shr")
            || m.eq_ignore_ascii_case("not")
            || m.eq_ignore_ascii_case("neg")
            || m.eq_ignore_ascii_case("and")
            || m.eq_ignore_ascii_case("or")
    )
}

const fn is_byte_register(operand: &str) -> bool {
    matches!(
        operand,
        r if r.eq_ignore_ascii_case("al")
            || r.eq_ignore_ascii_case("ah")
            || r.eq_ignore_ascii_case("bl")
            || r.eq_ignore_ascii_case("bh")
            || r.eq_ignore_ascii_case("cl")
            || r.eq_ignore_ascii_case("ch")
            || r.eq_ignore_ascii_case("dl")
            || r.eq_ignore_ascii_case("dh")
            || r.eq_ignore_ascii_case("sil")
            || r.eq_ignore_ascii_case("dil")
            || r.eq_ignore_ascii_case("bpl")
            || r.eq_ignore_ascii_case("spl")
            || r.eq_ignore_ascii_case("r8b")
            || r.eq_ignore_ascii_case("r9b")
            || r.eq_ignore_ascii_case("r10b")
            || r.eq_ignore_ascii_case("r11b")
            || r.eq_ignore_ascii_case("r12b")
            || r.eq_ignore_ascii_case("r13b")
            || r.eq_ignore_ascii_case("r14b")
            || r.eq_ignore_ascii_case("r15b")
    )
}

fn starts_with_ascii_ignore_case(value: &str, prefix: &str) -> bool {
    let value_bytes: &[u8] = value.as_bytes();
    let prefix_bytes: &[u8] = prefix.as_bytes();
    value_bytes
        .get(..prefix_bytes.len())
        .is_some_and(|head: &[u8]| ascii_eq_ignore_case(head, prefix_bytes))
}

fn contains_ascii_ignore_case(value: &str, needle: &str) -> bool {
    let needle_bytes: &[u8] = needle.as_bytes();
    if needle_bytes.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|window: &[u8]| ascii_eq_ignore_case(window, needle_bytes))
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(l, r): (&u8, &u8)| l.eq_ignore_ascii_case(r))
}

fn touches_memory(insn: &InsnView) -> bool {
    insn.operands
        .iter()
        .any(|op: &String| op.contains('[') && op.contains(']'))
}

fn capability_sites(module: &Module, capability: Capability) -> Vec<CapabilitySiteMatch> {
    let mut out: Vec<CapabilitySiteMatch> = Vec::new();
    for f in module.functions() {
        for insn in &f.instructions {
            let Some(target): Option<&SymbolRef> = resolve_external_reference(module, insn) else {
                continue;
            };
            if Capability::classify(&target.name) == Some(capability) {
                out.push(CapabilitySiteMatch {
                    function: Some(f.name.clone()),
                    offset: insn.offset,
                    mnemonic: insn.mnemonic.clone(),
                    symbol: target.name.clone(),
                    capability,
                });
            }
        }
    }
    out.sort_by_key(|m: &CapabilitySiteMatch| m.offset);
    out
}

fn resolve_external_reference<'a>(module: &'a Module, insn: &InsnView) -> Option<&'a SymbolRef> {
    let target: u64 = insn.branch_target?;
    let sym: &SymbolRef = module.symbol_ref(target)?;
    sym.kind.is_external().then_some(sym)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::query::Capability as Cap;

    #[test]
    fn classify_capability_recognizes_network_and_crypto() {
        assert_eq!(Cap::classify("connect"), Some(Cap::Network));
        assert_eq!(Cap::classify("WSAStartup"), Some(Cap::Network));
        assert_eq!(Cap::classify("CryptEncrypt"), Some(Cap::Crypto));
        assert_eq!(Cap::classify("AES_set_encrypt_key"), Some(Cap::Crypto));
        assert_eq!(Cap::classify("CreateProcessW"), Some(Cap::Process));
        assert_eq!(Cap::classify("fopen"), Some(Cap::Filesystem));
        assert_eq!(Cap::classify("printf"), None);
    }

    #[test]
    fn operand_address_match_handles_hex_forms() {
        assert!(operand_contains_address("[0x404000]", 0x0040_4000));
        assert!(operand_contains_address("RIP+0X404000", 0x0040_4000));
        assert!(!operand_contains_address("[0x404001]", 0x0040_4000));
    }

    #[test]
    fn byte_arith_handles_uppercase_disassembly_text() {
        let insn: InsnView = InsnView {
            offset: 0,
            mnemonic: "XOR".to_owned(),
            operands: vec!["BYTE PTR [RAX]".to_owned()],
            class: InsnClass::Other,
            branch_target: None,
            effects: disrobe_nir::EffectRow::none(disrobe_nir::SourceLang::Unknown),
            isa: crate::model::IsaView::default(),
            stack_effect: crate::model::StackEffectView::default(),
            segments: crate::model::InsnSegmentsView::default(),
        };
        assert!(is_byte_arith(&insn));
    }

    #[test]
    fn count_conversion_saturates() {
        assert_eq!(count_u32(0), 0);
        assert_eq!(count_u32(7), 7);
        assert_eq!(count_u32(usize::MAX), u32::MAX);
    }
}
