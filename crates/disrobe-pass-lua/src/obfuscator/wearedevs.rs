use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::obfuscator::string_decode::{
    apply_permutation, decode_base64_variant, eval_arith_expr, parse_alphabet_table,
    parse_permutation_table,
};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchEdge {
    Direct(i64),
    Conditional { taken: i64, not_taken: i64 },
    RuntimeTableJump { pool_index: i64 },
    RuntimeComposite,
    Halt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchBlock {
    index: usize,
    state_lo: i64,
    state_hi: i64,
    edge: DispatchEdge,
    const_loads: usize,
    stores: usize,
    arith_ops: usize,
}

#[derive(Debug, Clone)]
struct DispatchLift {
    blocks: Vec<DispatchBlock>,
    resolved_edges: usize,
    runtime_table_jumps: usize,
    runtime_composite: usize,
    const_loads: usize,
    indirect_jumps: usize,
    op_counts: BTreeMap<&'static str, usize>,
    guards: Vec<DispatchGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchGuard {
    index: usize,
    upper: i64,
    const_loads: usize,
    stores: usize,
    direct_jumps: usize,
    indirect_jumps: usize,
    arith_ops: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThresholdCut {
    source_start: usize,
    body_start: usize,
    upper: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchOp {
    ConstLoad,
    Store,
    DirectJump,
    IndirectJump,
    Arith,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchNode {
    Branch {
        threshold: i64,
        then_node: Box<DispatchNode>,
        else_node: Box<DispatchNode>,
    },
    Leaf {
        body: String,
    },
}

const MARKERS: &[&[u8]] = &[
    b"-- WeAreDevs",
    b"WRD_OBFUSCATOR",
    b"wearedevs_luau",
    b"wearedevs.net/obfuscator",
    b"https://wearedevs.net",
];
const DISPATCH_SCAN_LIMIT: usize = 256 * 1024;
const DISPATCH_PARSE_DEPTH_LIMIT: usize = 512;
const DISPATCH_BLOCK_LIMIT: usize = 4096;
const DISPATCH_STATE_CEIL: i64 = 1 << 30;
const P_TABLE_BASE: i64 = 40258;
const DISPATCH_GUARD_LIMIT: usize = 256;

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if !found.is_empty() {
        return Some(ObfuscatorDetection {
            kind: LuaObfuscatorKind::WeAreDevs,
            variant: Some("luau-string-encode".to_owned()),
            confidence: 82,
            markers: found,
        });
    }
    fingerprint_detect(src)
}

fn fingerprint_detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let head: &[u8] = &src[..src.len().min(4096)];
    let prelude_match: bool =
        disrobe_core::byte_search::contains(head, b"return(function(...)local v={")
            || disrobe_core::byte_search::contains(head, b"return (function(...) local v = {");
    if !prelude_match {
        return None;
    }
    let escape_density: u32 = count_decimal_escapes(head);
    if escape_density < 48 {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::WeAreDevs,
        variant: Some("luau-string-encode-vm".to_owned()),
        confidence: 70,
        markers: vec![
            "wearedevs anonymous-vm prelude".to_owned(),
            format!("decimal-escape density {escape_density}/4KB"),
        ],
    })
}

fn count_decimal_escapes(buf: &[u8]) -> u32 {
    let mut count: u32 = 0;
    let n: usize = buf.len();
    let mut i: usize = 0;
    while i + 3 < n {
        if buf[i] == b'\\'
            && buf[i + 1].is_ascii_digit()
            && buf[i + 2].is_ascii_digit()
            && buf[i + 3].is_ascii_digit()
        {
            count += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    count
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("WeAreDevs LuaU"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    decode_wearedevs(&text).map_or_else(
        || {
            Ok(PeelResult::passthrough(
                src,
                vec![
                    "wearedevs string-decode: alphabet table not statically recoverable".to_owned(),
                ],
            ))
        },
        Ok,
    )
}

fn decode_wearedevs(text: &str) -> Option<PeelResult> {
    let alphabet: BTreeMap<char, u8> = find_alphabet(text)?;
    let array_body: &str = find_string_array(text)?;
    let encoded: Vec<String> = parse_string_literals(array_body);
    if encoded.is_empty() {
        return None;
    }
    let mut recovered: Vec<String> = Vec::with_capacity(encoded.len());
    let mut decoded_any: bool = false;
    for enc in &encoded {
        match decode_base64_variant(enc, &alphabet) {
            Some(bytes) if !bytes.is_empty() => {
                let s: String = String::from_utf8_lossy(&bytes).into_owned();
                if s.chars()
                    .all(|c: char| !c.is_control() || c == '\n' || c == '\t')
                {
                    decoded_any = true;
                }
                recovered.push(s);
            }
            _ => recovered.push(enc.clone()),
        }
    }
    if !decoded_any {
        return None;
    }

    let mut passes_run: Vec<String> = vec![
        "wearedevs-alphabet-recover".to_owned(),
        "base64-variant-string-decode".to_owned(),
    ];

    let permutation: Option<Vec<(usize, usize)>> = parse_permutation_table(text);
    let mut ordered: Vec<String> = recovered.clone();
    if let Some(pairs) = permutation.as_ref() {
        apply_permutation(&mut ordered, pairs);
        passes_run.push("wearedevs-permutation-replay".to_owned());
    }

    let lift: Option<DispatchLift> = lift_dispatch(text);
    if lift.is_some() {
        passes_run.push("wearedevs-dispatch-lift".to_owned());
    }

    let mut out: String = String::new();
    out.push_str("local STRINGS = {\n");
    for s in &ordered {
        out.push_str("  ");
        out.push_str(&quote(s));
        out.push_str(",\n");
    }
    out.push_str("}\n");

    let mut residual_markers: Vec<String> = Vec::new();
    if let Some(lift) = lift.as_ref() {
        out.push_str(&render_dispatch(lift));
        residual_markers.push(format!(
            "wearedevs vm: resolved {}/{} structured dispatch guards into concrete control-flow edges; {} remain runtime-derived",
            lift.resolved_edges,
            lift.blocks.len(),
            lift.runtime_table_jumps + lift.runtime_composite
        ));
        residual_markers.push(format!(
            "wearedevs vm: {} data-dependent W=v[p(k)] jumps read runtime-populated string-key slots (label constants never written statically) and {} tail selectors combine runtime comparison registers; next-state values are computed at runtime and absent from the chunk as constants",
            lift.runtime_table_jumps, lift.runtime_composite
        ));
    } else {
        residual_markers.push(
            "wearedevs vm: dispatch tree not statically lifted (string pool only)".to_owned(),
        );
    }
    if permutation.is_none() {
        residual_markers.push(
            "wearedevs vm: permutation table absent -- constant order is decode order".to_owned(),
        );
    }

    Some(PeelResult {
        deobfuscated: out.into_bytes(),
        passes_run,
        residual_markers,
        recovered_strings: recovered,
        fully_recovered: false,
    })
}

fn lift_dispatch(text: &str) -> Option<DispatchLift> {
    let marker: &str = "while W do";
    let dispatch_start: usize = text.find(marker)?;
    let scan_end: usize = text
        .len()
        .min(dispatch_start.saturating_add(DISPATCH_SCAN_LIMIT));
    let after_marker: usize = dispatch_start + marker.len();
    let body: &str = &text[after_marker..scan_end];
    let inner: &str = trim_trailing_loop_end(body);

    let p_base: i64 = parse_p_table_base(text).unwrap_or(P_TABLE_BASE);

    let mut cursor: usize = 0;
    let mut depth: usize = 0;
    let tree: DispatchNode = parse_dispatch_node(inner, &mut cursor, &mut depth)?;

    let mut leaves: Vec<(i64, i64, String)> = Vec::new();
    collect_leaf_ranges(&tree, 0, DISPATCH_STATE_CEIL - 1, &mut leaves);
    if leaves.is_empty() {
        return None;
    }

    let mut blocks: Vec<DispatchBlock> = Vec::with_capacity(leaves.len());
    for entry in leaves.into_iter().enumerate() {
        let (index, (state_lo, state_hi, leaf_body)): (usize, (i64, i64, String)) = entry;
        if blocks.len() >= DISPATCH_BLOCK_LIMIT {
            break;
        }
        let edge: DispatchEdge = resolve_edge(&leaf_body, p_base);
        blocks.push(DispatchBlock {
            index,
            state_lo,
            state_hi,
            edge,
            const_loads: count_const_loads(&leaf_body),
            stores: count_store_ops(&leaf_body),
            arith_ops: count_arith_ops(&leaf_body),
        });
    }

    let resolved_edges: usize = blocks
        .iter()
        .filter(|b: &&DispatchBlock| {
            matches!(
                b.edge,
                DispatchEdge::Direct(_) | DispatchEdge::Conditional { .. } | DispatchEdge::Halt
            )
        })
        .count();
    let runtime_table_jumps: usize = blocks
        .iter()
        .filter(|b: &&DispatchBlock| matches!(b.edge, DispatchEdge::RuntimeTableJump { .. }))
        .count();
    let runtime_composite: usize = blocks
        .iter()
        .filter(|b: &&DispatchBlock| matches!(b.edge, DispatchEdge::RuntimeComposite))
        .count();
    let const_loads: usize = blocks.iter().map(|b: &DispatchBlock| b.const_loads).sum();

    let cuts: Vec<ThresholdCut> = collect_threshold_cuts(body);
    let guards: Vec<DispatchGuard> = lift_guard_blocks(body, &cuts);
    let indirect_jumps: usize = count_occurrences(body, "W=v[p(");
    let mut op_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    op_counts.insert(classify(&DispatchOp::ConstLoad), count_const_loads(body));
    op_counts.insert(classify(&DispatchOp::Store), count_store_ops(body));
    op_counts.insert(classify(&DispatchOp::DirectJump), count_direct_jumps(body));
    op_counts.insert(classify(&DispatchOp::IndirectJump), indirect_jumps);
    op_counts.insert(classify(&DispatchOp::Arith), count_arith_ops(body));

    Some(DispatchLift {
        blocks,
        resolved_edges,
        runtime_table_jumps,
        runtime_composite,
        const_loads,
        indirect_jumps,
        op_counts,
        guards,
    })
}

fn trim_trailing_loop_end(body: &str) -> &str {
    let terminator: &str = "W=#y";
    body.find(terminator)
        .map_or(body, |pos: usize| &body[..pos])
}

fn parse_p_table_base(text: &str) -> Option<i64> {
    let marker: &str = "local function p(p)return v[p-";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &str = &text[start..];
    let end: usize = rest.find(']')?;
    eval_prefixed_arith(&rest[..end])
}

fn parse_dispatch_node(s: &str, cursor: &mut usize, depth: &mut usize) -> Option<DispatchNode> {
    if *depth > DISPATCH_PARSE_DEPTH_LIMIT {
        return None;
    }
    skip_ws(s, cursor);
    let branch_prefix: &str = "if W<";
    if s[*cursor..].starts_with(branch_prefix) {
        *cursor += branch_prefix.len();
        let then_kw: &str = "then";
        let then_rel: usize = s[*cursor..].find(then_kw)?;
        let threshold: i64 = eval_prefixed_arith(&s[*cursor..*cursor + then_rel])?;
        *cursor += then_rel + then_kw.len();
        *depth += 1;
        let then_node: DispatchNode = parse_dispatch_node(s, cursor, depth)?;
        skip_ws(s, cursor);
        let else_kw: &str = "else";
        if !s[*cursor..].starts_with(else_kw) {
            *depth -= 1;
            return None;
        }
        *cursor += else_kw.len();
        let else_node: DispatchNode = parse_dispatch_node(s, cursor, depth)?;
        skip_ws(s, cursor);
        let end_kw: &str = "end";
        if !s[*cursor..].starts_with(end_kw) {
            *depth -= 1;
            return None;
        }
        *cursor += end_kw.len();
        *depth -= 1;
        return Some(DispatchNode::Branch {
            threshold,
            then_node: Box::new(then_node),
            else_node: Box::new(else_node),
        });
    }
    let leaf_start: usize = *cursor;
    let leaf_end: usize = find_leaf_end(s, leaf_start);
    *cursor = leaf_end;
    Some(DispatchNode::Leaf {
        body: s[leaf_start..leaf_end].to_owned(),
    })
}

fn find_leaf_end(s: &str, start: usize) -> usize {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = start;
    while i < bytes.len() {
        if is_keyword_at(bytes, i, b"else") || is_keyword_at(bytes, i, b"end") {
            return i;
        }
        i += 1;
    }
    bytes.len()
}

fn is_keyword_at(bytes: &[u8], i: usize, kw: &[u8]) -> bool {
    if i + kw.len() > bytes.len() || &bytes[i..i + kw.len()] != kw {
        return false;
    }
    match bytes.get(i + kw.len()) {
        Some(&b) => !b.is_ascii_alphanumeric(),
        None => true,
    }
}

fn skip_ws(s: &str, cursor: &mut usize) {
    let bytes: &[u8] = s.as_bytes();
    while matches!(bytes.get(*cursor), Some(b' ' | b'\n' | b'\t' | b'\r')) {
        *cursor += 1;
    }
}

fn collect_leaf_ranges(node: &DispatchNode, lo: i64, hi: i64, out: &mut Vec<(i64, i64, String)>) {
    match node {
        DispatchNode::Leaf { body } => out.push((lo, hi, body.clone())),
        DispatchNode::Branch {
            threshold,
            then_node,
            else_node,
        } => {
            collect_leaf_ranges(then_node, lo, hi.min(*threshold - 1), out);
            collect_leaf_ranges(else_node, lo.max(*threshold), hi, out);
        }
    }
}

fn resolve_edge(body: &str, p_base: i64) -> DispatchEdge {
    let Some(last_rhs): Option<&str> = last_w_assignment_rhs(body) else {
        return DispatchEdge::RuntimeComposite;
    };
    if let Some(after_p) = last_rhs.strip_prefix("v[p(") {
        let Some(key): Option<i64> = eval_balanced_paren_arith(after_p) else {
            return DispatchEdge::RuntimeComposite;
        };
        return DispatchEdge::RuntimeTableJump {
            pool_index: key - p_base,
        };
    }
    if last_rhs.starts_with("true") || last_rhs.starts_with("false") {
        return DispatchEdge::Halt;
    }
    if starts_numeric(last_rhs)
        && let Some(target) = eval_prefixed_arith(last_rhs)
    {
        return DispatchEdge::Direct(target);
    }
    if let Some(edge) = resolve_conditional(last_rhs) {
        return edge;
    }
    DispatchEdge::RuntimeComposite
}

fn resolve_conditional(rhs: &str) -> Option<DispatchEdge> {
    let and_kw: &str = " and";
    let and_pos: usize = rhs.find(and_kw)?;
    let selector: &str = &rhs[..and_pos];
    if selector.is_empty() || !selector.chars().all(is_selector_char) {
        return None;
    }
    let after_and: &str = &rhs[and_pos + and_kw.len()..];
    let taken_len: usize = arith_prefix_len(after_and);
    let taken: i64 = eval_prefixed_arith(&after_and[..taken_len])?;
    let rest: &str = after_and[taken_len..].trim_start();
    let not_taken_str: &str = rest.strip_prefix("or")?;
    let not_taken: i64 = eval_prefixed_arith(not_taken_str)?;
    Some(DispatchEdge::Conditional { taken, not_taken })
}

#[inline]
fn is_selector_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '[' || c == ']' || c == '_'
}

fn last_w_assignment_rhs(body: &str) -> Option<&str> {
    let bytes: &[u8] = body.as_bytes();
    let mut last: Option<usize> = None;
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'W' && bytes[i + 1] == b'=' {
            let is_boundary: bool = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let not_comparison: bool = bytes.get(i + 2) != Some(&b'=');
            if is_boundary && not_comparison {
                last = Some(i + 2);
            }
        }
        i += 1;
    }
    last.map(|pos: usize| &body[pos..])
}

#[inline]
fn starts_numeric(s: &str) -> bool {
    matches!(s.as_bytes().first(), Some(b) if b.is_ascii_digit() || *b == b'-')
}

fn arith_prefix_len(s: &str) -> usize {
    s.bytes()
        .take_while(|b: &u8| {
            matches!(
                b,
                b'0'..=b'9' | b'+' | b'-' | b'*' | b'/' | b'(' | b')' | b' '
            )
        })
        .count()
}

fn eval_prefixed_arith(s: &str) -> Option<i64> {
    let len: usize = arith_prefix_len(s);
    if len == 0 {
        return None;
    }
    eval_arith_expr(&s[..len])
}

fn eval_balanced_paren_arith(s: &str) -> Option<i64> {
    let bytes: &[u8] = s.as_bytes();
    let mut depth: i32 = 1;
    let mut end: usize = 0;
    while end < bytes.len() {
        match bytes[end] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        end += 1;
    }
    if depth != 0 {
        return None;
    }
    eval_arith_expr(&s[..end])
}

fn collect_threshold_cuts(body: &str) -> Vec<ThresholdCut> {
    const GUARD_PREFIX: &str = "if W<";
    const GUARD_SUFFIX: &str = "then";

    let mut cuts: Vec<ThresholdCut> = Vec::new();
    for entry in body.match_indices(GUARD_PREFIX) {
        let (source_start, _guard): (usize, &str) = entry;
        if cuts.len() >= DISPATCH_GUARD_LIMIT {
            break;
        }
        let after: &str = &body[source_start + GUARD_PREFIX.len()..];
        let Some(expr_end): Option<usize> = after.find(GUARD_SUFFIX) else {
            continue;
        };
        let expr: &str = &after[..expr_end];
        let Some(upper): Option<i64> = eval_arith_expr(expr) else {
            continue;
        };
        cuts.push(ThresholdCut {
            source_start,
            body_start: source_start + GUARD_PREFIX.len() + expr_end + GUARD_SUFFIX.len(),
            upper,
        });
    }
    cuts
}

fn lift_guard_blocks(body: &str, cuts: &[ThresholdCut]) -> Vec<DispatchGuard> {
    let mut guards: Vec<DispatchGuard> = Vec::with_capacity(cuts.len());
    for entry in cuts.iter().enumerate() {
        let (index, cut): (usize, &ThresholdCut) = entry;
        let end: usize = cuts
            .get(index + 1)
            .map_or(body.len(), |next: &ThresholdCut| next.source_start);
        let span: &str = if cut.body_start <= end && end <= body.len() {
            &body[cut.body_start..end]
        } else {
            ""
        };
        let indirect_jumps: usize = count_occurrences(span, "W=v[p(");
        let const_loads: usize = count_const_loads(span);
        guards.push(DispatchGuard {
            index,
            upper: cut.upper,
            const_loads,
            stores: count_store_ops(span),
            direct_jumps: count_direct_jumps(span),
            indirect_jumps,
            arith_ops: count_arith_ops(span),
        });
    }
    guards
}

#[inline]
const fn classify(op: &DispatchOp) -> &'static str {
    match op {
        DispatchOp::ConstLoad => "const-load",
        DispatchOp::Store => "register-store",
        DispatchOp::DirectJump => "direct-jump",
        DispatchOp::IndirectJump => "indirect-jump",
        DispatchOp::Arith => "arith",
    }
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn count_const_loads(body: &str) -> usize {
    let bytes: &[u8] = body.as_bytes();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'p' && bytes[i + 1] == b'(' && is_operand_start(bytes[i + 2]) {
            if i == 0 || !bytes[i - 1].is_ascii_alphanumeric() {
                count += 1;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

#[inline]
const fn is_operand_start(b: u8) -> bool {
    b.is_ascii_digit() || b == b'-'
}

fn count_store_ops(body: &str) -> usize {
    let bytes: &[u8] = body.as_bytes();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'S' && bytes[i + 1] == b'[' {
            count += 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

fn count_direct_jumps(body: &str) -> usize {
    let total: usize = count_occurrences(body, "W=");
    let indirect: usize = count_occurrences(body, "W=v[p(");
    total.saturating_sub(indirect)
}

fn count_arith_ops(body: &str) -> usize {
    count_occurrences(body, "%")
}

fn edge_label(edge: &DispatchEdge) -> String {
    match edge {
        DispatchEdge::Direct(target) => format!("goto = {target}"),
        DispatchEdge::Conditional { taken, not_taken } => {
            format!("branch = {{ taken = {taken}, not_taken = {not_taken} }}")
        }
        DispatchEdge::RuntimeTableJump { pool_index } => {
            format!("runtime_table_jump = {{ v_key = pool[{pool_index}] }}")
        }
        DispatchEdge::RuntimeComposite => "runtime_composite = true".to_owned(),
        DispatchEdge::Halt => "halt = true".to_owned(),
    }
}

fn render_dispatch(lift: &DispatchLift) -> String {
    let mut out: String = String::new();
    out.push_str("local DISPATCH_CFG = {\n");
    out.push_str(&format!("  blocks_total = {},\n", lift.blocks.len()));
    out.push_str(&format!("  pc_split_points = {},\n", lift.guards.len()));
    out.push_str("  edges = {\n");
    out.push_str(&format!("    resolved = {},\n", lift.resolved_edges));
    out.push_str(&format!(
        "    runtime_table_jumps = {},\n",
        lift.runtime_table_jumps
    ));
    out.push_str(&format!(
        "    runtime_composite = {},\n",
        lift.runtime_composite
    ));
    out.push_str("  },\n");
    out.push_str(&format!("  const_loads = {},\n", lift.const_loads));
    out.push_str(&format!("  indirect_jumps = {},\n", lift.indirect_jumps));
    out.push_str("  opcodes = {\n");
    for (name, count) in &lift.op_counts {
        out.push_str(&format!("    [\"{name}\"] = {count},\n"));
    }
    out.push_str("  },\n");
    out.push_str("  blocks = {\n");
    for block in &lift.blocks {
        out.push_str(&format!(
            "    {{ id = {}, when = \"W < {}\", state = {{ {}, {} }}, {}, const_loads = {}, stores = {}, arith = {} }},\n",
            block.index,
            block.state_hi + 1,
            block.state_lo,
            block.state_hi,
            edge_label(&block.edge),
            block.const_loads,
            block.stores,
            block.arith_ops
        ));
    }
    out.push_str("  },\n");
    out.push_str("  guards = {\n");
    for guard in &lift.guards {
        out.push_str(&format!(
            "    {{ id = {}, when = \"W < {}\", const_loads = {}, stores = {}, direct_jumps = {}, indirect_jumps = {}, arith = {} }},\n",
            guard.index,
            guard.upper,
            guard.const_loads,
            guard.stores,
            guard.direct_jumps,
            guard.indirect_jumps,
            guard.arith_ops
        ));
    }
    out.push_str("  },\n");
    out.push_str("}\n");
    out
}

fn find_alphabet(text: &str) -> Option<BTreeMap<char, u8>> {
    let marker: &str = "local W={";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &str = &text[start..];
    let end: usize = match_brace(rest)?;
    parse_alphabet_table(&rest[..end])
}

fn find_string_array(text: &str) -> Option<&str> {
    let marker: &str = "local v={";
    let start: usize = text.find(marker)? + marker.len();
    let rest: &str = &text[start..];
    let end: usize = match_brace(rest)?;
    Some(&rest[..end])
}

fn match_brace(s: &str) -> Option<usize> {
    let bytes: &[u8] = s.as_bytes();
    let mut depth: i32 = 1;
    let mut quote: Option<u8> = None;
    let mut escaped: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == active_quote {
                quote = None;
            }
        } else {
            match b {
                b'\'' | b'"' => quote = Some(b),
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn parse_string_literals(body: &str) -> Vec<String> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote: u8 = bytes[i];
            let mut s: String = String::new();
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    let digits: String = body[i + 1..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .take(3)
                        .collect();
                    if digits.is_empty() {
                        if i + 1 < bytes.len() {
                            s.push(bytes[i + 1] as char);
                        }
                        i += 2;
                    } else {
                        if let Ok(code) = digits.parse::<u32>()
                            && let Some(c) = char::from_u32(code)
                        {
                            s.push(c);
                        }
                        i += 1 + digits.len();
                    }
                } else {
                    s.push(bytes[i] as char);
                    i += 1;
                }
            }
            out.push(s);
        }
        i += 1;
    }
    out
}

fn quote(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\{}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_string_literals_reads_single_quoted_entries() {
        let parsed: Vec<String> = parse_string_literals("'alpha',\"beta\",'\\099'");
        assert_eq!(parsed, vec!["alpha", "beta", "c"]);
    }

    #[test]
    fn match_brace_ignores_braces_inside_single_quoted_strings() {
        let body: &str = "'} not a table end',{ \"nested\" } } trailing";
        let end: Option<usize> = match_brace(body);
        assert_eq!(end, body.rfind('}'));
    }

    #[test]
    fn resolve_edge_reads_direct_constant_jump() {
        let leaf: &str = "l=#G I=p(999022-958720)W=l+P W=-777639+10951463 ";
        assert_eq!(resolve_edge(leaf, 40258), DispatchEdge::Direct(10173824));
    }

    #[test]
    fn resolve_edge_reads_two_target_conditional() {
        let leaf: &str = "h=S[G]l=h W=h and 261366+6781282 or 16114+7865728 ";
        assert_eq!(
            resolve_edge(leaf, 40258),
            DispatchEdge::Conditional {
                taken: 7042648,
                not_taken: 7881842
            }
        );
    }

    #[test]
    fn resolve_edge_flags_runtime_table_jump_with_pool_index() {
        let leaf: &str = "l={G}W=v[p(-640836+681097)]";
        assert_eq!(
            resolve_edge(leaf, 40258),
            DispatchEdge::RuntimeTableJump { pool_index: 3 }
        );
    }

    #[test]
    fn resolve_edge_flags_composite_boolean_tail() {
        let leaf: &str = "l=8283+13477653 W=W or l ";
        assert_eq!(resolve_edge(leaf, 40258), DispatchEdge::RuntimeComposite);
    }

    #[test]
    fn resolve_edge_marks_boolean_halt() {
        let leaf: &str = "W=true W=W and 734599+11596537 or 15671472-(-754120)";
        assert!(matches!(
            resolve_edge(leaf, 40258),
            DispatchEdge::Conditional { .. }
        ));
        let halt_leaf: &str = "W=true ";
        assert_eq!(resolve_edge(halt_leaf, 40258), DispatchEdge::Halt);
    }

    #[test]
    fn parse_dispatch_node_splits_binary_search_into_ranged_leaves() {
        let s: &str = "if W<100 then W=5 else W=v[p(40261-0)]end";
        let mut cursor: usize = 0;
        let mut depth: usize = 0;
        let tree: DispatchNode = parse_dispatch_node(s, &mut cursor, &mut depth).expect("parses");
        let mut leaves: Vec<(i64, i64, String)> = Vec::new();
        collect_leaf_ranges(&tree, 0, 1000, &mut leaves);
        assert_eq!(leaves.len(), 2);
        assert_eq!((leaves[0].0, leaves[0].1), (0, 99));
        assert_eq!((leaves[1].0, leaves[1].1), (100, 1000));
    }
}
