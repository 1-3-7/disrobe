use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::obfuscator::string_decode::{
    apply_permutation, decode_base64_variant, eval_arith_expr, parse_alphabet_table,
    parse_permutation_table,
};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

#[derive(Debug, Clone, PartialEq, Eq)]
enum DispatchOp {
    ConstLoad,
    Store,
    DirectJump,
    IndirectJump,
    Arith,
}

#[derive(Debug, Clone)]
struct DispatchLift {
    pc_thresholds: Vec<i64>,
    op_counts: BTreeMap<&'static str, usize>,
    indirect_jumps: usize,
    const_loads: usize,
}

const MARKERS: &[&[u8]] = &[
    b"-- WeAreDevs",
    b"WRD_OBFUSCATOR",
    b"wearedevs_luau",
    b"wearedevs.net/obfuscator",
    b"https://wearedevs.net",
];

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if windowed_contains(src, m) {
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
    let prelude_match: bool = windowed_contains(head, b"return(function(...)local v={")
        || windowed_contains(head, b"return (function(...) local v = {");
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
            "wearedevs vm: {} indirect jumps (W=v[p(k)]) are data-dependent -- partial CFG",
            lift.indirect_jumps
        ));
        residual_markers.push(
            "wearedevs vm: opcode/dispatch stream lifted; full source reconstruction partial"
                .to_owned(),
        );
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
    let start: usize = text.find(marker)? + marker.len();
    let body: &str = &text[start..];

    let mut pc_thresholds: Vec<i64> = Vec::new();
    for cut in body.match_indices("if W<").map(|(i, _): (usize, &str)| i) {
        let after: &str = &body[cut + "if W<".len()..];
        let expr_end: usize = after.find("then").unwrap_or(after.len());
        if let Some(value) = eval_arith_expr(&after[..expr_end]) {
            pc_thresholds.push(value);
        }
    }
    if pc_thresholds.is_empty() {
        return None;
    }

    let indirect_jumps: usize = count_occurrences(body, "W=v[p(");
    let const_loads: usize = count_const_loads(body);
    let stores: usize = count_store_ops(body);
    let direct_jumps: usize = count_direct_jumps(body);
    let arith_ops: usize = count_arith_ops(body);

    let mut op_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    op_counts.insert(classify(&DispatchOp::ConstLoad), const_loads);
    op_counts.insert(classify(&DispatchOp::Store), stores);
    op_counts.insert(classify(&DispatchOp::DirectJump), direct_jumps);
    op_counts.insert(classify(&DispatchOp::IndirectJump), indirect_jumps);
    op_counts.insert(classify(&DispatchOp::Arith), arith_ops);

    Some(DispatchLift {
        pc_thresholds,
        op_counts,
        indirect_jumps,
        const_loads,
    })
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

fn render_dispatch(lift: &DispatchLift) -> String {
    let mut out: String = String::new();
    out.push_str("local DISPATCH = {\n");
    out.push_str(&format!(
        "  pc_split_points = {},\n",
        lift.pc_thresholds.len()
    ));
    out.push_str(&format!("  const_loads = {},\n", lift.const_loads));
    out.push_str(&format!("  indirect_jumps = {},\n", lift.indirect_jumps));
    out.push_str("  opcodes = {\n");
    for (name, count) in &lift.op_counts {
        out.push_str(&format!("    {name} = {count},\n"));
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
    let mut in_string: bool = false;
    let mut escaped: bool = false;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
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
        if bytes[i] == b'"' {
            let mut s: String = String::new();
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
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

fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}
