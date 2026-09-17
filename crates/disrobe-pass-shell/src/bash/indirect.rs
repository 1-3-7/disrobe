use std::io::Read;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;
use crate::policy::DynamicPolicy;

const MAX_PEEL_ROUNDS: usize = 32;
const MAX_PEELED_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_GZIP_OUTPUT: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct IndirectionReport {
    pub steps: Vec<String>,
    pub output: String,
    pub eval_depth: usize,
    pub walls: Vec<String>,
}

static IFS_INDIRECT: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r"\$\{?IFS\}?"));

static PRINTF_HEX: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"printf\s+(?:'((?:\\x[0-9A-Fa-f]{2})+)'|"((?:\\x[0-9A-Fa-f]{2})+)")"#,
    )
});

static B64_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?m)echo\s+(?:'([A-Za-z0-9+/=]+)'|"([A-Za-z0-9+/=]+)"|([A-Za-z0-9+/=]+))\s*\|\s*base64\s+(?:-d|--decode)"#,
    )
});

static B64_GZIP: LazyLock<Regex> = LazyLock::new(|| {
    crate::regex_util::safe_regex(
        r#"(?m)echo\s+(?:'([A-Za-z0-9+/=]+)'|"([A-Za-z0-9+/=]+)"|([A-Za-z0-9+/=]+))\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:gzip|gunzip|zcat)\s*-d"#,
    )
});

static EVAL_WRAP: LazyLock<Regex> =
    LazyLock::new(|| crate::regex_util::safe_regex(r#"(?s)\beval\s+(?:'(.*?)'|"(.*?)")"#));

pub fn peel_indirection(input: &str) -> Result<IndirectionReport> {
    peel_indirection_with_policy(input, DynamicPolicy::default())
}

pub fn peel_indirection_with_policy(
    input: &str,
    policy: DynamicPolicy,
) -> Result<IndirectionReport> {
    let mut steps: Vec<String> = Vec::new();
    let mut walls: Vec<String> = Vec::new();
    let mut eval_depth: usize = 0;
    let mut current: String = input.to_owned();
    let mut engine: super::decode::EvalEnv =
        super::decode::EvalEnv::with_eval_cap(policy.max_eval_depth());
    let decoded: super::decode::DecodeResult = super::decode::evaluate(&current, &mut engine);
    if !engine.steps.is_empty() {
        current = decoded.output;
        steps.extend(engine.steps.iter().cloned());
        walls.extend(engine.walls.iter().cloned());
        eval_depth = eval_depth.max(engine.eval_depth);
    }
    let mut rounds: usize = 0;
    loop {
        if rounds >= MAX_PEEL_ROUNDS {
            walls.push(format!(
                "indirection peeling stopped after {MAX_PEEL_ROUNDS} rounds"
            ));
            break;
        }
        rounds += 1;
        let before: String = current.clone();
        peel_non_eval_layers(&mut current, &mut steps)?;
        if current.len() > MAX_PEELED_OUTPUT {
            walls.push(format!(
                "indirection output exceeds {MAX_PEELED_OUTPUT}-byte ceiling; peeling halted"
            ));
            break;
        }
        if !EVAL_WRAP.is_match(&current) {
            if current == before {
                break;
            }
            continue;
        }
        let next_depth: usize = eval_depth + 1;
        if !policy.permits_depth(next_depth) {
            walls.push(format!(
                "eval depth {next_depth} exceeds static cap {}; re-run with --allow-dynamic to peel further",
                policy.max_eval_depth()
            ));
            break;
        }
        let snapshot: String = current.clone();
        let Some(cap): Option<regex::Captures<'_>> = EVAL_WRAP.captures(&snapshot) else {
            break;
        };
        let body: &str = first_capture(&cap, &[1usize, 2usize]);
        if body.is_empty() {
            break;
        }
        current = EVAL_WRAP
            .replace(&current, regex::NoExpand(body))
            .into_owned();
        eval_depth = next_depth;
        steps.push("strip-eval".to_owned());
    }
    Ok(IndirectionReport {
        steps,
        output: current,
        eval_depth,
        walls,
    })
}

fn peel_non_eval_layers(current: &mut String, steps: &mut Vec<String>) -> Result<()> {
    if IFS_INDIRECT.is_match(current) {
        *current = IFS_INDIRECT.replace_all(current, " ").into_owned();
        steps.push("substitute-ifs".to_owned());
    }
    let printed: std::borrow::Cow<'_, str> =
        PRINTF_HEX.replace_all(current, |c: &regex::Captures<'_>| {
            let raw: &str = first_capture(c, &[1usize, 2usize]);
            decode_printf_hex(raw)
        });
    if printed != *current {
        steps.push("printf-hex-decode".to_owned());
        *current = printed.into_owned();
    }
    if let Some(cap) = B64_GZIP.captures(current) {
        let blob: &str = first_capture(&cap, &[1usize, 2usize, 3usize]);
        if !blob.is_empty() {
            let raw: Vec<u8> = BASE64_STD.decode(blob)?;
            steps.push("base64-decode".to_owned());
            let reserve: usize = raw.len().saturating_mul(4).min(MAX_GZIP_OUTPUT as usize);
            let dec: GzDecoder<&[u8]> = GzDecoder::new(&raw[..]);
            let mut out: Vec<u8> = Vec::with_capacity(reserve);
            let produced: u64 = dec
                .take(MAX_GZIP_OUTPUT.saturating_add(1))
                .read_to_end(&mut out)
                .map(|n: usize| n as u64)?;
            if produced > MAX_GZIP_OUTPUT {
                steps.push("gzip-inflate-capped".to_owned());
                out.truncate(MAX_GZIP_OUTPUT as usize);
            } else {
                steps.push("gzip-inflate".to_owned());
            }
            *current = String::from_utf8_lossy(&out).into_owned();
        }
    } else if let Some(cap) = B64_PIPE.captures(current) {
        let blob: &str = first_capture(&cap, &[1usize, 2usize, 3usize]);
        if !blob.is_empty() {
            let raw: Vec<u8> = BASE64_STD.decode(blob)?;
            steps.push("base64-decode".to_owned());
            *current = String::from_utf8_lossy(&raw).into_owned();
        }
    }
    Ok(())
}

use crate::regex_util::first_capture;

fn decode_printf_hex(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() / 4);
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            let hex: &str = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::STATIC_EVAL_DEPTH_CAP;

    #[test]
    fn substitutes_ifs_tokens() -> Result<()> {
        let r: IndirectionReport = peel_indirection("c${IFS}a${IFS}t /etc/passwd")?;
        assert!(r.output.contains("c a t"));
        Ok(())
    }

    #[test]
    fn decodes_printf_hex() -> Result<()> {
        let r: IndirectionReport = peel_indirection(r#"printf '\x68\x69'"#)?;
        assert!(r.output.contains("hi"));
        Ok(())
    }

    #[test]
    fn decodes_echo_base64_pipe() -> Result<()> {
        let payload: &str = "uname -a";
        let b64: String = BASE64_STD.encode(payload);
        let src: String = format!("echo '{b64}' | base64 -d");
        let r: IndirectionReport = peel_indirection(&src)?;
        assert!(r.output.contains(payload));
        Ok(())
    }

    fn nested_b64_eval(depth: usize) -> String {
        let mut inner: String = "id".to_owned();
        for _ in 0..depth {
            let b64: String = BASE64_STD.encode(&inner);
            inner = format!("eval 'echo {b64} | base64 -d'");
        }
        inner
    }

    #[test]
    fn static_policy_stops_at_eval_depth_two() -> Result<()> {
        let src: String = nested_b64_eval(4);
        let r: IndirectionReport = peel_indirection(&src)?;
        assert_eq!(r.eval_depth, 2, "eval_depth={}", r.eval_depth);
        assert!(
            !r.walls.is_empty(),
            "deeply nested eval must record a static-cap wall; out={}",
            r.output
        );
        assert!(
            r.output.contains("eval"),
            "layers should remain unpeeled under static cap; out={}",
            r.output
        );
        Ok(())
    }

    #[test]
    fn allow_dynamic_peels_past_two() -> Result<()> {
        let src: String = nested_b64_eval(4);
        let r: IndirectionReport = peel_indirection_with_policy(&src, DynamicPolicy::AllowDynamic)?;
        assert!(
            r.eval_depth > STATIC_EVAL_DEPTH_CAP,
            "allow-dynamic must peel past the static cap; eval_depth={}",
            r.eval_depth
        );
        assert!(r.output.contains("id"), "out={}", r.output);
        assert!(r.walls.is_empty());
        Ok(())
    }

    #[test]
    fn single_eval_layer_peels_under_static() -> Result<()> {
        let r: IndirectionReport = peel_indirection(r#"eval 'whoami'"#)?;
        assert_eq!(r.eval_depth, 1);
        assert!(r.output.contains("whoami"));
        assert!(r.walls.is_empty());
        Ok(())
    }

    #[test]
    fn gzip_bomb_in_pipe_is_capped_not_oom() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let bomb: Vec<u8> = vec![b'A'; (MAX_GZIP_OUTPUT as usize) + (4 * 1024 * 1024)];
        let mut gz: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(&bomb)?;
        let compressed: Vec<u8> = gz.finish()?;
        let b64: String = BASE64_STD.encode(&compressed);
        let src: String = format!("echo '{b64}' | base64 -d | gzip -d");
        let r: IndirectionReport = peel_indirection(&src)?;
        assert!(
            r.output.len() <= MAX_GZIP_OUTPUT as usize,
            "output {} exceeds cap",
            r.output.len()
        );
        assert!(r.steps.contains(&"gzip-inflate-capped".to_owned()));
        Ok(())
    }

    #[test]
    fn output_ceiling_halts_peeling() -> Result<()> {
        let mut huge: String = "a".repeat(MAX_PEELED_OUTPUT + 16);
        huge.push_str("${IFS}b");
        let r: IndirectionReport = peel_indirection(&huge)?;
        assert!(
            r.walls.iter().any(|w: &String| w.contains("ceiling")),
            "expected an output-ceiling wall; walls={:?}",
            r.walls
        );
        Ok(())
    }
}
