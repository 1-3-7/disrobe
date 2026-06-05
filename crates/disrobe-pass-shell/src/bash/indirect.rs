use std::io::Read;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Serialize;

use crate::error::Result;
use crate::policy::DynamicPolicy;

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

/// Statically peel one bash indirection layer under the default static-only policy.
pub fn peel_indirection(input: &str) -> Result<IndirectionReport> {
    peel_indirection_with_policy(input, DynamicPolicy::default())
}

/// Iteratively peel nested bash indirection up to the [`DynamicPolicy`] eval-depth cap.
pub fn peel_indirection_with_policy(
    input: &str,
    policy: DynamicPolicy,
) -> Result<IndirectionReport> {
    let mut steps: Vec<String> = Vec::new();
    let mut walls: Vec<String> = Vec::new();
    let mut current: String = input.to_owned();
    let mut eval_depth: usize = 0;
    loop {
        let before: String = current.clone();
        peel_non_eval_layers(&mut current, &mut steps)?;
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
            let mut dec: GzDecoder<&[u8]> = GzDecoder::new(&raw[..]);
            let mut out: Vec<u8> = Vec::with_capacity(raw.len() * 4);
            dec.read_to_end(&mut out)?;
            steps.push("gzip-inflate".to_owned());
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

    /// Builds a base64-then-eval onion of the given depth.
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
}
