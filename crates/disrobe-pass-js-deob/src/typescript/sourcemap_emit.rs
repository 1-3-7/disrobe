use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceMapEmitResult {
    pub emitted: String,
    pub baked_url: Option<String>,
}

#[must_use]
pub fn emit_ts_with_source_map(ts: &str, map_url: Option<&str>) -> SourceMapEmitResult {
    fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
        let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
        if let Err(error) = result {
            unreachable!("string formatting failed: {error}");
        }
    }

    let mut out: String = String::with_capacity(ts.len() + 128);
    out.push_str(ts);
    if !ts.ends_with('\n') {
        out.push('\n');
    }
    if let Some(url) = map_url {
        push_format(&mut out, format_args!("//# sourceMappingURL={url}\n"));
        return SourceMapEmitResult {
            emitted: out,
            baked_url: Some(url.to_owned()),
        };
    }
    SourceMapEmitResult {
        emitted: out,
        baked_url: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bakes_source_map_url_when_given() {
        let r: SourceMapEmitResult =
            emit_ts_with_source_map("const a: number = 1;", Some("a.ts.map"));
        assert!(r.emitted.contains("//# sourceMappingURL=a.ts.map"));
        assert_eq!(r.baked_url.as_deref(), Some("a.ts.map"));
    }

    #[test]
    fn no_map_no_directive() {
        let r: SourceMapEmitResult = emit_ts_with_source_map("const a: number = 1;", None);
        assert!(!r.emitted.contains("sourceMappingURL"));
    }
}
