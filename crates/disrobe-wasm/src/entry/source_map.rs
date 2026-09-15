use disrobe_pass_js_deob::{
    RecoverOptions, RecoveredFile, RecoveryReport, SourceMap, SourceMapInfo, SourceMapLimits,
    decode_data_url_json, find_source_map, parse_source_map_with_limits, recover_source_map,
};
use serde::Serialize;

const INPUT_BYTES: usize = 1024 * 1024;
const LIMITS: SourceMapLimits = SourceMapLimits {
    input_bytes: INPUT_BYTES,
    sources: 4096,
    names: 16_384,
    sections: 1024,
    depth: 16,
    generated_lines: 65_536,
    mapping_segments: 65_536,
    content_bytes: INPUT_BYTES,
    path_bytes: INPUT_BYTES,
};

#[derive(Debug, Serialize)]
struct SourceFile {
    path: String,
    source: String,
    ignored: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum Recovery {
    Recovered {
        generated_file: Option<String>,
        source_root: Option<String>,
        total_sources: usize,
        embedded_sources: usize,
        missing_sources: Vec<String>,
        mapped_segments: usize,
        names: Vec<String>,
        files: Vec<SourceFile>,
    },
    ExternalReference {
        url: String,
    },
    NoMap,
}

#[derive(Debug, Serialize)]
pub struct SourceMapResult {
    ok: bool,
    format: &'static str,
    #[serde(flatten)]
    recovery: Recovery,
}

pub fn source_map_recover(bytes: &[u8]) -> Result<SourceMapResult, String> {
    if bytes.len() > INPUT_BYTES {
        return Err("Source-map recovery accepts inputs up to 1 MiB.".to_owned());
    }
    let source: &str = std::str::from_utf8(bytes)
        .map_err(|_| "Source-map recovery requires UTF-8 text.".to_owned())?;
    let trimmed: &str = source.trim_start_matches('\u{feff}').trim_start();
    let reference: Option<SourceMapInfo> = if trimmed.starts_with("data:") {
        Some(SourceMapInfo {
            url: trimmed.trim().to_owned(),
            inline: true,
        })
    } else {
        find_source_map(source)
    };
    let json_input: bool = trimmed.starts_with(")]}'")
        || (trimmed.starts_with('{')
            && (reference.is_none()
                || serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_ok()));
    let recovery: Recovery = if json_input {
        recover_json(source)?
    } else {
        match reference {
            Some(reference) if reference.inline => {
                let json: String =
                    decode_data_url_json(&reference.url).map_err(|error| error.to_string())?;
                recover_json(&json)?
            }
            Some(reference) => Recovery::ExternalReference { url: reference.url },
            None => Recovery::NoMap,
        }
    };
    Ok(SourceMapResult {
        ok: true,
        format: "source-map",
        recovery,
    })
}

fn recover_json(source: &str) -> Result<Recovery, String> {
    let map: SourceMap =
        parse_source_map_with_limits(source, LIMITS).map_err(|error| error.to_string())?;
    let report: RecoveryReport = recover_source_map(&map, RecoverOptions { emit_stubs: false });
    let missing_sources: Vec<String> = map
        .sources
        .iter()
        .enumerate()
        .filter(|(index, _)| map.sources_content.get(*index).is_none_or(Option::is_none))
        .map(|(_, name): (usize, &String)| name.clone())
        .collect();
    let files: Vec<SourceFile> = report
        .files
        .into_iter()
        .map(|file: RecoveredFile| {
            String::from_utf8(file.bytes)
                .map(|source: String| SourceFile {
                    path: file.relative_path,
                    source,
                    ignored: file.ignored,
                })
                .map_err(|_| "Recovered source is not valid UTF-8.".to_owned())
        })
        .collect::<Result<Vec<SourceFile>, String>>()?;
    Ok(Recovery::Recovered {
        generated_file: report.file,
        source_root: report.source_root,
        total_sources: report.total_sources,
        embedded_sources: report.with_content,
        missing_sources,
        mapped_segments: report.mapped_segments,
        names: map.names,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::{INPUT_BYTES, Recovery, source_map_recover};

    #[test]
    fn source_maps_preserve_empty_and_missing_content() -> Result<(), String> {
        let result = source_map_recover(br#"{"version":3,"sources":["empty.ts","missing.ts"],"sourcesContent":["",null],"names":[],"mappings":""}"#)?;
        let Recovery::Recovered {
            files,
            total_sources,
            embedded_sources,
            missing_sources,
            ..
        } = result.recovery
        else {
            return Err("expected recovered map".to_owned());
        };
        assert_eq!((total_sources, embedded_sources), (2, 1));
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "empty.ts");
        assert!(files[0].source.is_empty());
        assert_eq!(missing_sources, ["missing.ts"]);
        Ok(())
    }

    #[test]
    fn source_map_references_never_resolve_implicitly() {
        let result = source_map_recover(b"throw new Error('must not run');\n//# sourceMappingURL=https://example.invalid/app.js.map");
        assert!(
            matches!(result, Ok(super::SourceMapResult { recovery: Recovery::ExternalReference { url }, .. }) if url == "https://example.invalid/app.js.map")
        );
        assert!(matches!(
            source_map_recover(b"throw new Error('must not run')"),
            Ok(super::SourceMapResult {
                recovery: Recovery::NoMap,
                ..
            })
        ));
    }

    #[test]
    fn block_leading_javascript_can_carry_a_source_map() {
        let source: &[u8] = b"{ const value = 1; }\n//# sourceMappingURL=data:application/json,%7B%22version%22%3A3%2C%22sources%22%3A%5B%5D%2C%22mappings%22%3A%22%22%7D";
        assert!(matches!(
            source_map_recover(source),
            Ok(super::SourceMapResult {
                recovery: Recovery::Recovered {
                    total_sources: 0,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn source_map_entry_rejects_invalid_inputs() {
        for bytes in [
            vec![0xff],
            vec![b'a'; INPUT_BYTES + 1],
            b"{broken".to_vec(),
            b"data:application/json,%ff".to_vec(),
        ] {
            assert!(source_map_recover(&bytes).is_err());
        }
    }
}
