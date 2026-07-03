use std::path::PathBuf;

use disrobe_core::strings::{self, ExtractedString, Options, StringsReport};
use disrobe_pass_native::{EmulatedString, emulate_string_decoders};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};
use crate::cli::progress_ui::StageSpinner;

#[derive(Debug, Serialize)]
struct StringsWithEmulation {
    #[serde(flatten)]
    static_report: StringsReport,
    emulated_decoded: Vec<EmulatedString>,
}

pub(crate) fn run(
    path: PathBuf,
    min_len: usize,
    no_decode: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if min_len == 0 {
        return Err(miette::miette!("DR-STR-0049: --min-len must be at least 1"));
    }
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-STR-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let opts: Options = Options {
        min_len,
        decode: !no_decode,
    };
    let static_report: StringsReport = strings::report(&bytes, Some(&uri), opts);
    let emulated_decoded: Vec<EmulatedString> = if no_decode {
        Vec::new()
    } else {
        let label: String = path.display().to_string();
        let spinner: StageSpinner = StageSpinner::start(&label, "emulating string decoders");
        let decoded: Vec<EmulatedString> =
            deduplicate_against_static(emulate_string_decoders(&bytes), &static_report);
        spinner.finish(&format!("{} emulated strings", decoded.len()));
        decoded
    };

    let combined: StringsWithEmulation = StringsWithEmulation {
        static_report,
        emulated_decoded,
    };
    output::emit(fmt, &combined, || {
        if combined.static_report.strings.is_empty() {
            println!("no strings found");
        } else {
            for s in &combined.static_report.strings {
                println!(
                    "{}\t@{}\t{}",
                    s.tagging.label(),
                    s.offset,
                    sanitize(&s.value)
                );
            }
            println!("\n{} string(s)", combined.static_report.total);
        }
        if !combined.emulated_decoded.is_empty() {
            println!("\nemulation-recovered (decoder execution):");
            for e in &combined.emulated_decoded {
                println!(
                    "emu-decoded\t@decoder=0x{:x}\t@buffer=0x{:x}\t{}",
                    e.decoder_address,
                    e.source_buffer_address,
                    sanitize(&e.value)
                );
            }
            println!(
                "{} emulation-recovered string(s)",
                combined.emulated_decoded.len()
            );
        }
    })
}

fn deduplicate_against_static(
    emulated: Vec<EmulatedString>,
    static_report: &StringsReport,
) -> Vec<EmulatedString> {
    emulated
        .into_iter()
        .filter(|e: &EmulatedString| {
            !static_report
                .strings
                .iter()
                .any(|s: &ExtractedString| s.value == e.value)
        })
        .collect()
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c: char| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_control_whitespace() {
        assert_eq!(sanitize("a\nb\tc"), "a b c");
    }

    #[test]
    fn report_has_tagged_strings() {
        let report: StringsReport = strings::report(
            b"\x00hello world kernel\x00",
            Some("a.bin"),
            Options::default(),
        );
        let labels: Vec<String> = report
            .strings
            .iter()
            .map(|s: &ExtractedString| s.tagging.label())
            .collect();
        assert!(labels.iter().any(|l: &String| l == "plain"), "{labels:?}");
    }

    #[test]
    fn dedup_drops_strings_already_in_static_set() {
        let report: StringsReport = strings::report(
            b"\x00already-present-string\x00",
            Some("a.bin"),
            Options::default(),
        );
        let already: String = report
            .strings
            .first()
            .map(|s: &ExtractedString| s.value.clone())
            .unwrap_or_default();
        let emulated: Vec<EmulatedString> = vec![
            EmulatedString {
                value: already.clone(),
                decoder_address: 0x1000,
                source_buffer_address: 0x2000,
                output_address: 0x3000,
                exit: "ret".to_owned(),
            },
            EmulatedString {
                value: "only-from-emulation".to_owned(),
                decoder_address: 0x1000,
                source_buffer_address: 0x2000,
                output_address: 0x3000,
                exit: "ret".to_owned(),
            },
        ];
        let kept: Vec<EmulatedString> = deduplicate_against_static(emulated, &report);
        assert!(
            kept.iter().all(|e: &EmulatedString| e.value != already),
            "a string already in the static set must not be re-reported as emulation-only"
        );
        assert!(
            kept.iter()
                .any(|e: &EmulatedString| e.value == "only-from-emulation"),
            "an emulation-only string must survive deduplication"
        );
    }
}
