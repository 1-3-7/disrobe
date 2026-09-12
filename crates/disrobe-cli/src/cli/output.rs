#![allow(clippy::print_stdout)]
use std::io::{Seek as _, Write as _};

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Sarif,
}

impl OutputFormat {
    pub(crate) const fn from_flags(json: bool, ndjson: bool, sarif: bool) -> Self {
        if sarif {
            Self::Sarif
        } else if ndjson {
            Self::Ndjson
        } else if json {
            Self::Json
        } else {
            Self::Text
        }
    }

    pub(crate) const fn is_machine(self) -> bool {
        !matches!(self, Self::Text)
    }
}

pub(crate) fn write_json<W: std::io::Write, T: serde::Serialize>(
    writer: W,
    value: &T,
    pretty: bool,
) -> serde_json::Result<()> {
    if pretty {
        serde_json::to_writer_pretty(writer, value)
    } else {
        serde_json::to_writer(writer, value)
    }
}

fn write_stdout_json<T: serde::Serialize>(
    value: &T,
    pretty: bool,
    serialization_code: &'static str,
    serialization_context: &'static str,
) -> miette::Result<()> {
    let stdout: std::io::Stdout = std::io::stdout();
    let mut h: std::io::StdoutLock<'_> = stdout.lock();
    write_json(&mut h, value, pretty).map_err(|error: serde_json::Error| {
        if error.is_io() {
            miette::miette!("DR-CLI-0092: stdout write: {error}")
        } else {
            miette::miette!("{serialization_code}: {serialization_context}: {error}")
        }
    })?;
    h.write_all(b"\n")
        .map_err(|error: std::io::Error| miette::miette!("DR-CLI-0092: stdout write: {error}"))?;
    Ok(())
}

pub(crate) fn emit<T: serde::Serialize, F: FnOnce()>(
    fmt: OutputFormat,
    value: &T,
    text_fallback: F,
) -> miette::Result<()> {
    match fmt {
        OutputFormat::Text => {
            text_fallback();
            Ok(())
        }
        OutputFormat::Json => write_stdout_json(value, true, "DR-CLI-0091", "json serialize"),
        OutputFormat::Ndjson => write_stdout_json(value, false, "DR-CLI-0091", "ndjson serialize"),
        OutputFormat::Sarif => emit_sarif(value),
    }
}

pub(crate) fn emit_sarif_log(log: &crate::cli::sarif::SarifLog) -> miette::Result<()> {
    write_stdout_json(log, true, "DR-CLI-0094", "sarif envelope serialize")
}

fn emit_sarif<T: serde::Serialize>(value: &T) -> miette::Result<()> {
    use crate::cli::sarif::{Driver, SarifLog};
    let (scratch, mut spool): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create("sarif-stream", "json").map_err(
            |error: std::io::Error| miette::miette!("DR-CLI-0093: sarif spool: {error}"),
        )?;
    write_json(&mut spool, value, false).map_err(|error: serde_json::Error| {
        miette::miette!("DR-CLI-0093: sarif inner serialize: {error}")
    })?;
    spool
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error: std::io::Error| miette::miette!("DR-CLI-0093: sarif spool: {error}"))?;
    let results: Vec<crate::cli::sarif::SarifResult> = sarif_results_from_reader(&mut spool)
        .map_err(|error: serde_json::Error| {
            miette::miette!("DR-CLI-0093: sarif inner deserialize: {error}")
        })?;
    drop(spool);
    scratch
        .close()
        .map_err(|error: std::io::Error| miette::miette!("DR-CLI-0093: sarif spool: {error}"))?;
    let log: SarifLog = SarifLog::new(Driver::disrobe(Vec::new()), results);
    emit_sarif_log(&log)
}

#[derive(Debug, Default)]
struct SarifPayload {
    findings: Vec<serde_json::Value>,
}

impl<'de> Deserialize<'de> for SarifPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SarifPayloadVisitor;

        impl<'de> Visitor<'de> for SarifPayloadVisitor {
            type Value = SarifPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a report payload")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let mut payload: SarifPayload = SarifPayload::default();
                while let Some(key) = access.next_key::<String>()? {
                    let key: String = key;
                    if key == "findings" {
                        let findings: Option<Vec<serde_json::Value>> = access.next_value()?;
                        payload.findings = findings.unwrap_or_default();
                    } else {
                        let _: IgnoredAny = access.next_value()?;
                    }
                }
                Ok(payload)
            }

            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(SarifPayload::default())
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_string<E: serde::de::Error>(self, _: String) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(SarifPayload::default())
            }
        }

        deserializer.deserialize_any(SarifPayloadVisitor)
    }
}

fn sarif_results_from_reader<R: std::io::Read>(
    reader: R,
) -> serde_json::Result<Vec<crate::cli::sarif::SarifResult>> {
    use crate::cli::sarif::{
        ArtifactLocation, Location, Message, PhysicalLocation, SarifLevel, SarifResult,
    };
    let payload: SarifPayload = serde_json::from_reader(reader)?;
    let results: Vec<SarifResult> = payload
        .findings
        .into_iter()
        .map(|finding: serde_json::Value| {
            let rule_id: String = finding
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("DR-UNKNOWN")
                .to_owned();
            let text: String = finding
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("disrobe finding")
                .to_owned();
            let level: SarifLevel = match finding.get("level").and_then(serde_json::Value::as_str) {
                Some("error") => SarifLevel::Error,
                Some("warning") => SarifLevel::Warning,
                Some(_) | None => SarifLevel::Note,
            };
            let region: Option<crate::cli::sarif::Region> = finding
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .map(crate::cli::sarif::Region::at_byte_offset);
            let locations: Vec<Location> = finding
                .get("uri")
                .and_then(serde_json::Value::as_str)
                .map(|uri: &str| {
                    vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation::at(uri.to_owned()),
                            region,
                        },
                    }]
                })
                .unwrap_or_default();
            SarifResult {
                rule_id,
                kind: None,
                level,
                message: Message { text },
                locations,
                properties: None,
            }
        })
        .collect();
    Ok(results)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use std::io::SeekFrom;

    use serde::ser::{SerializeSeq, Serializer};

    struct BoundedWrite {
        largest: usize,
        total: usize,
    }

    struct RepeatedRows(usize);

    impl serde::Serialize for RepeatedRows {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut sequence: S::SerializeSeq = serializer.serialize_seq(Some(self.0))?;
            for index in 0..self.0 {
                sequence.serialize_element(&index)?;
            }
            sequence.end()
        }
    }

    #[derive(serde::Serialize)]
    struct SarifFixture {
        rows: RepeatedRows,
        findings: [serde_json::Value; 1],
    }

    impl std::io::Write for BoundedWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.len() > 64 {
                return Err(std::io::Error::other(
                    "serializer buffered the complete value",
                ));
            }
            self.largest = self.largest.max(buf.len());
            self.total += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_is_written_incrementally_instead_of_buffering_the_complete_value() {
        let value: Vec<String> = (0..10_000_usize)
            .map(|index: usize| format!("row-{index:08}"))
            .collect();
        let mut writer: BoundedWrite = BoundedWrite {
            largest: 0,
            total: 0,
        };
        write_json(&mut writer, &value, true).expect("stream JSON");
        assert!(writer.total > 100_000, "{}", writer.total);
        assert!(writer.largest <= 64, "{}", writer.largest);
    }

    #[test]
    fn sarif_reads_only_findings_from_a_streamed_large_payload() {
        let fixture: SarifFixture = SarifFixture {
            rows: RepeatedRows(200_000),
            findings: [serde_json::json!({
                "code": "DR-TEST-0001",
                "message": "bounded",
                "level": "warning",
                "offset": 17,
                "uri": "sample.bin"
            })],
        };
        let mut spool: std::fs::File = tempfile::tempfile().expect("anonymous spool");
        write_json(&mut spool, &fixture, false).expect("stream fixture");
        spool.seek(SeekFrom::Start(0)).expect("rewind fixture");
        let results: Vec<crate::cli::sarif::SarifResult> =
            sarif_results_from_reader(spool).expect("extract findings");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "DR-TEST-0001");
        assert_eq!(results[0].message.text, "bounded");
    }

    #[test]
    fn sarif_keeps_non_object_payloads_as_empty_logs() {
        let results: Vec<crate::cli::sarif::SarifResult> =
            sarif_results_from_reader(std::io::Cursor::new(b"[1,2,3]"))
                .expect("ignore non-object payload");
        assert!(results.is_empty());
    }
}
