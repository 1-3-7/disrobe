use std::collections::BTreeMap;
use std::fmt::Arguments;
use std::io::Cursor;

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::arsc::{ArscEntry, ArscResources};
use crate::axml;

const RES_XML_MAGIC: [u8; 4] = [0x03, 0x00, 0x08, 0x00];
const MAX_DECODED_XML: usize = 4096;
const MAX_VALUES_ENTRIES: usize = 16384;

const VALUE_TYPE_NAMES: [&str; 6] = ["string", "color", "dimen", "bool", "integer", "fraction"];

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedResXml {
    pub path: String,
    pub xml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedValuesFile {
    pub virtual_path: String,
    pub config: String,
    pub xml: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResDecodeReport {
    pub decoded_xml: Vec<DecodedResXml>,
    pub values_files: Vec<ReconstructedValuesFile>,
    pub binary_xml_count: usize,
    pub values_resource_count: usize,
}

#[must_use]
pub fn is_binary_xml_res_path(path: &str) -> bool {
    path.starts_with("res/") && path.ends_with(".xml")
}

#[must_use]
pub fn is_res_xml_magic(head: &[u8]) -> bool {
    head.len() >= 4 && head[..4] == RES_XML_MAGIC
}

pub fn decode_archive(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    entries: &[(usize, String, u64)],
    resources: Option<&ArscResources>,
) -> ResDecodeReport {
    let mut decoded_xml: Vec<DecodedResXml> = Vec::new();
    for (index, name, _size) in entries {
        if decoded_xml.len() >= MAX_DECODED_XML {
            break;
        }
        if !is_binary_xml_res_path(name) {
            continue;
        }
        let Ok(raw) = read_entry(archive, *index) else {
            continue;
        };
        if !is_res_xml_magic(&raw) {
            continue;
        }
        let Ok(doc) = axml::parse(&raw) else {
            continue;
        };
        let xml: String = doc.to_xml_with_resources(resources);
        decoded_xml.push(DecodedResXml {
            path: name.clone(),
            xml,
        });
    }
    decoded_xml.sort_by(|a: &DecodedResXml, b: &DecodedResXml| a.path.cmp(&b.path));

    let (values_files, values_resource_count): (Vec<ReconstructedValuesFile>, usize) =
        match resources {
            Some(table) => reconstruct_values(table),
            None => (Vec::new(), 0),
        };

    ResDecodeReport {
        binary_xml_count: decoded_xml.len(),
        decoded_xml,
        values_files,
        values_resource_count,
    }
}

fn read_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
) -> crate::error::Result<Vec<u8>> {
    let f: zip::read::ZipFile<'_> = archive.by_index(index)?;
    let name: String = f.name().to_owned();
    crate::read_zip_file_bounded(f, &name)
}

fn is_value_type(type_name: &str) -> bool {
    VALUE_TYPE_NAMES.contains(&type_name)
        || matches!(
            type_name,
            "bools" | "integers" | "dimens" | "strings" | "colors" | "fractions"
        )
}

fn reconstruct_values(table: &ArscResources) -> (Vec<ReconstructedValuesFile>, usize) {
    let mut grouped: BTreeMap<(String, String), Vec<&ArscEntry>> = BTreeMap::new();
    let mut resource_count: usize = 0;
    for pkg in &table.packages {
        for entry in &pkg.entries {
            if resource_count >= MAX_VALUES_ENTRIES {
                break;
            }
            if entry.is_complex || !is_value_type(&entry.type_name) {
                continue;
            }
            let Some(value) = &entry.value else {
                continue;
            };
            if value.is_empty() && entry.type_name != "string" {
                continue;
            }
            resource_count += 1;
            grouped
                .entry((entry.config.clone(), entry.type_name.clone()))
                .or_default()
                .push(entry);
        }
    }

    let mut by_config: BTreeMap<String, Vec<(&str, &Vec<&ArscEntry>)>> = BTreeMap::new();
    for ((config, type_name), entries) in &grouped {
        by_config
            .entry(config.clone())
            .or_default()
            .push((type_name.as_str(), entries));
    }

    let mut files: Vec<ReconstructedValuesFile> = Vec::new();
    for (config, types) in &by_config {
        let mut xml: String =
            String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        for (type_name, entries) in types {
            for entry in *entries {
                write_value_element(&mut xml, type_name, entry, table);
            }
        }
        xml.push_str("</resources>\n");
        let dir: String = if config.is_empty() {
            "values".to_owned()
        } else {
            format!("values-{config}")
        };
        files.push(ReconstructedValuesFile {
            virtual_path: format!("res/{dir}/reconstructed.xml"),
            config: config.clone(),
            xml,
        });
    }
    (files, resource_count)
}

fn write_value_element(
    mut out: &mut String,
    type_name: &str,
    entry: &ArscEntry,
    table: &ArscResources,
) {
    let value: &str = entry.value.as_deref().unwrap_or_default();
    let resolved: String = resolve_value(value, table);
    let element: &str = element_name_for(type_name);
    push_line!(
        out,
        "    <{element} name=\"{}\">{}</{element}>",
        escape_attr(&entry.key_name),
        escape_text(&resolved)
    );
}

fn element_name_for(type_name: &str) -> &str {
    match type_name {
        "string" | "strings" => "string",
        "color" | "colors" => "color",
        "dimen" | "dimens" => "dimen",
        "bool" | "bools" => "bool",
        "integer" | "integers" => "integer",
        "fraction" | "fractions" => "fraction",
        other => other,
    }
}

fn resolve_value(value: &str, table: &ArscResources) -> String {
    if let Some(hex) = value.strip_prefix("@0x")
        && let Ok(id) = u32::from_str_radix(hex, 16)
        && let Some(name) = table.resolve(id)
    {
        return format!("@{name}");
    }
    if let Some(hex) = value.strip_prefix("?0x")
        && let Ok(id) = u32::from_str_radix(hex, 16)
        && let Some(name) = table.resolve(id)
    {
        return format!("?{name}");
    }
    value.to_owned()
}

fn escape_attr(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_text(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn binary_xml_path_predicate() {
        assert!(is_binary_xml_res_path("res/layout/main.xml"));
        assert!(is_binary_xml_res_path(
            "res/xml/network_security_config.xml"
        ));
        assert!(!is_binary_xml_res_path("res/drawable/icon.png"));
        assert!(!is_binary_xml_res_path("assets/foo.xml"));
        assert!(!is_binary_xml_res_path("AndroidManifest.xml"));
    }

    #[test]
    fn res_xml_magic_recognised() {
        assert!(is_res_xml_magic(&[0x03, 0x00, 0x08, 0x00, 0x10]));
        assert!(!is_res_xml_magic(&[0x02, 0x00, 0x0c, 0x00]));
        assert!(!is_res_xml_magic(&[0x03, 0x00]));
    }

    #[test]
    fn element_name_mapping() {
        assert_eq!(element_name_for("string"), "string");
        assert_eq!(element_name_for("colors"), "color");
        assert_eq!(element_name_for("dimens"), "dimen");
    }
}
