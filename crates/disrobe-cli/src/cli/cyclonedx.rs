use serde::Serialize;

use disrobe_pass_native::AuditableCrate;

const BOM_FORMAT: &str = "CycloneDX";
const SPEC_VERSION: &str = "1.5";
const BOM_VERSION: u32 = 1;
const TOOL_NAME: &str = "disrobe";
const SHA256_ALG: &str = "SHA-256";
const BLAKE3_ALG: &str = "BLAKE3";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CycloneDxBom {
    pub(crate) bom_format: &'static str,
    pub(crate) spec_version: &'static str,
    pub(crate) version: u32,
    pub(crate) metadata: Metadata,
    pub(crate) components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) timestamp: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Tool {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ComponentType {
    Library,
    Application,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub(crate) struct Component {
    #[serde(rename = "type")]
    pub(crate) component_type: ComponentType,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purl: Option<String>,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub(crate) bom_ref: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) hashes: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Hash {
    pub(crate) alg: &'static str,
    pub(crate) content: String,
}

impl Tool {
    #[inline]
    pub(crate) const fn disrobe() -> Self {
        Self {
            name: TOOL_NAME,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[inline]
fn cargo_purl(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

pub(crate) fn component_from_crate(krate: &AuditableCrate) -> Component {
    let purl: String = cargo_purl(&krate.name, &krate.version);
    Component {
        component_type: ComponentType::Library,
        name: krate.name.clone(),
        version: Some(krate.version.clone()),
        purl: Some(purl.clone()),
        bom_ref: Some(purl),
        hashes: Vec::new(),
    }
}

pub(crate) fn application_component(
    name: String,
    sha256_hex: String,
    blake3_hex: String,
) -> Component {
    Component {
        component_type: ComponentType::Application,
        name,
        version: None,
        purl: None,
        bom_ref: None,
        hashes: vec![
            Hash {
                alg: SHA256_ALG,
                content: sha256_hex,
            },
            Hash {
                alg: BLAKE3_ALG,
                content: blake3_hex,
            },
        ],
    }
}

impl CycloneDxBom {
    pub(crate) fn from_crates(
        timestamp: Option<String>,
        root: Option<Component>,
        crates: &[AuditableCrate],
    ) -> Self {
        let mut components: Vec<Component> =
            Vec::with_capacity(crates.len() + usize::from(root.is_some()));
        if let Some(app) = root {
            components.push(app);
        }
        components.extend(crates.iter().map(component_from_crate));
        Self {
            bom_format: BOM_FORMAT,
            spec_version: SPEC_VERSION,
            version: BOM_VERSION,
            metadata: Metadata {
                timestamp,
                tools: vec![Tool::disrobe()],
            },
            components,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn krate(name: &str, version: &str) -> AuditableCrate {
        AuditableCrate {
            name: name.to_owned(),
            version: version.to_owned(),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
        }
    }

    fn to_value(bom: &CycloneDxBom) -> Value {
        serde_json::to_value(bom).expect("serialize cyclonedx bom")
    }

    #[test]
    fn full_shape_is_faithful() {
        let root: Component =
            application_component("hello".to_owned(), "a".repeat(64), "b".repeat(64));
        let crates: Vec<AuditableCrate> = vec![krate("serde", "1.0.0"), krate("anyhow", "1.0.86")];
        let bom: CycloneDxBom = CycloneDxBom::from_crates(None, Some(root), &crates);
        let v: Value = to_value(&bom);

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert_eq!(v["version"], 1);
        assert!(v["version"].is_u64());

        let tool: &Value = &v["metadata"]["tools"][0];
        assert_eq!(tool["name"], "disrobe");
        assert!(tool["version"].is_string());

        let components: &Vec<Value> = v["components"].as_array().expect("components array");
        assert_eq!(components.len(), 3);

        let app: &Value = &components[0];
        assert_eq!(app["type"], "application");
        assert_eq!(app["name"], "hello");
        assert_eq!(app["hashes"][0]["alg"], "SHA-256");
        assert!(app["hashes"][0]["content"].is_string());
        assert_eq!(app["hashes"][1]["alg"], "BLAKE3");

        let lib: &Value = &components[1];
        assert_eq!(lib["type"], "library");
        assert_eq!(lib["name"], "serde");
        assert_eq!(lib["version"], "1.0.0");
        assert_eq!(lib["purl"], "pkg:cargo/serde@1.0.0");
        assert_eq!(lib["bom-ref"], "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn empty_crates_is_valid_bom() {
        let bom: CycloneDxBom = CycloneDxBom::from_crates(None, None, &[]);
        let v: Value = to_value(&bom);
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        assert!(v["version"].is_u64());
        assert_eq!(v["components"].as_array().expect("components").len(), 0);
        assert_eq!(v["metadata"]["tools"][0]["name"], "disrobe");
    }

    #[test]
    fn timestamp_present_when_supplied() {
        let bom: CycloneDxBom =
            CycloneDxBom::from_crates(Some("2026-06-01T00:00:00Z".to_owned()), None, &[]);
        let v: Value = to_value(&bom);
        assert_eq!(v["metadata"]["timestamp"], "2026-06-01T00:00:00Z");
    }

    #[test]
    fn timestamp_omitted_when_absent() {
        let bom: CycloneDxBom = CycloneDxBom::from_crates(None, None, &[]);
        let v: Value = to_value(&bom);
        assert!(v["metadata"].get("timestamp").is_none());
    }

    #[test]
    fn purl_is_faithful() {
        assert_eq!(cargo_purl("anyhow", "1.0.86"), "pkg:cargo/anyhow@1.0.86");
    }

    #[test]
    fn library_component_omits_hashes() {
        let c: Component = component_from_crate(&krate("serde", "1.0.0"));
        let v: Value = serde_json::to_value(&c).expect("serialize component");
        assert!(v.get("hashes").is_none());
        assert!(v.get("version").is_some());
    }

    #[test]
    fn component_type_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ComponentType::Library).expect("lib"),
            Value::String("library".to_owned())
        );
        assert_eq!(
            serde_json::to_value(ComponentType::Application).expect("app"),
            Value::String("application".to_owned())
        );
    }
}
