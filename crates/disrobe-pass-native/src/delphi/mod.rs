mod dfm;
mod image;
mod init_table;
mod layout;
mod resource;
mod strings;
mod tables;
mod typeinfo;
mod units;
mod version;
mod vmt;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use image::PeView;

pub use init_table::{DelphiInitTable, DelphiUnitEntry};
pub use strings::{DelphiString, DelphiStringKind};
pub use typeinfo::{DelphiRecordField, DelphiTypeInfo};
pub use units::{DelphiOrigin, classify_unit};
pub use version::{DelphiSignalKind, DelphiVersion, DelphiVersionSignal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelphiEra {
    Legacy32,
    Modern32,
    Modern64,
}

impl DelphiEra {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Legacy32 => "pre-2009 32-bit VMT layout",
            Self::Modern32 => "Delphi 2009+ 32-bit VMT layout",
            Self::Modern64 => "64-bit VMT layout",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiProperty {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiMethod {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiField {
    pub name: String,
    pub offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiDynamicMethod {
    pub index: i16,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiInterface {
    pub iid: String,
    pub vtable: u64,
    pub instance_offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiClass {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_name: Option<String>,
    pub origin: DelphiOrigin,
    pub era: DelphiEra,
    pub instance_size: u32,
    pub vmt_va: u64,
    pub properties: Vec<DelphiProperty>,
    pub methods: Vec<DelphiMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<DelphiField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_methods: Vec<DelphiDynamicMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<DelphiInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiForm {
    pub resource_name: String,
    pub root_class: String,
    pub text: String,
    pub object_count: usize,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiReport {
    pub is_delphi: bool,
    pub rtti_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub era: Option<DelphiEra>,
    pub version: DelphiVersion,
    pub classes: Vec<DelphiClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<DelphiTypeInfo>,
    pub forms: Vec<DelphiForm>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<DelphiString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_table: Option<DelphiInitTable>,
    pub library_class_count: usize,
    pub author_class_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

const MARKERS: &[&[u8]] = &[
    b"Borland Delphi",
    b"Embarcadero Delphi",
    b"Embarcadero\\Studio",
    b"SOFTWARE\\Borland\\Delphi",
    b"Software\\Embarcadero\\",
    b"System.SysUtils",
    b"TObject",
];

fn scan_window(bytes: &[u8]) -> &[u8] {
    const LIMIT: usize = 8 * 1024 * 1024;
    &bytes[..bytes.len().min(LIMIT)]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn has_markers(bytes: &[u8]) -> bool {
    let window: &[u8] = scan_window(bytes);
    MARKERS.iter().any(|m: &&[u8]| contains(window, m))
}

#[must_use]
pub fn recover_delphi_classes(bytes: &[u8]) -> Vec<DelphiClass> {
    PeView::parse(bytes).map_or_else(Vec::new, |view: PeView<'_>| {
        vmt::scan_classes(&view).classes
    })
}

#[must_use]
pub fn recover_delphi_strings(bytes: &[u8]) -> Vec<DelphiString> {
    PeView::parse(bytes).map_or_else(Vec::new, |view: PeView<'_>| strings::scan(&view))
}

#[must_use]
pub fn decode_dfm(bytes: &[u8]) -> Option<DelphiForm> {
    let decoded: dfm::DfmDecoded = dfm::decode(bytes)?;
    Some(DelphiForm {
        resource_name: String::new(),
        root_class: decoded.root_class,
        text: decoded.text,
        object_count: decoded.object_count,
        truncated: decoded.truncated,
        notes: decoded.notes,
    })
}

#[must_use]
pub fn recover_dfm_resources(bytes: &[u8]) -> Vec<DelphiForm> {
    let Some(view): Option<PeView<'_>> = PeView::parse(bytes) else {
        return Vec::new();
    };
    decode_forms(&view)
}

fn decode_forms(view: &PeView<'_>) -> Vec<DelphiForm> {
    let mut forms: Vec<DelphiForm> = Vec::new();
    for res in resource::collect_rcdata(view, &resource::is_form) {
        let Some(decoded): Option<dfm::DfmDecoded> = dfm::decode(&res.data) else {
            continue;
        };
        forms.push(DelphiForm {
            resource_name: res.name,
            root_class: decoded.root_class,
            text: decoded.text,
            object_count: decoded.object_count,
            truncated: decoded.truncated,
            notes: decoded.notes,
        });
    }
    forms
}

#[must_use]
pub fn detect_delphi(bytes: &[u8]) -> bool {
    if has_markers(bytes) {
        return true;
    }
    PeView::parse(bytes).is_some_and(|view: PeView<'_>| {
        !vmt::scan_classes(&view).classes.is_empty()
            || !resource::collect_rcdata(&view, &resource::is_form).is_empty()
    })
}

fn empty_version() -> DelphiVersion {
    DelphiVersion {
        product: None,
        ver_symbol: None,
        package_version: None,
        candidates: Vec::new(),
        signals: Vec::new(),
        conflicts: Vec::new(),
    }
}

#[must_use]
pub fn analyze(bytes: &[u8]) -> DelphiReport {
    let markers: bool = has_markers(bytes);
    let Some(view): Option<PeView<'_>> = PeView::parse(bytes) else {
        return DelphiReport {
            is_delphi: markers,
            rtti_present: false,
            era: None,
            version: empty_version(),
            classes: Vec::new(),
            types: Vec::new(),
            forms: Vec::new(),
            strings: Vec::new(),
            init_table: None,
            library_class_count: 0,
            author_class_count: 0,
            notes: if markers {
                vec!["Delphi marker present but the input is not a PE image".to_owned()]
            } else {
                Vec::new()
            },
        };
    };

    let outcome: vmt::ScanOutcome = vmt::scan_classes(&view);
    let forms: Vec<DelphiForm> = decode_forms(&view);
    let rtti_present: bool = !outcome.classes.is_empty();
    let license: Option<String> = resource::find_license_resource(&view);
    let version: DelphiVersion = version::identify(
        bytes,
        outcome.era,
        &vmt::unit_names(&outcome.classes),
        license.as_deref(),
    );
    let (library_class_count, author_class_count): (usize, usize) =
        vmt::origin_counts(&outcome.classes);
    let is_delphi: bool = markers || rtti_present || !forms.is_empty();
    let literals: Vec<DelphiString> = if is_delphi {
        strings::scan(&view)
    } else {
        Vec::new()
    };
    let init_table: Option<DelphiInitTable> = init_table::recover(&view);

    let mut notes: Vec<String> = Vec::new();
    if outcome.scan_truncated {
        notes.push(
            "VMT scan reached an internal position or count cap before covering the whole image; class results may be incomplete".to_owned(),
        );
    }
    if !rtti_present {
        if outcome.anchor_count > 0 {
            notes.push(
                "possible VMT anchor pattern(s) found, none validated as a Delphi class".to_owned(),
            );
        } else {
            notes.push("no Delphi RTTI virtual method tables present".to_owned());
        }
    }
    if init_table.is_some() && view.every_mapped_section_is_executable() {
        notes.push(
            "every mapped section in this image is flagged executable, so the check that unit addresses lie in code cannot discriminate here and the recovered table is weakly validated".to_owned(),
        );
    }
    if is_delphi && init_table.is_none() {
        notes.push(
            "no unit initialization table was reached from the entry point; the entry point belongs to a packer or loader stub rather than the Delphi startup code when a binary is packed".to_owned(),
        );
    }
    for conflict in &version.conflicts {
        notes.push(conflict.clone());
    }
    for form in &forms {
        if form.truncated {
            notes.push(format!(
                "form resource {} decoded partially",
                form.resource_name
            ));
        }
    }

    DelphiReport {
        is_delphi,
        rtti_present,
        era: outcome.era,
        version,
        classes: outcome.classes,
        types: outcome.types,
        forms,
        strings: literals,
        init_table,
        library_class_count,
        author_class_count,
        notes,
    }
}
