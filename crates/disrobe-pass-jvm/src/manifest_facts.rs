use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::axml::{
    AxmlAttribute, AxmlNode, AxmlTree, TYPE_DYNAMIC_REFERENCE, TYPE_INT_BOOLEAN, TYPE_INT_DEC,
    TYPE_INT_HEX, TYPE_REFERENCE,
};

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
const MAX_MANIFEST_COMPONENTS: usize = 65_536;
const PROVIDER_EXPORTED_BY_DEFAULT_BELOW_SDK: i64 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::ActivityAlias => "activity-alias",
            Self::Service => "service",
            Self::Receiver => "receiver",
            Self::Provider => "provider",
        }
    }

    fn from_element(name: &str) -> Option<Self> {
        match name {
            "activity" => Some(Self::Activity),
            "activity-alias" => Some(Self::ActivityAlias),
            "service" => Some(Self::Service),
            "receiver" => Some(Self::Receiver),
            "provider" => Some(Self::Provider),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestComponent {
    pub kind: ComponentKind,
    pub name: String,
    pub exported: Option<bool>,
    pub effectively_exported: bool,
    pub intent_filters: usize,
    pub launchable: bool,
    pub permission: Option<String>,
    pub authorities: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFacts {
    pub package: Option<String>,
    pub version_code: Option<i64>,
    pub version_name: Option<String>,
    pub min_sdk: Option<i64>,
    pub target_sdk: Option<i64>,
    pub compile_sdk: Option<i64>,
    pub uses_permissions: Vec<String>,
    pub declared_permissions: Vec<String>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    pub components: Vec<ManifestComponent>,
    pub exported_components: usize,
    pub launchable_activities: Vec<String>,
    pub components_truncated: bool,
}

fn android_attr<'a>(attributes: &'a [AxmlAttribute], name: &str) -> Option<&'a AxmlAttribute> {
    attributes
        .iter()
        .find(|a: &&AxmlAttribute| a.name == name && a.ns.as_deref() == Some(ANDROID_NS))
}

fn plain_attr<'a>(attributes: &'a [AxmlAttribute], name: &str) -> Option<&'a AxmlAttribute> {
    attributes
        .iter()
        .find(|a: &&AxmlAttribute| a.name == name && a.ns.is_none())
}

fn string_of(attribute: &AxmlAttribute) -> Option<String> {
    match attribute.raw_value.as_deref() {
        Some(raw) if !raw.is_empty() => Some(raw.to_owned()),
        _ => match attribute.value_type {
            TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => {
                Some(format!("@0x{:08x}", attribute.typed_value))
            }
            TYPE_INT_DEC => Some((attribute.typed_value as i32).to_string()),
            TYPE_INT_HEX => Some(format!("0x{:x}", attribute.typed_value)),
            _ => None,
        },
    }
}

fn int_of(attribute: &AxmlAttribute) -> Option<i64> {
    match attribute.value_type {
        TYPE_INT_DEC | TYPE_INT_HEX => Some(i64::from(attribute.typed_value as i32)),
        _ => attribute.raw_value.as_deref()?.trim().parse::<i64>().ok(),
    }
}

fn bool_of(attribute: &AxmlAttribute) -> Option<bool> {
    match attribute.value_type {
        TYPE_INT_BOOLEAN => Some(attribute.typed_value != 0),
        _ => match attribute.raw_value.as_deref()?.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
    }
}

fn qualify(package: Option<&str>, name: &str) -> String {
    match package {
        Some(pkg) if name.starts_with('.') => format!("{pkg}{name}"),
        Some(pkg) if !name.contains('.') => format!("{pkg}.{name}"),
        _ => name.to_owned(),
    }
}

struct OpenComponent {
    component: ManifestComponent,
    has_main_action: bool,
    has_launcher_category: bool,
    in_filter: bool,
}

#[must_use]
pub fn manifest_facts(tree: &AxmlTree) -> ManifestFacts {
    let mut facts: ManifestFacts = ManifestFacts::default();
    let mut uses_permissions: BTreeSet<String> = BTreeSet::new();
    let mut declared_permissions: BTreeSet<String> = BTreeSet::new();
    let mut open: Option<OpenComponent> = None;
    let mut depth: usize = 0;
    let mut component_depth: usize = 0;
    for node in &tree.events {
        match node {
            AxmlNode::StartElement {
                name, attributes, ..
            } => {
                depth += 1;
                match name.as_str() {
                    "manifest" => {
                        facts.package = plain_attr(attributes, "package").and_then(string_of);
                        facts.version_code =
                            android_attr(attributes, "versionCode").and_then(int_of);
                        facts.version_name =
                            android_attr(attributes, "versionName").and_then(string_of);
                        facts.compile_sdk =
                            android_attr(attributes, "compileSdkVersion").and_then(int_of);
                    }
                    "uses-sdk" => {
                        facts.min_sdk = android_attr(attributes, "minSdkVersion").and_then(int_of);
                        facts.target_sdk =
                            android_attr(attributes, "targetSdkVersion").and_then(int_of);
                    }
                    "uses-permission" | "uses-permission-sdk-23" => {
                        if let Some(permission) =
                            android_attr(attributes, "name").and_then(string_of)
                        {
                            uses_permissions.insert(permission);
                        }
                    }
                    "permission" => {
                        if let Some(permission) =
                            android_attr(attributes, "name").and_then(string_of)
                        {
                            declared_permissions.insert(permission);
                        }
                    }
                    "application" => {
                        facts.debuggable = android_attr(attributes, "debuggable").and_then(bool_of);
                        facts.allow_backup =
                            android_attr(attributes, "allowBackup").and_then(bool_of);
                        facts.uses_cleartext_traffic =
                            android_attr(attributes, "usesCleartextTraffic").and_then(bool_of);
                        facts.network_security_config =
                            android_attr(attributes, "networkSecurityConfig").and_then(string_of);
                    }
                    "intent-filter" => {
                        if let Some(current) = open.as_mut() {
                            current.component.intent_filters =
                                current.component.intent_filters.saturating_add(1);
                            current.in_filter = true;
                        }
                    }
                    "action" | "category" => {
                        if let Some(current) = open.as_mut()
                            && current.in_filter
                        {
                            let value: Option<String> =
                                android_attr(attributes, "name").and_then(string_of);
                            match (name.as_str(), value.as_deref()) {
                                ("action", Some("android.intent.action.MAIN")) => {
                                    current.has_main_action = true;
                                }
                                ("category", Some("android.intent.category.LAUNCHER")) => {
                                    current.has_launcher_category = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    other => {
                        if open.is_none()
                            && let Some(kind) = ComponentKind::from_element(other)
                        {
                            let raw_name: String = android_attr(attributes, "name")
                                .and_then(string_of)
                                .unwrap_or_default();
                            open = Some(OpenComponent {
                                component: ManifestComponent {
                                    kind,
                                    name: qualify(facts.package.as_deref(), &raw_name),
                                    exported: android_attr(attributes, "exported")
                                        .and_then(bool_of),
                                    effectively_exported: false,
                                    intent_filters: 0,
                                    launchable: false,
                                    permission: android_attr(attributes, "permission")
                                        .and_then(string_of),
                                    authorities: android_attr(attributes, "authorities")
                                        .and_then(string_of),
                                },
                                has_main_action: false,
                                has_launcher_category: false,
                                in_filter: false,
                            });
                            component_depth = depth;
                        }
                    }
                }
            }
            AxmlNode::EndElement { name, .. } => {
                if name == "intent-filter"
                    && let Some(current) = open.as_mut()
                {
                    current.in_filter = false;
                }
                if depth == component_depth
                    && let Some(mut finished) = open.take()
                {
                    let component: &mut ManifestComponent = &mut finished.component;
                    component.launchable = matches!(
                        component.kind,
                        ComponentKind::Activity | ComponentKind::ActivityAlias
                    ) && finished.has_main_action
                        && finished.has_launcher_category;
                    let default_exported: bool = match component.kind {
                        ComponentKind::Provider => facts
                            .min_sdk
                            .is_some_and(|sdk: i64| sdk < PROVIDER_EXPORTED_BY_DEFAULT_BELOW_SDK),
                        _ => component.intent_filters > 0,
                    };
                    component.effectively_exported = component.exported.unwrap_or(default_exported);
                    if facts.components.len() < MAX_MANIFEST_COMPONENTS {
                        facts.components.push(finished.component);
                    } else {
                        facts.components_truncated = true;
                    }
                }
                depth = depth.saturating_sub(1);
            }
            AxmlNode::StartNamespace { .. }
            | AxmlNode::EndNamespace { .. }
            | AxmlNode::CharData(_) => {}
        }
    }
    facts.uses_permissions = uses_permissions.into_iter().collect();
    facts.declared_permissions = declared_permissions.into_iter().collect();
    facts.exported_components = facts
        .components
        .iter()
        .filter(|c: &&ManifestComponent| c.effectively_exported)
        .count();
    facts.launchable_activities = facts
        .components
        .iter()
        .filter(|c: &&ManifestComponent| c.launchable)
        .map(|c: &ManifestComponent| c.name.clone())
        .collect();
    facts
}
