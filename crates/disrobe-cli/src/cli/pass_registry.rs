use super::wasm_cmd::WasmCmd;

#[cfg(feature = "wasm")]
pub(crate) const WASM_RUN: Option<fn(WasmCmd) -> miette::Result<()>> = Some(crate::cli::wasm::run);
#[cfg(not(feature = "wasm"))]
pub(crate) const WASM_RUN: Option<fn(WasmCmd) -> miette::Result<()>> = None;

pub(crate) fn not_compiled(pass: &str, feature: &str) -> miette::Report {
    miette::miette!(
        "the `{pass}` pass is not compiled into this binary (slim build); rebuild with default features (feature `{feature}`)"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn full_umbrella_lists_every_declared_pass_feature() {
        let manifest: toml::Value =
            toml::from_str(include_str!("../../Cargo.toml")).expect("cli Cargo.toml parses");
        let features: &toml::Table = manifest
            .get("features")
            .and_then(toml::Value::as_table)
            .expect("[features] table present");
        let full: BTreeSet<&str> = features
            .get("full")
            .and_then(toml::Value::as_array)
            .expect("full feature array present")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect();
        let declared: BTreeSet<&str> = features
            .keys()
            .map(String::as_str)
            .filter(|k: &&str| *k != "default" && *k != "full")
            .collect();
        assert_eq!(
            full,
            declared,
            "the `full` umbrella must list every declared pass feature (missing from full: {:?})",
            declared.difference(&full).collect::<Vec<&&str>>()
        );
        let default_feature: Vec<&str> = features
            .get("default")
            .and_then(toml::Value::as_array)
            .expect("default feature array present")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect();
        assert_eq!(
            default_feature,
            vec!["full"],
            "default must route through the full umbrella only"
        );
    }
}
