use disrobe_pass_js_deob::{
    Error, ExtractedModule, UnbundleLimits, UnbundleResult, auto_unbundle_with_limits,
};
use serde::Serialize;

const INPUT_BYTES: usize = 1024 * 1024;
const LIMITS: UnbundleLimits = UnbundleLimits {
    input_bytes: INPUT_BYTES,
    modules: 4096,
    output_bytes: 8 * 1024 * 1024,
};

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum Unbundling {
    Recognized {
        bundler: &'static str,
        markers: Vec<String>,
        modules: Vec<ExtractedModule>,
    },
    Unrecognized,
}

#[derive(Debug, Serialize)]
pub struct BundleResult {
    ok: bool,
    format: &'static str,
    #[serde(flatten)]
    result: Unbundling,
}

pub fn js_unbundle(bytes: &[u8]) -> Result<BundleResult, String> {
    if bytes.len() > INPUT_BYTES {
        return Err("JavaScript unbundling accepts inputs up to 1 MiB.".to_owned());
    }
    let source: &str = std::str::from_utf8(bytes)
        .map_err(|_| "JavaScript unbundling requires UTF-8 text.".to_owned())?;
    let result: Unbundling = match auto_unbundle_with_limits(source, LIMITS) {
        Ok(UnbundleResult {
            kind,
            detection,
            modules,
        }) => Unbundling::Recognized {
            bundler: kind.as_str(),
            markers: detection.markers,
            modules,
        },
        Err(Error::NoFamilyMatched) => Unbundling::Unrecognized,
        Err(error) => return Err(error.to_string()),
    };
    Ok(BundleResult {
        ok: true,
        format: "javascript-bundle",
        result,
    })
}

#[cfg(test)]
mod tests {
    use super::{INPUT_BYTES, Unbundling, js_unbundle};

    #[test]
    fn real_webpack_modules_reach_the_browser_adapter() -> Result<(), String> {
        let route: super::super::AutoRouteResult = super::super::auto_route(include_bytes!(
            "../../../../corpus/js/webpack5/gauntlet/bundle.js"
        ));
        assert_eq!(
            route.primary.as_ref().map(|candidate| candidate.mode),
            Some("js_unbundle")
        );
        let result = js_unbundle(include_bytes!(
            "../../../../corpus/js/webpack5/gauntlet/bundle.js"
        ))?;
        let Unbundling::Recognized {
            bundler, modules, ..
        } = result.result
        else {
            return Err("webpack bundle was not recognized".to_owned());
        };
        assert_eq!(bundler, "webpack5");
        for id in ["./src/geometry.js", "./src/inventory.js"] {
            assert!(
                modules
                    .iter()
                    .any(|module| module.id == id && !module.source.is_empty())
            );
        }
        Ok(())
    }

    #[test]
    fn bundle_adapter_distinguishes_detection_from_extraction() -> Result<(), String> {
        assert!(matches!(
            js_unbundle(b"const value = 1;")?.result,
            Unbundling::Unrecognized
        ));
        let result =
            js_unbundle(b"var __webpack_modules__ = {}; var __webpack_module_cache__ = {};")?;
        assert!(
            matches!(result.result, Unbundling::Recognized { modules, .. } if modules.is_empty())
        );
        Ok(())
    }

    #[test]
    fn automatic_bundle_routing_preserves_wrapper_priority() {
        for (prefix, expected) in [("<?php", "php_detect"), ("__pyarmor__", "pyarmor_classify")] {
            let source: String = format!(
                "{prefix}\nvar __webpack_modules__ = {{}}; var __webpack_module_cache__ = {{}};"
            );
            let result = super::super::auto_route(source.as_bytes());
            assert_eq!(
                result.primary.as_ref().map(|candidate| candidate.mode),
                Some(expected)
            );
            assert!(
                result
                    .candidates
                    .iter()
                    .any(|candidate| candidate.mode == "js_unbundle")
            );
        }
    }

    #[test]
    fn bundle_adapter_checks_input_before_parsing() {
        assert!(js_unbundle(&[0xff]).is_err());
        assert!(js_unbundle(&vec![b'a'; INPUT_BYTES + 1]).is_err());
    }
}
