use disrobe_pass_js_deob::{
    BundlerKind, Error, ExtractedModule, UnbundleLimits, UnbundleResult, auto_unbundle_with_limits,
    unbundle, unbundle_with_limits,
};

const LIMITS: UnbundleLimits = UnbundleLimits {
    input_bytes: 1024 * 1024,
    modules: 4096,
    output_bytes: 8 * 1024 * 1024,
};

const WEBPACK: &str = include_str!("../../../corpus/js/webpack5/gauntlet/bundle.js");

#[test]
fn wrapper_normalization_preserves_following_statements() {
    let source: &str = "function(module, exports) { module.exports = 1; }; report();";
    let mut modules: Vec<ExtractedModule> = vec![ExtractedModule {
        id: "0".to_owned(),
        chunk_id: None,
        source: source.to_owned(),
    }];
    disrobe_pass_js_deob::rewrite_modules(&mut modules);
    assert_eq!(modules[0].source, source);
    for separator in ["\n", "\r", "\u{2028}", "\u{2029}"] {
        let source: String = format!(
            "function(module, exports) {{ module.exports = 1; }}; // trailer{separator}report();"
        );
        modules[0].source.clone_from(&source);
        disrobe_pass_js_deob::rewrite_modules(&mut modules);
        assert_eq!(modules[0].source, source);
    }
}

#[test]
fn real_bundle_module_bodies_parse_as_javascript() -> Result<(), Error> {
    for source in [
        WEBPACK,
        include_str!("../../../corpus/js/browserify/bundle.js"),
    ] {
        let result: UnbundleResult = auto_unbundle_with_limits(source, LIMITS)?;
        assert!(!result.modules.is_empty());
        for module in result.modules {
            let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
            let parsed: oxc_parser::ParserReturn<'_> =
                oxc_parser::Parser::new(&allocator, &module.source, oxc_span::SourceType::mjs())
                    .parse();
            assert!(
                !parsed.panicked && parsed.errors.is_empty(),
                "{} contains invalid module syntax: {:?}",
                module.id,
                parsed.errors
            );
        }
    }
    Ok(())
}

#[test]
fn input_limit_accepts_exact_bytes_and_rejects_one_more() -> Result<(), Error> {
    let source: &str = "export const x = 1;";
    let limits: UnbundleLimits = UnbundleLimits {
        input_bytes: source.len(),
        ..LIMITS
    };
    let result: UnbundleResult = unbundle_with_limits(BundlerKind::Rollup, source, limits)?;
    assert_eq!(result.modules.len(), 1);
    assert!(matches!(
        unbundle_with_limits(BundlerKind::Rollup, &format!("{source} "), limits),
        Err(Error::SyntaxLimit {
            kind: "bundle input bytes",
            ..
        })
    ));
    assert!(matches!(
        auto_unbundle_with_limits(&format!("{source} "), limits),
        Err(Error::SyntaxLimit {
            kind: "bundle input bytes",
            ..
        })
    ));
    Ok(())
}

#[test]
fn module_limit_rejects_excess_instead_of_returning_partial_modules() -> Result<(), Error> {
    let source: &str = "export const x = 1;\nexport const y = 2;";
    let limits: UnbundleLimits = UnbundleLimits {
        modules: 2,
        ..LIMITS
    };
    assert_eq!(
        unbundle_with_limits(BundlerKind::Rollup, source, limits)?
            .modules
            .len(),
        2
    );
    assert!(matches!(
        unbundle_with_limits(
            BundlerKind::Rollup,
            source,
            UnbundleLimits {
                modules: 1,
                ..limits
            }
        ),
        Err(Error::SyntaxLimit {
            kind: "bundle module count",
            observed: 2,
            maximum: 1
        })
    ));
    Ok(())
}

#[test]
fn output_limit_includes_module_identity() -> Result<(), Error> {
    let source: &str = "export const x = 1";
    let limits: UnbundleLimits = UnbundleLimits {
        output_bytes: source.len() + 1,
        ..LIMITS
    };
    let result: UnbundleResult = unbundle_with_limits(BundlerKind::Rollup, source, limits)?;
    assert_eq!(result.modules[0].source, source);
    assert_eq!(result.modules[0].id, "x");
    assert!(matches!(
        unbundle_with_limits(
            BundlerKind::Rollup,
            source,
            UnbundleLimits {
                output_bytes: source.len(),
                ..limits
            }
        ),
        Err(Error::SyntaxLimit {
            kind: "bundle output bytes",
            ..
        })
    ));
    Ok(())
}

#[test]
fn require_expansion_is_checked_against_output_limit() {
    let source: String = format!(
        "var __webpack_modules__ = {{0: function(module, exports, require) {{{}}}, 1: function(module, exports) {{module.exports = 1;}}}};",
        "require(1);".repeat(100)
    );
    assert!(matches!(
        unbundle_with_limits(
            BundlerKind::Webpack5,
            &source,
            UnbundleLimits {
                output_bytes: source.len(),
                ..LIMITS
            }
        ),
        Err(Error::SyntaxLimit {
            kind: "bundle output bytes",
            ..
        })
    ));
}

#[test]
fn bounded_webpack_keeps_real_module_bodies_and_existing_output() -> Result<(), Error> {
    let bounded: UnbundleResult = unbundle_with_limits(BundlerKind::Webpack5, WEBPACK, LIMITS)?;
    let existing: UnbundleResult = unbundle(BundlerKind::Webpack5, WEBPACK)?;
    let bounded_modules: Vec<(&str, &str, Option<&str>)> = bounded
        .modules
        .iter()
        .map(|module: &ExtractedModule| {
            (
                module.id.as_str(),
                module.source.as_str(),
                module.chunk_id.as_deref(),
            )
        })
        .collect();
    let existing_modules: Vec<(&str, &str, Option<&str>)> = existing
        .modules
        .iter()
        .map(|module: &ExtractedModule| {
            (
                module.id.as_str(),
                module.source.as_str(),
                module.chunk_id.as_deref(),
            )
        })
        .collect();
    assert_eq!(bounded_modules, existing_modules);
    for id in ["./src/geometry.js", "./src/inventory.js"] {
        let module: Option<&ExtractedModule> = bounded
            .modules
            .iter()
            .find(|module: &&ExtractedModule| module.id == id);
        assert!(
            module.is_some_and(|module: &ExtractedModule| !module.source.is_empty()
                && !module.source.contains("__webpack_module_cache__")),
            "missing independent fixture module: {id}"
        );
    }
    assert_eq!(
        auto_unbundle_with_limits(WEBPACK, LIMITS)?.kind,
        BundlerKind::Webpack5
    );
    Ok(())
}

#[test]
fn unrecognized_source_is_not_reported_as_extracted() {
    for source in ["", "const value = 1;"] {
        assert!(matches!(
            auto_unbundle_with_limits(source, LIMITS),
            Err(Error::NoFamilyMatched)
        ));
    }
}

#[test]
fn modern_browserify_loader_preserves_all_real_modules() -> Result<(), Error> {
    let result: UnbundleResult = auto_unbundle_with_limits(
        include_str!("../../../corpus/js/browserify/bundle.js"),
        LIMITS,
    )?;
    assert_eq!(result.kind, BundlerKind::Browserify);
    assert_eq!(
        result
            .modules
            .iter()
            .map(|module: &ExtractedModule| module.id.as_str())
            .collect::<Vec<&str>>(),
        ["1", "2", "3"]
    );
    for (index, token) in [
        "const counter = new Counter()",
        "factorial",
        "class Counter",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            result.modules[index].source.contains(token),
            "module {} lost {token}",
            index + 1
        );
    }
    Ok(())
}

#[test]
fn webpack_direct_pushes_keep_duplicate_ids_in_distinct_chunks() -> Result<(), Error> {
    let source: &str = "__webpack_require__.r = function() {}; self.webpackChunkapp.push([[1], {same: function(module, exports) {module.exports = 'one';}}]); self.webpackChunkapp.push([[2], {same: function(module, exports) {module.exports = 'two';}}]);";
    let result: UnbundleResult = auto_unbundle_with_limits(source, LIMITS)?;
    assert_eq!(result.kind, BundlerKind::Webpack5);
    assert_eq!(result.modules.len(), 2);
    assert_eq!(result.modules[0].id, result.modules[1].id);
    assert_ne!(result.modules[0].chunk_id, result.modules[1].chunk_id);
    assert_eq!(result.modules[0].source, "module.exports = 'one';");
    assert_eq!(result.modules[1].source, "module.exports = 'two';");
    Ok(())
}

#[test]
fn unicode_indentation_preserves_module_text() -> Result<(), Error> {
    let source: &str = "var __webpack_modules__ = {0: function(module, exports) {\n module.exports = 'café';\n\u{2003}\n\u{2003}exports.label = '世界';\n}};";
    let result: UnbundleResult = unbundle_with_limits(BundlerKind::Webpack5, source, LIMITS)?;
    assert_eq!(result.modules.len(), 1);
    assert_eq!(
        result.modules[0].source,
        "module.exports = 'café';\n\nexports.label = '世界';"
    );
    Ok(())
}
