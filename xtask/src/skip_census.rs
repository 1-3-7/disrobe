use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use syn::visit::Visit;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MIN_SCANNED_FILES: usize = 3_400;
const SCANNED_ROOTS: [&str; 4] = ["crates", "benches", "xtask", "fuzz"];

const SKIP_CEILING: &[(&str, usize)] = &[
    ("disrobe-binfmt", 41),
    ("disrobe-cli", 34),
    ("disrobe-core", 5),
    ("disrobe-irsummary", 1),
    ("disrobe-lift-x86", 5),
    ("disrobe-mba", 9),
    ("disrobe-nir-lift", 7),
    ("disrobe-pass-as3", 25),
    ("disrobe-pass-beam", 1),
    ("disrobe-pass-go", 35),
    ("disrobe-pass-js-deob", 1),
    ("disrobe-pass-jvm", 31),
    ("disrobe-pass-lua", 22),
    ("disrobe-pass-mobile", 21),
    ("disrobe-pass-native", 165),
    ("disrobe-pass-nativelang", 7),
    ("disrobe-pass-nuitka", 9),
    ("disrobe-pass-php", 67),
    ("disrobe-pass-py-decompile", 23),
    ("disrobe-pass-pyarmor", 2),
    ("disrobe-pass-pyfreeze", 6),
    ("disrobe-pass-pyinstaller", 11),
    ("disrobe-pass-ruby", 21),
    ("disrobe-pass-scriptlang", 2),
    ("disrobe-pass-shell", 3),
    ("disrobe-pass-sourcedefender", 5),
    ("disrobe-pass-swift-objc", 45),
    ("disrobe-pass-wasm-deob", 10),
    ("disrobe-pass-webview", 6),
    ("disrobe-passes", 2),
    ("disrobe-playground", 1),
    ("disrobe-pyarmor-cextract", 8),
    ("disrobe-semdiff", 10),
    ("disrobe-sleigh", 14),
    ("disrobe-taint", 11),
    ("disrobe-transcode", 2),
    ("disrobe-typerec", 4),
    ("disrobe-validator", 2),
    ("xtask", 3),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkipSite {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) test: String,
}

fn is_test_attribute(attribute: &syn::Attribute) -> bool {
    let segments: Vec<String> = attribute
        .path()
        .segments
        .iter()
        .map(|segment: &syn::PathSegment| segment.ident.to_string())
        .collect();
    segments.last().is_some_and(|last: &String| last == "test")
}

fn is_successful_return(value: Option<&syn::Expr>) -> bool {
    let Some(value): Option<&syn::Expr> = value else {
        return true;
    };
    let syn::Expr::Call(call) = value else {
        return false;
    };
    let syn::Expr::Path(callee) = call.func.as_ref() else {
        return false;
    };
    callee.path.is_ident("Ok")
        && call.args.len() == 1
        && matches!(call.args.first(), Some(syn::Expr::Tuple(unit)) if unit.elems.is_empty())
}

struct EarlyReturns<'a> {
    file: &'a str,
    test: String,
    found: Vec<SkipSite>,
}

impl<'ast> Visit<'ast> for EarlyReturns<'_> {
    fn visit_expr_closure(&mut self, _closure: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _block: &'ast syn::ExprAsync) {}

    fn visit_item(&mut self, _item: &'ast syn::Item) {}

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if is_successful_return(node.expr.as_deref()) {
            let span: proc_macro2::Span = node.return_token.span;
            self.found.push(SkipSite {
                file: self.file.to_owned(),
                line: span.start().line,
                test: self.test.clone(),
            });
        }
        syn::visit::visit_expr_return(self, node);
    }
}

const fn is_tail_return(statement: &syn::Stmt) -> bool {
    matches!(statement, syn::Stmt::Expr(syn::Expr::Return(_), _))
}

fn early_returns_in_test(file: &str, function: &syn::ItemFn) -> Vec<SkipSite> {
    let mut visitor: EarlyReturns<'_> = EarlyReturns {
        file,
        test: function.sig.ident.to_string(),
        found: Vec::new(),
    };
    let statements: &[syn::Stmt] = &function.block.stmts;
    let body: &[syn::Stmt] = match statements.split_last() {
        Some((last, rest)) if is_tail_return(last) => rest,
        _ => statements,
    };
    for statement in body {
        visitor.visit_stmt(statement);
    }
    visitor.found
}

struct TestFunctions<'a> {
    file: &'a str,
    found: Vec<SkipSite>,
}

impl<'ast> Visit<'ast> for TestFunctions<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if function.attrs.iter().any(is_test_attribute) {
            self.found
                .extend(early_returns_in_test(self.file, function));
        }
    }
}

pub(crate) fn sites_in_source(relative: &str, source: &str) -> Result<Vec<SkipSite>> {
    let file: syn::File =
        syn::parse_file(source).wrap_err_with(|| format!("parsing {relative} as Rust"))?;
    let mut visitor: TestFunctions<'_> = TestFunctions {
        file: relative,
        found: Vec::new(),
    };
    visitor.visit_file(&file);
    Ok(visitor.found)
}

fn owner_of(relative: &str) -> Option<String> {
    let mut parts: std::str::Split<'_, char> = relative.split('/');
    match parts.next()? {
        "crates" => parts.next().map(str::to_owned),
        "benches" => parts.next().map(|bench: &str| format!("benches/{bench}")),
        "xtask" => Some("xtask".to_owned()),
        "fuzz" => Some("fuzz".to_owned()),
        _ => None,
    }
}

struct Census {
    sites: BTreeMap<String, Vec<SkipSite>>,
    scanned: usize,
}

fn is_scanned_source(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext == "rs")
        && !path
            .components()
            .any(|component: std::path::Component<'_>| {
                matches!(
                    component.as_os_str().to_str(),
                    Some("target" | "fixtures" | "golden")
                )
            })
}

fn scan(root: &Path) -> Result<Census> {
    let mut sites: BTreeMap<String, Vec<SkipSite>> = BTreeMap::new();
    let mut scanned: usize = 0;
    for top in SCANNED_ROOTS {
        let directory: PathBuf = root.join(top);
        if !directory.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&directory)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path: &Path = entry.path();
            if !is_scanned_source(path) {
                continue;
            }
            let relative: String = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let Some(owner): Option<String> = owner_of(&relative) else {
                continue;
            };
            let length: u64 = entry
                .metadata()
                .map_or(0, |meta: std::fs::Metadata| meta.len());
            if length > MAX_SOURCE_BYTES {
                bail!(
                    "{relative} is {length} bytes, above the {MAX_SOURCE_BYTES}-byte census \
                     bound; a source the census cannot read would report none of its skips"
                );
            }
            let source: String = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("read {}", path.display()))?;
            scanned = scanned.saturating_add(1);
            let found: Vec<SkipSite> = sites_in_source(&relative, &source)?;
            if !found.is_empty() {
                sites.entry(owner).or_default().extend(found);
            }
        }
    }
    Ok(Census { sites, scanned })
}

fn enforce_scan_floor(scanned: usize) -> Result<()> {
    if scanned >= MIN_SCANNED_FILES {
        return Ok(());
    }
    bail!(
        "xtask skip-census scanned only {scanned} Rust source file(s), below the floor of \
         {MIN_SCANNED_FILES}. The scan itself is broken or the tree moved; a census that reads a \
         fraction of the tree reports a clean sheet for everything it never opened"
    )
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let census: Census = scan(root)?;

    enforce_scan_floor(census.scanned)?;

    let declared: BTreeMap<&str, usize> = SKIP_CEILING.iter().copied().collect();
    let mut issues: Vec<String> = Vec::new();
    let mut total: usize = 0;

    for (owner, sites) in &census.sites {
        let count: usize = sites.len();
        total = total.saturating_add(count);
        let ceiling: usize = declared.get(owner.as_str()).copied().unwrap_or(0);
        if count > ceiling {
            let first: String = sites
                .iter()
                .take(3)
                .map(|site: &SkipSite| format!("{}:{} ({})", site.file, site.line, site.test))
                .collect::<Vec<String>>()
                .join(", ");
            issues.push(format!(
                "{owner} carries {count} successful early return(s) inside tests, above its \
                 declared ceiling of {ceiling}. A test that returns before its assertions is \
                 counted as passed and proves nothing: fail by name when the reference is \
                 missing, or declare it optional through disrobe_testkit::require and \
                 tests/optional.toml. First site(s): {first}"
            ));
        }
        if count < ceiling {
            issues.push(format!(
                "{owner} carries {count} successful early return(s) inside tests, below its \
                 declared ceiling of {ceiling}. Lower the ceiling in xtask/src/skip_census.rs in \
                 the same commit, so the number can only ratchet down"
            ));
        }
    }

    for (owner, ceiling) in SKIP_CEILING {
        if !census.sites.contains_key(*owner) && *ceiling > 0 {
            issues.push(format!(
                "SKIP_CEILING declares {ceiling} for {owner}, which now carries none. Remove the \
                 entry in the same commit"
            ));
        }
    }

    if !issues.is_empty() {
        bail!(
            "xtask skip-census: {} finding(s); {total} successful early return(s) inside \
             tests:\n  {}",
            issues.len(),
            issues.join("\n  ")
        );
    }

    println!(
        "xtask skip-census: {} Rust source file(s) parsed, {total} successful early return(s) \
         inside tests across {} owner(s), each at or below its declared ceiling in \
         xtask/src/skip_census.rs; the ceiling ratchets down only",
        census.scanned,
        census.sites.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SkipSite, owner_of, sites_in_source};

    fn sites(source: &str) -> eyre::Result<Vec<SkipSite>> {
        sites_in_source("crates/x/tests/a.rs", source)
    }

    #[test]
    fn a_bare_return_before_the_assertions_of_a_test_is_a_site() -> eyre::Result<()> {
        let found: Vec<SkipSite> = sites(
            "#[test]\nfn probe() {\n    if absent() {\n        return;\n    }\n    assert!(false);\n}\n",
        )?;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].line, found[0].test.as_str()), (4, "probe"));
        Ok(())
    }

    #[test]
    fn a_let_else_return_and_an_ok_unit_return_are_sites() -> eyre::Result<()> {
        let found: Vec<SkipSite> = sites(concat!(
            "#[test]\n",
            "fn probe() -> Result<(), String> {\n",
            "    let Some(tool) = find() else { return Ok(()); };\n",
            "    if tool.is_empty() { return Ok( ( ) ); }\n",
            "    assert!(run(tool));\n",
            "    Ok(())\n",
            "}\n"
        ))?;
        assert_eq!(found.len(), 2, "{found:?}");
        Ok(())
    }

    #[test]
    fn a_failing_return_a_tail_return_a_closure_and_a_helper_are_not_sites() -> eyre::Result<()> {
        let found: Vec<SkipSite> = sites(concat!(
            "fn helper() { return; }\n",
            "#[test]\n",
            "fn probe() -> Result<(), String> {\n",
            "    if broken() { return Err(\"broken\".to_owned()); }\n",
            "    let check = || { return; };\n",
            "    check();\n",
            "    fn nested() { return; }\n",
            "    nested();\n",
            "    return Ok(());\n",
            "}\n"
        ))?;
        assert!(found.is_empty(), "{found:?}");
        Ok(())
    }

    #[test]
    fn tests_inside_a_cfg_test_module_and_async_test_attributes_are_counted() -> eyre::Result<()> {
        let found: Vec<SkipSite> = sites(concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    #[tokio::test]\n",
            "    async fn probe() {\n",
            "        if absent() { return; }\n",
            "        assert!(false);\n",
            "    }\n",
            "}\n"
        ))?;
        assert_eq!(found.len(), 1, "{found:?}");
        Ok(())
    }

    #[test]
    fn a_return_written_in_a_string_or_comment_is_not_a_site() -> eyre::Result<()> {
        let found: Vec<SkipSite> = sites(
            "#[test]\nfn probe() {\n    // return;\n    let text = \"return;\";\n    assert!(text.len() > 0);\n}\n",
        )?;
        assert!(found.is_empty(), "{found:?}");
        Ok(())
    }

    #[test]
    fn owners_cover_crates_benches_xtask_and_fuzz() {
        assert_eq!(
            owner_of("crates/disrobe-core/src/a.rs").as_deref(),
            Some("disrobe-core")
        );
        assert_eq!(
            owner_of("benches/perf/src/main.rs").as_deref(),
            Some("benches/perf")
        );
        assert_eq!(owner_of("xtask/src/main.rs").as_deref(), Some("xtask"));
        assert_eq!(owner_of("fuzz/fuzz_targets/a.rs").as_deref(), Some("fuzz"));
        assert_eq!(owner_of("docs/a.rs"), None);
    }
}
