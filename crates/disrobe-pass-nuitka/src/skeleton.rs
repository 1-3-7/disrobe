use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::const_blob::{CodeKind, CodeObjectMeta, ConstItem, ModuleConstants, NuitkaConstants};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkeletonParam {
    pub name: String,
    pub annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkeletonFunction {
    pub name: String,
    pub qualname: String,
    pub params: Vec<SkeletonParam>,
    pub return_annotation: Option<String>,
    pub kind: CodeKind,
    pub nested: bool,
    pub from_annotations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkeletonModule {
    pub name: String,
    pub filename: Option<String>,
    pub docstring: Option<String>,
    pub functions: Vec<SkeletonFunction>,
    pub constant_names: Vec<String>,
    pub python: String,
    pub from_code_objects: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NuitkaSkeleton {
    pub modules: Vec<SkeletonModule>,
}

impl NuitkaSkeleton {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    #[must_use]
    pub fn function_count(&self) -> usize {
        self.modules
            .iter()
            .map(|m: &SkeletonModule| m.functions.len())
            .sum()
    }
}

#[must_use]
pub fn reconstruct(constants: &NuitkaConstants) -> NuitkaSkeleton {
    let modules: Vec<SkeletonModule> = constants
        .modules
        .iter()
        .filter(|m: &&ModuleConstants| is_user_module(&m.name))
        .map(reconstruct_module)
        .collect();
    NuitkaSkeleton { modules }
}

fn is_user_module(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn reconstruct_module(module: &ModuleConstants) -> SkeletonModule {
    let mut functions: Vec<SkeletonFunction> = if module.code_objects.is_empty() {
        functions_from_items(module)
    } else {
        functions_from_code_objects(&module.code_objects, &module.name)
    };
    merge_nested_qualnames(&mut functions, module);
    let filename: Option<String> = module_filename(module);
    let docstring: Option<String> = module_docstring(module);
    let constant_names: Vec<String> = constant_like_names(module, &functions);
    let python: String = render_module(
        &module.name,
        docstring.as_deref(),
        &functions,
        &constant_names,
    );
    SkeletonModule {
        name: module.name.clone(),
        filename,
        docstring,
        functions,
        constant_names,
        python,
        from_code_objects: !module.code_objects.is_empty(),
    }
}

fn functions_from_items(module: &ModuleConstants) -> Vec<SkeletonFunction> {
    let items: &[ConstItem] = &module.ordered_items;
    let mut out: Vec<SkeletonFunction> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut anon: u32 = 0;
    for (index, item) in items.iter().enumerate() {
        let ConstItem::AnnotationDict { params, ret } = item else {
            continue;
        };
        let (name, qualname, nested): (String, String, bool) =
            if let Some(qn) = adjacent_function_name(items, index) {
                let leaf: String = qualname_leaf(&qn);
                if leaf.is_empty() {
                    continue;
                }
                let resolved: String = nested_qualname_for_leaf(&leaf, module).unwrap_or(qn);
                let is_nested: bool = resolved.contains("<locals>");
                if !seen.insert(resolved.clone()) {
                    continue;
                }
                (leaf, resolved, is_nested)
            } else {
                anon += 1;
                let placeholder: String = format!("_typed_function_{anon}");
                (placeholder.clone(), placeholder, false)
            };
        out.push(SkeletonFunction {
            params: params
                .iter()
                .map(|(pname, ann): &(String, String)| SkeletonParam {
                    name: pname.clone(),
                    annotation: non_empty(ann),
                })
                .collect(),
            return_annotation: ret.as_deref().and_then(non_empty),
            name,
            qualname,
            kind: CodeKind::Function,
            nested,
            from_annotations: true,
        });
    }
    out
}

fn nested_qualname_for_leaf(leaf: &str, module: &ModuleConstants) -> Option<String> {
    let suffix: String = format!(".<locals>.{leaf}");
    module
        .strings
        .iter()
        .find(|s: &&String| s.ends_with(&suffix))
        .cloned()
}

fn adjacent_function_name(items: &[ConstItem], dict_index: usize) -> Option<String> {
    let mut fallback: Option<String> = None;
    for offset in 1..=2usize {
        let Some(ConstItem::Str { value }) = items.get(dict_index + offset) else {
            break;
        };
        if value.contains('.') && is_bindable_name(value) {
            return Some(value.clone());
        }
        if fallback.is_none() && is_bindable_name(value) {
            fallback = Some(value.clone());
        }
    }
    fallback
}

fn is_bindable_name(value: &str) -> bool {
    if value.contains("<locals>") || value.contains("<lambda>") {
        return false;
    }
    if value.contains('.') {
        let parts: Vec<&str> = value.split('.').collect();
        return parts.len() >= 2
            && parts.iter().all(|p: &&str| is_plain_identifier_lax(p))
            && is_plain_identifier_lax(parts[parts.len() - 1]);
    }
    is_plain_identifier(value) && !value.starts_with("__")
}

fn is_plain_identifier_lax(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn qualname_leaf(qualname: &str) -> String {
    qualname.rsplit('.').next().unwrap_or(qualname).to_owned()
}

fn merge_nested_qualnames(functions: &mut Vec<SkeletonFunction>, module: &ModuleConstants) {
    let mut existing_names: BTreeSet<String> = functions
        .iter()
        .map(|f: &SkeletonFunction| f.name.clone())
        .collect();
    let mut existing_quals: BTreeSet<String> = functions
        .iter()
        .map(|f: &SkeletonFunction| f.qualname.clone())
        .collect();
    for qualname in &module.strings {
        if qualname.contains("<locals>") {
            merge_locals_qualname(
                qualname,
                functions,
                &mut existing_names,
                &mut existing_quals,
            );
        } else if let Some((class, method)) = split_dotted_method(qualname) {
            merge_dotted_method(
                qualname,
                class,
                method,
                functions,
                &mut existing_names,
                &mut existing_quals,
            );
        }
    }
    functions.sort_by(|a: &SkeletonFunction, b: &SkeletonFunction| {
        a.nested
            .cmp(&b.nested)
            .then_with(|| a.qualname.cmp(&b.qualname))
    });
}

fn merge_locals_qualname(
    qualname: &str,
    functions: &mut Vec<SkeletonFunction>,
    existing_names: &mut BTreeSet<String>,
    existing_quals: &mut BTreeSet<String>,
) {
    let last: &str = qualname.rsplit('.').next().unwrap_or(qualname);
    if !is_comprehension(last)
        && is_plain_identifier(last)
        && existing_quals.insert(qualname.to_owned())
    {
        existing_names.insert(last.to_owned());
        functions.push(SkeletonFunction {
            name: last.to_owned(),
            qualname: qualname.to_owned(),
            params: Vec::new(),
            return_annotation: None,
            kind: CodeKind::Function,
            nested: true,
            from_annotations: false,
        });
    }
    if let Some((parent, _)) = qualname.split_once(".<locals>.")
        && is_plain_identifier(parent)
        && existing_names.insert(parent.to_owned())
    {
        existing_quals.insert(parent.to_owned());
        functions.push(SkeletonFunction {
            name: parent.to_owned(),
            qualname: parent.to_owned(),
            params: Vec::new(),
            return_annotation: None,
            kind: CodeKind::Function,
            nested: false,
            from_annotations: false,
        });
    }
}

fn merge_dotted_method(
    qualname: &str,
    class: &str,
    method: &str,
    functions: &mut Vec<SkeletonFunction>,
    existing_names: &mut BTreeSet<String>,
    existing_quals: &mut BTreeSet<String>,
) {
    let _ = class;
    if !existing_names.insert(method.to_owned()) {
        return;
    }
    existing_quals.insert(qualname.to_owned());
    functions.push(SkeletonFunction {
        name: method.to_owned(),
        qualname: qualname.to_owned(),
        params: Vec::new(),
        return_annotation: None,
        kind: CodeKind::Function,
        nested: false,
        from_annotations: false,
    });
}

fn split_dotted_method(qualname: &str) -> Option<(&str, &str)> {
    if qualname.contains("<locals>") || qualname.contains('<') {
        return None;
    }
    let parts: Vec<&str> = qualname.split('.').collect();
    if parts.len() != 2 {
        return None;
    }
    let (class, method): (&str, &str) = (parts[0], parts[1]);
    if is_plain_identifier(class)
        && class
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_uppercase())
        && is_plain_identifier(method)
        && !is_comprehension(method)
    {
        Some((class, method))
    } else {
        None
    }
}

fn functions_from_code_objects(codes: &[CodeObjectMeta], module: &str) -> Vec<SkeletonFunction> {
    let mut out: Vec<SkeletonFunction> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for code in codes {
        if is_module_code(&code.name, module) || is_comprehension(&code.name) {
            continue;
        }
        let qualname: String = code.qualname.clone().unwrap_or_else(|| code.name.clone());
        if !seen.insert(qualname.clone()) {
            continue;
        }
        let params: Vec<SkeletonParam> = code
            .varnames
            .iter()
            .take(usize::try_from(code.argcount).unwrap_or(0))
            .map(|name: &String| SkeletonParam {
                name: name.clone(),
                annotation: None,
            })
            .collect();
        out.push(SkeletonFunction {
            name: code.name.clone(),
            nested: qualname.contains("<locals>"),
            qualname,
            params,
            return_annotation: None,
            kind: code.kind,
            from_annotations: false,
        });
    }
    out
}

fn is_comprehension(name: &str) -> bool {
    matches!(
        name,
        "<genexpr>" | "<listcomp>" | "<dictcomp>" | "<setcomp>" | "<lambda>" | "lambda"
    )
}

fn is_module_code(name: &str, module: &str) -> bool {
    name == format!("<module {module}>") || (name.starts_with("<module ") && name.ends_with('>'))
}

fn is_plain_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && !is_comprehension(s)
        && !KEYWORDS.contains(&s)
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

fn module_filename(module: &ModuleConstants) -> Option<String> {
    module
        .code_objects
        .iter()
        .find_map(|c: &CodeObjectMeta| c.filename.clone())
        .or_else(|| {
            module
                .ordered_strings
                .iter()
                .find(|s: &&String| {
                    std::path::Path::new(s)
                        .extension()
                        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("py"))
                        && !s.contains(' ')
                })
                .cloned()
        })
}

const fn module_docstring(_module: &ModuleConstants) -> Option<String> {
    None
}

const fn constant_like_names(
    _module: &ModuleConstants,
    _functions: &[SkeletonFunction],
) -> Vec<String> {
    Vec::new()
}

fn render_module(
    module: &str,
    docstring: Option<&str>,
    functions: &[SkeletonFunction],
    constants: &[String],
) -> String {
    let mut out: String = String::new();
    if let Some(doc) = docstring {
        out.push_str(&render_docstring(doc));
        out.push('\n');
        out.push('\n');
    }
    out.push_str("# module: ");
    out.push_str(module);
    out.push('\n');
    out.push_str("# recovered from Nuitka constants metadata; bodies compiled to native code\n");
    out.push_str(
        "# signatures are approximate: parameter kinds (*args/**kwargs), defaults, and order are not all recoverable from constants\n",
    );
    out.push('\n');
    for name in constants {
        out.push_str(name);
        out.push_str(" = ...  # module constant\n");
    }
    if !constants.is_empty() {
        out.push('\n');
    }
    let classes: Vec<String> = class_names(functions);
    for class in &classes {
        out.push_str("class ");
        out.push_str(class);
        out.push_str(":\n");
        let methods: Vec<&SkeletonFunction> = functions
            .iter()
            .filter(|f: &&SkeletonFunction| method_class(&f.qualname).as_deref() == Some(class))
            .collect();
        if methods.is_empty() {
            out.push_str("    ...  # class body compiled to native code\n");
        }
        for method in &methods {
            render_method(&mut out, method);
        }
        out.push('\n');
    }

    let module_functions: Vec<&SkeletonFunction> = functions
        .iter()
        .filter(|f: &&SkeletonFunction| !f.nested && method_class(&f.qualname).is_none())
        .collect();
    for func in &module_functions {
        render_function(&mut out, func, 0);
        for inner in functions.iter().filter(|f: &&SkeletonFunction| {
            f.nested
                && f.qualname
                    .starts_with(&format!("{}.<locals>.", func.qualname))
        }) {
            render_function(&mut out, inner, 1);
        }
        out.push('\n');
    }
    let orphan_nested: Vec<&SkeletonFunction> = functions
        .iter()
        .filter(|f: &&SkeletonFunction| {
            f.nested
                && !functions.iter().any(|t: &SkeletonFunction| {
                    !t.nested && f.qualname.starts_with(&format!("{}.<locals>.", t.qualname))
                })
        })
        .collect();
    for func in orphan_nested {
        render_function(&mut out, func, 0);
        out.push('\n');
    }
    out
}

fn method_class(qualname: &str) -> Option<String> {
    if qualname.contains("<locals>") {
        return None;
    }
    let (class, method): (&str, &str) = qualname.split_once('.')?;
    if method.contains('.') {
        return None;
    }
    let class_ok: bool = !class.is_empty()
        && class
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_uppercase())
        && class
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
    class_ok.then(|| class.to_owned())
}

fn class_names(functions: &[SkeletonFunction]) -> Vec<String> {
    let mut names: Vec<String> = functions
        .iter()
        .filter_map(|f: &SkeletonFunction| method_class(&f.qualname))
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn render_method(out: &mut String, func: &SkeletonFunction) {
    let prefix: &str = match func.kind {
        CodeKind::Coroutine | CodeKind::AsyncGenerator => "async def",
        CodeKind::Function | CodeKind::Generator => "def",
    };
    let mut parts: Vec<String> = vec!["self".to_owned()];
    for param in &func.params {
        if param.name == "self" {
            continue;
        }
        parts.push(param.annotation.as_ref().map_or_else(
            || param.name.clone(),
            |ann: &String| format!("{}: {ann}", param.name),
        ));
    }
    let ret: String = func
        .return_annotation
        .as_ref()
        .map_or_else(String::new, |r: &String| format!(" -> {r}"));
    out.push_str("    ");
    out.push_str(prefix);
    out.push(' ');
    out.push_str(&func.name);
    out.push('(');
    out.push_str(&parts.join(", "));
    out.push(')');
    out.push_str(&ret);
    out.push_str(":\n");
    out.push_str("        ...  # body compiled to native code\n");
}

fn render_function(out: &mut String, func: &SkeletonFunction, indent: usize) {
    let pad: String = "    ".repeat(indent);
    let prefix: &str = match func.kind {
        CodeKind::Coroutine | CodeKind::AsyncGenerator => "async def",
        CodeKind::Function | CodeKind::Generator => "def",
    };
    let params: String = func
        .params
        .iter()
        .map(|p: &SkeletonParam| {
            p.annotation.as_ref().map_or_else(
                || p.name.clone(),
                |ann: &String| format!("{}: {ann}", p.name),
            )
        })
        .collect::<Vec<String>>()
        .join(", ");
    let ret: String = func
        .return_annotation
        .as_ref()
        .map_or_else(String::new, |r: &String| format!(" -> {r}"));
    out.push_str(&pad);
    out.push_str(prefix);
    out.push(' ');
    out.push_str(&func.name);
    out.push('(');
    out.push_str(&params);
    out.push(')');
    out.push_str(&ret);
    out.push_str(":\n");
    let body_pad: String = "    ".repeat(indent + 1);
    let note: &str = match func.kind {
        CodeKind::Generator => "generator body compiled to native code",
        CodeKind::Coroutine => "coroutine body compiled to native code",
        CodeKind::AsyncGenerator => "async generator body compiled to native code",
        CodeKind::Function => "body compiled to native code",
    };
    out.push_str(&body_pad);
    out.push_str("...  # ");
    out.push_str(note);
    out.push('\n');
}

fn render_docstring(doc: &str) -> String {
    if doc.contains('\n') || doc.contains("\"\"\"") {
        format!("'''{doc}'''")
    } else {
        format!("\"\"\"{doc}\"\"\"")
    }
}

const KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn comprehension_names_filtered() {
        assert!(is_comprehension("<genexpr>"));
        assert!(!is_comprehension("run_one"));
    }

    #[test]
    fn module_code_detected() {
        assert!(is_module_code(
            "<module sample_app.core>",
            "sample_app.core"
        ));
        assert!(!is_module_code("compute_checksum", "sample_app.core"));
    }

    #[test]
    fn plain_identifier_rules() {
        assert!(is_plain_identifier("compute_checksum"));
        assert!(!is_plain_identifier("return"));
        assert!(!is_plain_identifier("<genexpr>"));
        assert!(!is_plain_identifier("list[int]"));
    }

    #[test]
    fn real_corpus_binds_typed_signatures_correctly() {
        use crate::const_blob::parse_constants;
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe");
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let skeleton: NuitkaSkeleton = reconstruct(&parse_constants(&image));
        let core: &SkeletonModule = skeleton
            .modules
            .iter()
            .find(|m: &&SkeletonModule| m.name == "sample_app.core")
            .expect("core module recovered");

        let checksum: &SkeletonFunction = core
            .functions
            .iter()
            .find(|f: &&SkeletonFunction| f.name == "compute_checksum")
            .expect("compute_checksum bound");
        assert_eq!(checksum.params.len(), 1);
        assert_eq!(checksum.params[0].name, "data");
        assert_eq!(checksum.params[0].annotation.as_deref(), Some("bytes"));
        assert_eq!(checksum.return_annotation.as_deref(), Some("int"));

        let pipeline: &SkeletonFunction = core
            .functions
            .iter()
            .find(|f: &&SkeletonFunction| f.name == "transform_pipeline")
            .expect("transform_pipeline bound");
        assert_eq!(pipeline.return_annotation.as_deref(), Some("list[Any]"));
        assert!(
            pipeline
                .params
                .iter()
                .any(|p: &SkeletonParam| p.name == "items"),
            "transform_pipeline params: {:?}",
            pipeline.params
        );

        assert!(
            core.functions.iter().any(|f: &SkeletonFunction| f.nested
                && f.qualname == "transform_pipeline.<locals>.run_one"),
            "nested run_one recovered from <locals> qualname"
        );

        let utils: &SkeletonModule = skeleton
            .modules
            .iter()
            .find(|m: &&SkeletonModule| m.name == "sample_app.utils")
            .expect("utils module recovered");
        let slugify: &SkeletonFunction = utils
            .functions
            .iter()
            .find(|f: &&SkeletonFunction| f.name == "slugify")
            .expect("slugify bound");
        assert_eq!(slugify.return_annotation.as_deref(), Some("str"));
    }

    #[test]
    fn real_corpus_binds_dedup_and_locals_function_names() {
        use crate::const_blob::parse_constants;
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe");
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let skeleton: NuitkaSkeleton = reconstruct(&parse_constants(&image));
        let names: BTreeSet<String> = skeleton
            .modules
            .iter()
            .flat_map(|m: &SkeletonModule| m.functions.iter())
            .map(|f: &SkeletonFunction| f.name.clone())
            .collect();
        for proven in ["withdraw", "apply_interest", "total", "run"] {
            assert!(
                names.contains(proven),
                "dedup/locals-proven function {proven} must be name-bound; got {names:?}"
            );
        }
        let bound: usize = [
            "compute_checksum",
            "transform_pipeline",
            "normalize_scores",
            "magic_sum",
            "deposit",
            "withdraw",
            "apply_interest",
            "balance",
            "total",
            "clamp",
            "slugify",
            "weighted_mean",
            "make_counter",
            "squares",
            "run",
            "main",
            "run_one",
            "increment",
        ]
        .iter()
        .filter(|t: &&&str| names.contains(**t))
        .count();
        assert!(bound >= 18, "expected >= 18/19 name-bound, got {bound}");
    }

    #[test]
    fn real_corpus_reconstructs_classes_and_omits_invented_constants() {
        use crate::const_blob::parse_constants;
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe");
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let skeleton: NuitkaSkeleton = reconstruct(&parse_constants(&image));
        let models: &SkeletonModule = skeleton
            .modules
            .iter()
            .find(|m: &&SkeletonModule| m.name == "sample_app.models")
            .expect("models recovered");
        assert!(
            models.python.contains("class Account:") && models.python.contains("def deposit(self"),
            "models must reconstruct Account as a class with self-methods:\n{}",
            models.python
        );
        assert!(
            models.constant_names.is_empty(),
            "invented module constants must be dropped, got {:?}",
            models.constant_names
        );
        assert!(
            !models.python.contains("USD = ..."),
            "the value 'USD' must not be invented as a module constant:\n{}",
            models.python
        );
        assert!(
            models.docstring.is_none(),
            "module docstring is not structurally distinguishable and must be omitted, got {:?}",
            models.docstring
        );
        assert!(
            models.python.contains("signatures are approximate"),
            "skeleton must carry the approximate-signature honesty caveat"
        );
    }
}
