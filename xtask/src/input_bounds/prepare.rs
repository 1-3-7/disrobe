use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::visit_mut::VisitMut;
use syn::{
    Attribute, Block, Expr, ExprCall, ExprPath, ExprRepeat, File, Ident, ImplItem, ImplItemConst,
    ImplItemFn, Item, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemTrait,
    ItemUse, Lit, Meta, Pat, Path, PathSegment, Signature, Stmt, Token, TraitItem, TraitItemFn,
    Type, UseTree, token,
};

pub(super) const MACRO_SCOPE: &str = "__macro";

pub(super) fn parse(text: &str) -> syn::Result<File> {
    let mut file: File = syn::parse_file(text)?;
    Expander.visit_file_mut(&mut file);
    Ok(file)
}

struct Expander;

impl VisitMut for Expander {
    fn visit_file_mut(&mut self, node: &mut File) {
        node.items.retain(|item: &Item| !is_test_item(item));
        syn::visit_mut::visit_file_mut(self, node);
    }

    fn visit_item_mod_mut(&mut self, node: &mut ItemMod) {
        if let Some((_, items)) = &mut node.content {
            items.retain(|item: &Item| !is_test_item(item));
        }
        syn::visit_mut::visit_item_mod_mut(self, node);
    }

    fn visit_item_impl_mut(&mut self, node: &mut ItemImpl) {
        node.items
            .retain(|item: &ImplItem| !is_test_attrs(impl_item_attrs(item)));
        syn::visit_mut::visit_item_impl_mut(self, node);
    }

    fn visit_item_trait_mut(&mut self, node: &mut ItemTrait) {
        node.items
            .retain(|item: &TraitItem| !is_test_attrs(trait_item_attrs(item)));
        syn::visit_mut::visit_item_trait_mut(self, node);
    }

    fn visit_block_mut(&mut self, node: &mut Block) {
        node.stmts.retain(|stmt: &Stmt| match stmt {
            Stmt::Item(item) => !is_test_item(item),
            Stmt::Local(_) | Stmt::Expr(..) | Stmt::Macro(_) => true,
        });
        syn::visit_mut::visit_block_mut(self, node);
    }

    fn visit_expr_mut(&mut self, node: &mut Expr) {
        if let Expr::Macro(expr) = node
            && let Some(call) = expand(&expr.mac)
        {
            *node = call;
        }
        syn::visit_mut::visit_expr_mut(self, node);
    }

    fn visit_stmt_mut(&mut self, node: &mut Stmt) {
        if let Stmt::Macro(stmt) = node
            && let Some(call) = expand(&stmt.mac)
        {
            *node = Stmt::Expr(call, stmt.semi_token);
        }
        syn::visit_mut::visit_stmt_mut(self, node);
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(inner) => &inner.attrs,
        ImplItem::Fn(inner) => &inner.attrs,
        ImplItem::Type(inner) => &inner.attrs,
        ImplItem::Macro(inner) => &inner.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(inner) => &inner.attrs,
        TraitItem::Fn(inner) => &inner.attrs,
        TraitItem::Type(inner) => &inner.attrs,
        TraitItem::Macro(inner) => &inner.attrs,
        _ => &[],
    }
}

fn is_test_item(item: &Item) -> bool {
    let attrs: &[Attribute] = match item {
        Item::Const(inner) => &inner.attrs,
        Item::Enum(inner) => &inner.attrs,
        Item::ExternCrate(inner) => &inner.attrs,
        Item::Fn(inner) => &inner.attrs,
        Item::ForeignMod(inner) => &inner.attrs,
        Item::Impl(inner) => &inner.attrs,
        Item::Macro(inner) => &inner.attrs,
        Item::Mod(inner) => &inner.attrs,
        Item::Static(inner) => &inner.attrs,
        Item::Struct(inner) => &inner.attrs,
        Item::Trait(inner) => &inner.attrs,
        Item::TraitAlias(inner) => &inner.attrs,
        Item::Type(inner) => &inner.attrs,
        Item::Union(inner) => &inner.attrs,
        Item::Use(inner) => &inner.attrs,
        _ => &[],
    };
    is_test_attrs(attrs)
}

fn is_test_attrs(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr: &Attribute| {
        if attr.path().is_ident("test") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return false;
        };
        let condition: String = list
            .tokens
            .to_string()
            .chars()
            .filter(|c: &char| !c.is_whitespace())
            .collect();
        condition == "test" || condition.starts_with("all(test,") || condition == "all(test)"
    })
}

fn expand(mac: &syn::Macro) -> Option<Expr> {
    let name: String = mac.path.segments.last()?.ident.to_string();
    let mut args: Vec<Expr> = if name == "matches" {
        mac.parse_body_with(matches_args).ok()?
    } else {
        mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
            .map(|args: Punctuated<Expr, Token![,]>| args.into_iter().collect())
            .or_else(|_| {
                mac.parse_body_with(repeat_args)
                    .map(|repeat: Expr| vec![repeat])
            })
            .ok()?
    };
    let inline: Vec<Expr> = args
        .iter()
        .filter_map(|arg: &Expr| match arg {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(text) => Some(text.value()),
                _ => None,
            },
            _ => None,
        })
        .flat_map(|text: String| inline_format_idents(&text))
        .map(|ident: String| path_expr(&[ident.as_str()]))
        .collect();
    args.extend(inline);
    Some(Expr::Call(ExprCall {
        attrs: Vec::new(),
        func: Box::new(path_expr(&[MACRO_SCOPE, &name])),
        paren_token: token::Paren::default(),
        args: args.into_iter().collect(),
    }))
}

fn matches_args(input: ParseStream<'_>) -> syn::Result<Vec<Expr>> {
    let scrutinee: Expr = input.parse()?;
    let _: Token![,] = input.parse()?;
    let _: Pat = Pat::parse_multi_with_leading_vert(input)?;
    let mut out: Vec<Expr> = vec![scrutinee];
    if input.peek(Token![if]) {
        let _: Token![if] = input.parse()?;
        out.push(input.parse()?);
    }
    let _: Option<Token![,]> = input.parse()?;
    Ok(out)
}

fn repeat_args(input: ParseStream<'_>) -> syn::Result<Expr> {
    let element: Expr = input.parse()?;
    let semi_token: Token![;] = input.parse()?;
    let len: Expr = input.parse()?;
    Ok(Expr::Repeat(ExprRepeat {
        attrs: Vec::new(),
        bracket_token: token::Bracket::default(),
        expr: Box::new(element),
        semi_token,
        len: Box::new(len),
    }))
}

fn inline_format_idents(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest: &str = text;
    while let Some(open) = rest.find('{') {
        rest = &rest[open + 1..];
        if rest.starts_with('{') {
            rest = &rest[1..];
            continue;
        }
        let end: usize = rest.find(['}', ':']).unwrap_or(rest.len());
        let candidate: &str = &rest[..end];
        let is_ident: bool = candidate
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
            && candidate
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
        if is_ident {
            out.push(candidate.to_owned());
        }
        rest = &rest[end..];
    }
    out
}

fn path_expr(segments: &[&str]) -> Expr {
    let mut path: Path = Path {
        leading_colon: None,
        segments: Punctuated::new(),
    };
    for segment in segments {
        path.segments
            .push(PathSegment::from(Ident::new(segment, Span::call_site())));
    }
    Expr::Path(ExprPath {
        attrs: Vec::new(),
        qself: None,
        path,
    })
}

pub(super) fn macro_name(expr: &ExprCall) -> Option<String> {
    let Expr::Path(func) = &*expr.func else {
        return None;
    };
    let mut segments: syn::punctuated::Iter<'_, PathSegment> = func.path.segments.iter();
    let scope: &PathSegment = segments.next()?;
    let name: &PathSegment = segments.next()?;
    (scope.ident == MACRO_SCOPE && segments.next().is_none()).then(|| name.ident.to_string())
}

pub(super) fn tokens_contain(tokens: &TokenStream, name: &str, after_dot: bool) -> bool {
    let mut previous_dot: bool = false;
    for tree in tokens.clone() {
        match tree {
            TokenTree::Ident(ident) => {
                if ident == name && (previous_dot || !after_dot) {
                    return true;
                }
                previous_dot = false;
            }
            TokenTree::Group(group) => {
                if tokens_contain(&group.stream(), name, after_dot) {
                    return true;
                }
                previous_dot = false;
            }
            TokenTree::Punct(punct) => previous_dot = punct.as_char() == '.',
            TokenTree::Literal(_) => previous_dot = false,
        }
    }
    false
}

#[derive(Debug, Clone)]
pub(super) struct FnRef<'a> {
    pub(super) ident: &'a Ident,
    pub(super) sig: &'a Signature,
    pub(super) block: &'a Block,
    pub(super) owner: Option<String>,
    pub(super) file: usize,
}

#[derive(Debug, Default)]
pub(super) struct Index<'a> {
    pub(super) fns: BTreeMap<String, Vec<FnRef<'a>>>,
    pub(super) const_files: BTreeMap<String, BTreeSet<usize>>,
    pub(super) imports: BTreeMap<usize, BTreeSet<(String, String)>>,
    pub(super) codes: BTreeSet<(String, String, String)>,
}

pub(super) fn index(files: &[File]) -> Index<'_> {
    let mut indexer: Indexer<'_> = Indexer {
        index: Index::default(),
        file: 0,
        owner: None,
    };
    for (file_index, file) in files.iter().enumerate() {
        indexer.file = file_index;
        indexer.visit_file(file);
    }
    indexer.index
}

struct Indexer<'a> {
    index: Index<'a>,
    file: usize,
    owner: Option<String>,
}

impl<'a> Indexer<'a> {
    fn add_fn(&mut self, sig: &'a Signature, block: &'a Block) {
        let owner: Option<String> = self.owner.clone();
        let file: usize = self.file;
        self.index
            .fns
            .entry(sig.ident.to_string())
            .or_default()
            .push(FnRef {
                ident: &sig.ident,
                sig,
                block,
                owner,
                file,
            });
    }

    fn add_const(&mut self, ident: &Ident) {
        self.index
            .const_files
            .entry(ident.to_string())
            .or_default()
            .insert(self.file);
    }
}

impl<'a> Visit<'a> for Indexer<'a> {
    fn visit_attribute(&mut self, _: &'a Attribute) {}

    fn visit_item_fn(&mut self, node: &'a ItemFn) {
        let outer: Option<String> = self.owner.take();
        self.add_fn(&node.sig, &node.block);
        syn::visit::visit_item_fn(self, node);
        self.owner = outer;
    }

    fn visit_item_impl(&mut self, node: &'a ItemImpl) {
        let owner: Option<String> = match &*node.self_ty {
            Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment: &PathSegment| segment.ident.to_string()),
            _ => None,
        };
        let outer: Option<String> = std::mem::replace(&mut self.owner, owner);
        syn::visit::visit_item_impl(self, node);
        self.owner = outer;
    }

    fn visit_item_trait(&mut self, node: &'a ItemTrait) {
        let outer: Option<String> = self.owner.replace(node.ident.to_string());
        syn::visit::visit_item_trait(self, node);
        self.owner = outer;
    }

    fn visit_impl_item_fn(&mut self, node: &'a ImplItemFn) {
        self.add_fn(&node.sig, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'a TraitItemFn) {
        if let Some(block) = &node.default {
            self.add_fn(&node.sig, block);
        }
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_item_use(&mut self, node: &'a ItemUse) {
        let mut prefix: Vec<String> = Vec::new();
        let imports: &mut BTreeSet<(String, String)> =
            self.index.imports.entry(self.file).or_default();
        flatten_use(&node.tree, &mut prefix, imports);
    }

    fn visit_item_const(&mut self, node: &'a ItemConst) {
        self.add_const(&node.ident);
        syn::visit::visit_item_const(self, node);
    }

    fn visit_impl_item_const(&mut self, node: &'a ImplItemConst) {
        self.add_const(&node.ident);
        syn::visit::visit_impl_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'a ItemStatic) {
        self.add_const(&node.ident);
        syn::visit::visit_item_static(self, node);
    }

    fn visit_item_enum(&mut self, node: &'a ItemEnum) {
        for variant in &node.variants {
            if let Some(code) = variant.attrs.iter().find_map(diagnostic_code) {
                self.index
                    .codes
                    .insert((node.ident.to_string(), variant.ident.to_string(), code));
            }
        }
        syn::visit::visit_item_enum(self, node);
    }
}

fn flatten_use(tree: &UseTree, prefix: &mut Vec<String>, out: &mut BTreeSet<(String, String)>) {
    let last: Option<String> = prefix.last().cloned();
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(name) => {
            if let Some(module) = last {
                out.insert((module, name.ident.to_string()));
            }
        }
        UseTree::Rename(rename) => {
            if let Some(module) = last {
                out.insert((module, rename.ident.to_string()));
            }
        }
        UseTree::Glob(_) => {
            if let Some(module) = last {
                out.insert((module, "*".to_owned()));
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use(item, prefix, out);
            }
        }
    }
}

fn diagnostic_code(attr: &Attribute) -> Option<String> {
    if !attr.path().is_ident("error") {
        return None;
    }
    let Meta::List(list) = &attr.meta else {
        return None;
    };
    let text: String = list.tokens.to_string();
    let start: usize = text.find("\"DR-")? + 1;
    let code: String = text[start..]
        .chars()
        .take_while(|c: &char| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '-')
        .collect();
    let code: &str = code.trim_end_matches('-');
    (code.len() > "DR-".len()).then(|| code.to_owned())
}
