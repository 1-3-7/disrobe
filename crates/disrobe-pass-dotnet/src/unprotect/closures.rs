use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{MethodBody, OperandValue};
use crate::model::{AssemblyModel, FieldModel, MethodModel, Resolver, TypeModel};
use crate::pe::PeImage;
use crate::signature::TypeSig;

use super::confuserex::method_body;

pub(crate) const LAYER_CLOSURES: &str = "renamed compiler-generated closure types and helpers";

const DISPLAY_CLASS_PREFIX: &str = "<>c__DisplayClass";
const SINGLETON_TYPE: &str = "<>c";
const SINGLETON_FIELD: &str = "<>9";
const CACHED_DELEGATE_PREFIX: &str = "<>9__";
const THIS_FIELD: &str = "<>4__this";
const FIELD_STATIC: u16 = 0x0010;
const MAX_STORE_DISTANCE: usize = 4;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ClosureRenames {
    pub(crate) types: BTreeMap<u32, String>,
    pub(crate) members: BTreeMap<u32, String>,
}

impl ClosureRenames {
    pub(crate) fn len(&self) -> usize {
        self.types.len() + self.members.len()
    }
}

fn named_token(sig: &TypeSig) -> Option<u32> {
    match sig {
        TypeSig::NamedType { token, .. } => Some(*token),
        TypeSig::ByRef(inner) => named_token(inner),
        _ => None,
    }
}

fn is_generated_name(name: &str) -> bool {
    name.starts_with('<')
}

fn canonical_display_index(name: &str) -> Option<u32> {
    let rest: &str = name.strip_prefix(DISPLAY_CLASS_PREFIX)?;
    let (index, _): (&str, &str) = rest.split_once('_')?;
    index.parse::<u32>().ok()
}

fn canonical_cache_ordinals(name: &str) -> Option<(u32, u32)> {
    let rest: &str = name.strip_prefix(CACHED_DELEGATE_PREFIX)?;
    let (index, ordinal): (&str, &str) = rest.split_once('_')?;
    Some((index.parse::<u32>().ok()?, ordinal.parse::<u32>().ok()?))
}

fn canonical_lambda_ordinals(name: &str) -> Option<(u32, u32)> {
    let close: usize = name.strip_prefix('<')?.find('>')? + 1;
    let rest: &str = name[close + 1..].strip_prefix("b__")?;
    let (index, ordinal): (&str, &str) = rest.split_once('_')?;
    Some((index.parse::<u32>().ok()?, ordinal.parse::<u32>().ok()?))
}

const fn is_static_field(field: &FieldModel) -> bool {
    field.flags & FIELD_STATIC != 0
}

fn stores_this(body: &MethodBody, field: u32) -> bool {
    body.instructions.windows(2).any(|pair| {
        pair[0].name == "ldarg.0"
            && pair[1].name == "stfld"
            && pair[1].operand == OperandValue::Token(field)
    })
}

struct Bodies<'a> {
    image: &'a [u8],
    pe: &'a PeImage,
    rewritten: &'a BTreeMap<u32, MethodBody>,
    parsed: BTreeMap<u32, Option<MethodBody>>,
}

impl Bodies<'_> {
    fn body(&mut self, m: &MethodModel) -> Option<&MethodBody> {
        if let Some(body) = self.rewritten.get(&m.token) {
            return Some(body);
        }
        if !self.parsed.contains_key(&m.token) {
            let body: Option<MethodBody> = method_body(self.image, self.pe, m);
            self.parsed.insert(m.token, body);
        }
        self.parsed.get(&m.token).and_then(Option::as_ref)
    }

    fn tokens(&mut self, m: &MethodModel) -> BTreeSet<u32> {
        self.body(m)
            .map_or_else(BTreeSet::new, |body: &MethodBody| {
                body.instructions
                    .iter()
                    .filter_map(|i| match i.operand {
                        OperandValue::Token(token) => Some(token),
                        _ => None,
                    })
                    .collect()
            })
    }

    fn ldftn_targets(&mut self, m: &MethodModel) -> BTreeSet<u32> {
        self.body(m)
            .map_or_else(BTreeSet::new, |body: &MethodBody| {
                body.instructions
                    .iter()
                    .filter_map(|i| match i.operand {
                        OperandValue::Token(token)
                            if i.name == "ldftn" || i.name == "ldvirtftn" =>
                        {
                            Some(token)
                        }
                        _ => None,
                    })
                    .collect()
            })
    }

    fn delegate_cache_pairs(&mut self, m: &MethodModel) -> Vec<(u32, u32)> {
        let Some(body) = self.body(m) else {
            return Vec::new();
        };
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        for (index, ins) in body.instructions.iter().enumerate() {
            if ins.name != "ldftn" {
                continue;
            }
            let OperandValue::Token(method) = ins.operand else {
                continue;
            };
            let store: Option<u32> = body.instructions[index + 1..]
                .iter()
                .take(MAX_STORE_DISTANCE)
                .find_map(|later| match later.operand {
                    OperandValue::Token(field)
                        if later.name == "stsfld" || later.name == "stfld" =>
                    {
                        Some(field)
                    }
                    _ => None,
                });
            if let Some(field) = store {
                pairs.push((method, field));
            }
        }
        pairs
    }
}

struct Owners<'a> {
    enclosing: &'a TypeModel,
    resolver: &'a Resolver,
    member_renames: &'a BTreeMap<u32, String>,
    references: Vec<(usize, BTreeSet<u32>)>,
}

impl<'a> Owners<'a> {
    fn new(
        enclosing: &'a TypeModel,
        resolver: &'a Resolver,
        member_renames: &'a BTreeMap<u32, String>,
        bodies: &mut Bodies<'_>,
    ) -> Self {
        let references: Vec<(usize, BTreeSet<u32>)> = enclosing
            .methods
            .iter()
            .enumerate()
            .filter(|(_, m): &(usize, &MethodModel)| {
                !resolver.has_compiler_generated_attribute(m.token)
            })
            .map(|(ordinal, m): (usize, &MethodModel)| (ordinal, bodies.tokens(m)))
            .collect();
        Self {
            enclosing,
            resolver,
            member_renames,
            references,
        }
    }

    fn owner_of(&self, wanted: &BTreeSet<u32>) -> Option<(u32, &'a MethodModel)> {
        self.references
            .iter()
            .find(|(_, tokens): &&(usize, BTreeSet<u32>)| !tokens.is_disjoint(wanted))
            .and_then(|(ordinal, _): &(usize, BTreeSet<u32>)| {
                Some((
                    u32::try_from(*ordinal).ok()?,
                    self.enclosing.methods.get(*ordinal)?,
                ))
            })
    }

    fn name_of(&self, owner: Option<(u32, &MethodModel)>) -> String {
        owner.map_or_else(
            || "Lambda".to_owned(),
            |(_, m): (u32, &MethodModel)| {
                self.member_renames
                    .get(&m.token)
                    .cloned()
                    .unwrap_or_else(|| m.name.clone())
            },
        )
    }

    fn is_generated(&self, token: u32) -> bool {
        self.resolver.has_compiler_generated_attribute(token)
    }
}

fn closure_types_of<'a>(
    model: &'a AssemblyModel,
    resolver: &Resolver,
) -> BTreeMap<u32, Vec<&'a TypeModel>> {
    let mut out: BTreeMap<u32, Vec<&'a TypeModel>> = BTreeMap::new();
    for ty in &model.types {
        let Some(enclosing): Option<u32> = resolver.enclosing_type_token(ty.token) else {
            continue;
        };
        if !resolver.has_compiler_generated_attribute(ty.token)
            || resolver.type_implements_any_interface(ty.token)
        {
            continue;
        }
        out.entry(enclosing).or_default().push(ty);
    }
    out
}

fn seeded_ordinals(nested: &[&TypeModel]) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut taken: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for ty in nested {
        for f in &ty.fields {
            if let Some((index, ordinal)) = canonical_cache_ordinals(&f.name) {
                taken.entry(index).or_default().insert(ordinal);
            }
        }
        for m in &ty.methods {
            if let Some((index, ordinal)) = canonical_lambda_ordinals(&m.name) {
                taken.entry(index).or_default().insert(ordinal);
            }
        }
    }
    taken
}

fn free_ordinal(taken: &mut BTreeMap<u32, BTreeSet<u32>>, index: u32) -> u32 {
    let slots: &mut BTreeSet<u32> = taken.entry(index).or_default();
    let mut ordinal: u32 = 0;
    while slots.contains(&ordinal) {
        ordinal = ordinal.saturating_add(1);
    }
    slots.insert(ordinal);
    ordinal
}

pub(crate) fn closure_renames(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    model: &AssemblyModel,
    rewritten: &BTreeMap<u32, MethodBody>,
    member_renames: &BTreeMap<u32, String>,
) -> ClosureRenames {
    let by_token: BTreeMap<u32, &TypeModel> = model
        .types
        .iter()
        .map(|t: &TypeModel| (t.token, t))
        .collect();
    let mut bodies: Bodies<'_> = Bodies {
        image,
        pe,
        rewritten,
        parsed: BTreeMap::new(),
    };
    let mut out: ClosureRenames = ClosureRenames::default();
    let mut display_types: BTreeMap<u32, u32> = BTreeMap::new();
    for (enclosing_token, nested) in closure_types_of(model, resolver) {
        let Some(enclosing): Option<&&TypeModel> = by_token.get(&enclosing_token) else {
            continue;
        };
        let owners: Owners<'_> = Owners::new(enclosing, resolver, member_renames, &mut bodies);
        let mut taken: BTreeMap<u32, BTreeSet<u32>> = seeded_ordinals(&nested);
        let mut pairs: BTreeMap<u32, u32> = BTreeMap::new();
        let mut delegates: BTreeSet<u32> = BTreeSet::new();
        for m in &enclosing.methods {
            if owners.is_generated(m.token) {
                continue;
            }
            pairs.extend(bodies.delegate_cache_pairs(m));
            delegates.extend(bodies.ldftn_targets(m));
        }
        for ty in &nested {
            for m in &ty.methods {
                delegates.extend(bodies.ldftn_targets(m));
            }
        }
        for ty in &nested {
            let singleton: bool = ty.fields.iter().any(|f: &FieldModel| {
                is_static_field(f) && named_token(&f.field_type) == Some(ty.token)
            });
            let member_tokens: BTreeSet<u32> = ty
                .fields
                .iter()
                .map(|f: &FieldModel| f.token)
                .chain(ty.methods.iter().map(|m: &MethodModel| m.token))
                .chain(std::iter::once(ty.token))
                .collect();
            let type_owner: Option<(u32, &MethodModel)> = owners.owner_of(&member_tokens);
            let index: u32 = canonical_display_index(&ty.name)
                .or_else(|| type_owner.map(|(ordinal, _): (u32, &MethodModel)| ordinal))
                .unwrap_or(0);
            if !is_generated_name(&ty.name) {
                let name: String = if singleton {
                    SINGLETON_TYPE.to_owned()
                } else {
                    format!("{DISPLAY_CLASS_PREFIX}{index}_0")
                };
                out.types.insert(ty.token, name);
            }
            if !singleton {
                display_types.insert(ty.token, index);
            }
            let field_names: BTreeMap<u32, &str> = ty
                .fields
                .iter()
                .map(|f: &FieldModel| (f.token, f.name.as_str()))
                .collect();
            let mut paired_fields: BTreeMap<u32, (u32, u32)> = BTreeMap::new();
            let mut local_functions: u32 = 0;
            for m in &ty.methods {
                if m.name == ".ctor" || m.name == ".cctor" || is_generated_name(&m.name) {
                    continue;
                }
                let lambda_owner: Option<(u32, &MethodModel)> =
                    owners.owner_of(&BTreeSet::from([m.token])).or(type_owner);
                let owner_index: u32 =
                    lambda_owner.map_or(index, |(ordinal, _): (u32, &MethodModel)| ordinal);
                if !singleton && !delegates.contains(&m.token) {
                    // a closure method never loaded as a function pointer is a captured local
                    // function called directly, so it takes the local-function mangling
                    out.members.insert(
                        m.token,
                        format!(
                            "<{}>g__Local{local_functions}|{owner_index}_{local_functions}",
                            owners.name_of(lambda_owner)
                        ),
                    );
                    local_functions = local_functions.saturating_add(1);
                    continue;
                }
                let cache: Option<u32> = pairs.get(&m.token).copied();
                let (cache_index, ordinal): (u32, u32) = cache
                    .and_then(|field: u32| field_names.get(&field))
                    .and_then(|name: &&str| canonical_cache_ordinals(name))
                    .unwrap_or_else(|| (owner_index, free_ordinal(&mut taken, owner_index)));
                out.members.insert(
                    m.token,
                    format!(
                        "<{}>b__{cache_index}_{ordinal}",
                        owners.name_of(lambda_owner)
                    ),
                );
                if let Some(field) = cache {
                    paired_fields.insert(field, (cache_index, ordinal));
                }
            }
            let owner_is_instance: bool =
                type_owner.is_some_and(|(_, m): (u32, &MethodModel)| !m.is_static());
            for f in &ty.fields {
                if is_generated_name(&f.name) {
                    continue;
                }
                if singleton && named_token(&f.field_type) == Some(ty.token) {
                    out.members.insert(f.token, SINGLETON_FIELD.to_owned());
                } else if let Some((cache_index, ordinal)) = paired_fields.get(&f.token) {
                    out.members.insert(
                        f.token,
                        format!("{CACHED_DELEGATE_PREFIX}{cache_index}_{ordinal}"),
                    );
                } else if !singleton
                    && !is_static_field(f)
                    && named_token(&f.field_type) == Some(enclosing_token)
                    && owner_is_instance
                    && type_owner.is_some_and(|(_, m): (u32, &MethodModel)| {
                        bodies
                            .body(m)
                            .is_some_and(|body: &MethodBody| stores_this(body, f.token))
                    })
                {
                    out.members.insert(f.token, THIS_FIELD.to_owned());
                }
            }
        }
    }
    for ty in &model.types {
        let mut local: u32 = 0;
        for helper in &ty.methods {
            if is_generated_name(&helper.name)
                || !helper.is_static()
                || !resolver.has_compiler_generated_attribute(helper.token)
            {
                continue;
            }
            let Some(index): Option<u32> =
                helper.signature.params.iter().find_map(|p: &TypeSig| {
                    named_token(p).and_then(|t: u32| display_types.get(&t).copied())
                })
            else {
                continue;
            };
            let mut owner: Option<&MethodModel> = None;
            for m in &ty.methods {
                if m.token == helper.token || resolver.has_compiler_generated_attribute(m.token) {
                    continue;
                }
                if bodies.tokens(m).contains(&helper.token) {
                    owner = Some(m);
                    break;
                }
            }
            let owner_text: String = owner.map_or_else(
                || "Lambda".to_owned(),
                |m: &MethodModel| {
                    member_renames
                        .get(&m.token)
                        .cloned()
                        .unwrap_or_else(|| m.name.clone())
                },
            );
            out.members.insert(
                helper.token,
                format!("<{owner_text}>g__Local{local}|{index}_{local}"),
            );
            local = local.saturating_add(1);
        }
    }
    out
}
