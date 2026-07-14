use std::collections::BTreeMap;

use pdb::FallibleIterator as _;

use crate::error::Result;
use crate::pdb_cxx::pdb_err;

const MAX_TYPE_RECORDS: usize = 4_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum UdtFamily {
    ClassLike,
    Union,
    Enum,
}

#[derive(Debug)]
pub(crate) struct TypeCatalog<'t> {
    finder: pdb::TypeFinder<'t>,
    defining: BTreeMap<(UdtFamily, String), pdb::TypeIndex>,
}

impl<'t> TypeCatalog<'t> {
    pub(crate) fn build(type_info: &'t pdb::TypeInformation<'_>) -> Result<Self> {
        if type_info.len() > MAX_TYPE_RECORDS {
            return Err(crate::error::Error::Pdb(format!(
                "TPI stream exceeds the bound of {MAX_TYPE_RECORDS} records ({} present)",
                type_info.len()
            )));
        }
        let mut finder: pdb::TypeFinder<'t> = type_info.finder();
        let mut defining: BTreeMap<(UdtFamily, String), pdb::TypeIndex> = BTreeMap::new();
        let mut iter: pdb::TypeIter<'t> = type_info.iter();
        while let Some(item) = iter.next().map_err(pdb_err)? {
            finder.update(&iter);
            let idx: pdb::TypeIndex = item.index();
            let Ok(data) = item.parse() else {
                continue;
            };
            record_definition(&mut defining, idx, &data);
        }
        Ok(Self { finder, defining })
    }

    pub(crate) fn get(&self, index: pdb::TypeIndex) -> Result<pdb::TypeData<'t>> {
        self.finder
            .find(index)
            .map_err(pdb_err)?
            .parse()
            .map_err(pdb_err)
    }

    pub(crate) fn resolve(
        &self,
        index: pdb::TypeIndex,
    ) -> Result<(pdb::TypeIndex, pdb::TypeData<'t>)> {
        let data: pdb::TypeData<'t> = self.get(index)?;
        let Some(target) = self.forward_ref_target(&data) else {
            return Ok((index, data));
        };
        if target == index {
            return Ok((index, data));
        }
        let redirected: pdb::TypeData<'t> = self.get(target)?;
        Ok((target, redirected))
    }

    fn forward_ref_target(&self, data: &pdb::TypeData<'t>) -> Option<pdb::TypeIndex> {
        let (family, name, unique_name, is_fwdref) = udt_identity(data)?;
        if !is_fwdref {
            return None;
        }
        let key: (UdtFamily, String) = (family, defining_key(name, unique_name));
        self.defining.get(&key).copied()
    }

    pub(crate) fn defining_indices(&self, family: UdtFamily) -> Vec<pdb::TypeIndex> {
        let mut out: Vec<pdb::TypeIndex> = self
            .defining
            .iter()
            .filter(|((f, _), _)| *f == family)
            .map(|(_, idx)| *idx)
            .collect();
        out.sort_by_key(|idx: &pdb::TypeIndex| idx.0);
        out.dedup();
        out
    }
}

fn record_definition(
    defining: &mut BTreeMap<(UdtFamily, String), pdb::TypeIndex>,
    idx: pdb::TypeIndex,
    data: &pdb::TypeData<'_>,
) {
    let Some((family, name, unique_name, is_fwdref)) = udt_identity(data) else {
        return;
    };
    if is_fwdref || name.is_empty() {
        return;
    }
    let key: (UdtFamily, String) = (family, defining_key(name, unique_name));
    defining.entry(key).or_insert(idx);
}

type UdtIdentity<'t> = (
    UdtFamily,
    pdb::RawString<'t>,
    Option<pdb::RawString<'t>>,
    bool,
);

fn udt_identity<'t>(data: &pdb::TypeData<'t>) -> Option<UdtIdentity<'t>> {
    match data {
        pdb::TypeData::Class(c) => Some((
            UdtFamily::ClassLike,
            c.name,
            c.unique_name,
            c.properties.forward_reference(),
        )),
        pdb::TypeData::Union(u) => Some((
            UdtFamily::Union,
            u.name,
            u.unique_name,
            u.properties.forward_reference(),
        )),
        pdb::TypeData::Enumeration(e) => Some((
            UdtFamily::Enum,
            e.name,
            e.unique_name,
            e.properties.forward_reference(),
        )),
        _ => None,
    }
}

fn defining_key(name: pdb::RawString<'_>, unique_name: Option<pdb::RawString<'_>>) -> String {
    unique_name.unwrap_or(name).to_string().into_owned()
}
