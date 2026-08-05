use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

pub(crate) fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name()
            .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
    })?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        let next_off: usize = file
            .symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
                    && s.name().is_ok_and(|n: &str| !n.is_empty())
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len());
        next_off.min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}
