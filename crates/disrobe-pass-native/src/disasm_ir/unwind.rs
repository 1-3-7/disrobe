use gimli::{
    BaseAddresses, CieOrFde, CommonInformationEntry, EhFrame, EhFrameOffset, EndianSlice,
    FrameDescriptionEntry, LittleEndian, UnwindSection as _,
};
use object::{Object as _, ObjectSection as _};

type EhSlice<'a> = EndianSlice<'a, LittleEndian>;

fn parse_cie<'a>(
    section: &EhFrame<EhSlice<'a>>,
    bases: &BaseAddresses,
    offset: EhFrameOffset<usize>,
) -> gimli::Result<CommonInformationEntry<EhSlice<'a>>> {
    section.cie_from_offset(bases, offset)
}

pub(super) fn visit_frame_ranges(
    file: &object::File<'_>,
    text_base: u64,
    limit: usize,
    mut visit: impl FnMut(u64, u64),
) {
    let Some(section): Option<object::Section<'_, '_>> = file.section_by_name(".eh_frame") else {
        return;
    };
    let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
        return;
    };
    let bases: BaseAddresses = BaseAddresses::default()
        .set_eh_frame(section.address())
        .set_text(text_base);
    let eh_frame: EhFrame<EhSlice<'_>> = EhFrame::new(data, LittleEndian);
    let mut entries: gimli::CfiEntriesIter<'_, EhFrame<EhSlice<'_>>, EhSlice<'_>> =
        eh_frame.entries(&bases);
    for _ in 0..limit {
        let Ok(Some(entry)): gimli::Result<
            Option<CieOrFde<'_, EhFrame<EhSlice<'_>>, EhSlice<'_>>>,
        > = entries.next() else {
            return;
        };
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde): gimli::Result<FrameDescriptionEntry<EhSlice<'_>>> = partial.parse(parse_cie)
        else {
            continue;
        };
        visit(fde.initial_address(), fde.len());
    }
}
