use std::io::Read as _;
use std::path::Path;

use disrobe_binfmt::containers::luks1::{
    LUKS1_HEADER_BYTES, Luks1Header, MAX_LUKS1_PAYLOAD_BYTES, MAX_LUKS1_PAYLOAD_OFFSET_BYTES,
    parse_luks1, validate_luks1_image_length, validate_luks1_raw_key_support,
};

pub(crate) struct Luks1FileProbe {
    pub(crate) prefix: Vec<u8>,
    header: Luks1Header,
}

pub(crate) enum Luks1ProbeError {
    Input(std::io::Error),
    Refused(disrobe_binfmt::Error),
}

pub(crate) fn probe(path: &Path) -> Result<Option<Luks1FileProbe>, Luks1ProbeError> {
    let file: std::fs::File = std::fs::File::open(path).map_err(Luks1ProbeError::Input)?;
    let metadata: std::fs::Metadata = file.metadata().map_err(Luks1ProbeError::Input)?;
    let mut prefix: Vec<u8> = Vec::with_capacity(LUKS1_HEADER_BYTES);
    file.take(LUKS1_HEADER_BYTES as u64)
        .read_to_end(&mut prefix)
        .map_err(Luks1ProbeError::Input)?;
    if !prefix.starts_with(b"LUKS\xba\xbe") {
        return Ok(None);
    }
    let header: Luks1Header = parse_luks1(&prefix)
        .and_then(|header: Luks1Header| {
            validate_luks1_raw_key_support(&header)?;
            validate_luks1_image_length(&header, metadata.len())?;
            Ok(header)
        })
        .map_err(Luks1ProbeError::Refused)?;
    Ok(Some(Luks1FileProbe { prefix, header }))
}

pub(crate) fn read_luks1_bounded(path: &Path, probe: &Luks1FileProbe) -> miette::Result<Vec<u8>> {
    let read_cap: u64 = MAX_LUKS1_PAYLOAD_OFFSET_BYTES
        .checked_add(MAX_LUKS1_PAYLOAD_BYTES as u64)
        .and_then(|bytes: u64| bytes.checked_add(1))
        .ok_or_else(|| miette::miette!("DR-CLI-0844: LUKS1 input cap is not addressable"))?;
    let file: std::fs::File = std::fs::File::open(path).map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-CLI-0844: cannot reopen input {}: {error}",
            path.display()
        )
    })?;
    let mut bytes: Vec<u8> = Vec::new();
    file.take(read_cap)
        .read_to_end(&mut bytes)
        .map_err(|error: std::io::Error| {
            miette::miette!(
                "DR-CLI-0844: cannot read bounded LUKS1 input {}: {error}",
                path.display()
            )
        })?;
    validate_luks1_image_length(&probe.header, bytes.len() as u64).map_err(
        |error: disrobe_binfmt::Error| {
            miette::miette!(
                "DR-CLI-0844: LUKS1 input {} changed or exceeded its bounds while reading: {error}",
                path.display()
            )
        },
    )?;
    Ok(bytes)
}
