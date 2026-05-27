use std::path::{Path, PathBuf};

use crate::briefcase;
use crate::common::manifest::{FreezerKind, FreezerManifest};
use crate::cxfreeze;
use crate::detect::{Detection, detect_bytes};
use crate::error::{Error, Result};
use crate::pex;
use crate::py2exe;
use crate::pyoxidizer;
use crate::shiv;

#[derive(Debug, Clone)]
pub struct PyfreezeOutput {
    pub detection: Detection,
    pub manifest: FreezerManifest,
    pub out_dir: PathBuf,
    pub extracted_count: usize,
}

pub fn extract(input: &Path, out_dir: &Path) -> Result<PyfreezeOutput> {
    let bytes: Vec<u8> = std::fs::read(input)?;
    let detection: Detection = detect_bytes(&bytes, Some(input));

    let manifest: FreezerManifest = match detection.kind {
        FreezerKind::Py2exe => {
            let res: py2exe::Py2exeExtraction = py2exe::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::CxFreeze => {
            let res: cxfreeze::CxFreezeExtraction = cxfreeze::detect_and_extract(input, out_dir)?;
            res.manifest
        }
        FreezerKind::Pex => {
            let res: pex::PexExtraction = pex::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::Shiv => {
            let res: shiv::ShivExtraction = shiv::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::PyOxidizer => {
            let res: pyoxidizer::PyOxidizerExtraction =
                pyoxidizer::detect_and_extract(&bytes, input, out_dir)?;
            res.manifest
        }
        FreezerKind::Briefcase => {
            let res: briefcase::BriefcaseExtraction = briefcase::detect_and_extract(input)?;
            res.manifest
        }
        FreezerKind::Unknown => return Err(Error::UnknownFormat),
    };

    let extracted_count: usize = manifest.entry_count;
    Ok(PyfreezeOutput {
        detection,
        manifest,
        out_dir: out_dir.to_path_buf(),
        extracted_count,
    })
}

pub fn detect(input: &Path) -> Result<Detection> {
    let bytes: Vec<u8> = std::fs::read(input)?;
    Ok(detect_bytes(&bytes, Some(input)))
}
