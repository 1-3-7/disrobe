use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct CxFreezeLayout {
    pub library_zip: PathBuf,
    pub license_file: Option<PathBuf>,
}

pub fn probe(binary_path: &Path) -> Result<CxFreezeLayout> {
    let dir: &Path = binary_path
        .parent()
        .ok_or_else(|| missing(binary_path, vec!["parent directory".to_owned()]))?;

    let license_candidates: [PathBuf; 2] = [
        dir.join("frozen_application_license.txt"),
        dir.join("lib").join("frozen_application_license.txt"),
    ];
    let license_file: Option<PathBuf> = license_candidates.iter().find(|p| p.exists()).cloned();

    let nested_zip: PathBuf = dir.join("lib").join("library.zip");
    let top_zip: PathBuf = dir.join("library.zip");
    let library_zip: PathBuf = if nested_zip.exists() {
        nested_zip
    } else if license_file.is_some() && top_zip.exists() {
        top_zip
    } else {
        return Err(missing(
            binary_path,
            vec![
                "lib/library.zip".to_owned(),
                "frozen_application_license.txt + library.zip".to_owned(),
            ],
        ));
    };

    Ok(CxFreezeLayout {
        library_zip,
        license_file,
    })
}

#[must_use]
pub fn could_be_cxfreeze(binary_path: &Path) -> bool {
    probe(binary_path).is_ok()
}

fn missing(binary_path: &Path, missing: Vec<String>) -> Error {
    Error::CxFreezeMissingSibling {
        binary: binary_path.display().to_string(),
        missing,
    }
}
