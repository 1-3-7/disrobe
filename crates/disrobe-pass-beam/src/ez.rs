use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EzEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EzArchive {
    pub entries: BTreeMap<String, EzEntry>,
}

impl EzArchive {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let cursor: Cursor<&[u8]> = Cursor::new(buf);
        let mut archive: zip::ZipArchive<Cursor<&[u8]>> = zip::ZipArchive::new(cursor)?;
        let mut entries: BTreeMap<String, EzEntry> = BTreeMap::new();
        for i in 0..archive.len() {
            let mut file: zip::read::ZipFile<'_> = archive.by_index(i)?;
            let path: String = file.name().to_owned();
            let is_dir: bool = file.is_dir();
            let size: u64 = file.size();
            let mut data: Vec<u8> = Vec::with_capacity(size as usize);
            if !is_dir {
                file.read_to_end(&mut data)?;
            }
            entries.insert(
                path.clone(),
                EzEntry {
                    path,
                    size,
                    is_dir,
                    data,
                },
            );
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn beam_files(&self) -> Vec<&EzEntry> {
        self.entries
            .values()
            .filter(|e: &&EzEntry| !e.is_dir && e.path.ends_with(".beam"))
            .collect()
    }
}
