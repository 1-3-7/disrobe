#![allow(unreachable_pub, dead_code, clippy::missing_panics_doc)]
#[path = "../tests/common/mod.rs"]
mod common;

use std::fs;
use std::path::PathBuf;

use crate::common::{embed_signature, synth_minimal_dotnet_pe};

fn main() -> std::io::Result<()> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base: PathBuf = manifest.join("../../corpus/src/dotnet");
    fs::create_dir_all(&base)?;

    fs::write(
        base.join("tiny-managed-pe.bin"),
        synth_minimal_dotnet_pe("v4.0.30319"),
    )?;

    let mut img2: Vec<u8> = synth_minimal_dotnet_pe("v4.0.30319");
    embed_signature(&mut img2, b"ConfuserEx2 v1.6.0");
    embed_signature(&mut img2, b"ConfusedByAttribute");
    fs::write(base.join("confuserex2-sigblob.bin"), img2)?;

    let mut img3: Vec<u8> = synth_minimal_dotnet_pe("v6.0.0");
    embed_signature(&mut img3, b"Obfuscar.Obfuscator");
    fs::write(base.join("obfuscar-sigblob.bin"), img3)?;

    let mut img4: Vec<u8> = vec![0u8; 2048];
    img4[100..109].copy_from_slice(b"NativeAOT");
    img4[200..210].copy_from_slice(b"RhpNewFast");
    img4[400..406].copy_from_slice(b"net8.0");
    fs::write(base.join("native-aot-net8-symblob.bin"), img4)?;

    let mut img5: Vec<u8> = synth_minimal_dotnet_pe("v8.0.0");
    embed_signature(&mut img5, b"SmartAssembly.Attributes");
    fs::write(base.join("smartassembly-sigblob.bin"), img5)?;

    Ok(())
}
