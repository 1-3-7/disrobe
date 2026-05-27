#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub(crate) enum EnvelopeCmd {
    #[command(about = "inspect a .dr envelope: version, rung, capabilities, provenance, root hash")]
    Inspect {
        #[arg(help = ".dr envelope to inspect")]
        input: PathBuf,
    },
    #[command(
        about = "create a .dr envelope from a source file (rkyv hot payload + postcard cold sidecar + BLAKE3 root hash)"
    )]
    Create {
        #[arg(help = "source file to envelope")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the .dr envelope")]
        out: PathBuf,
        #[arg(
            long,
            default_value = "raw",
            help = "IR rung (only `raw` is implemented in v0.1)"
        )]
        rung: String,
        #[arg(long, help = "label this envelope's producer (default: disrobe-cli)")]
        produced_by: Option<String>,
        #[arg(long, help = "label the detected source format")]
        format: Option<String>,
    },
    #[command(about = "verify a .dr envelope's BLAKE3 root hash against its payload")]
    Verify {
        #[arg(help = ".dr envelope to verify")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: EnvelopeCmd) -> miette::Result<()> {
    match action {
        EnvelopeCmd::Inspect { input } => inspect(input),
        EnvelopeCmd::Create {
            input,
            out,
            rung,
            produced_by,
            format,
        } => create(input, out, rung, produced_by, format),
        EnvelopeCmd::Verify { input } => verify(input),
    }
}

fn verify(input: PathBuf) -> miette::Result<()> {
    let view: disrobe_ir::MmapView = disrobe_ir::mmap_envelope_view(&input)
        .map_err(|e| miette::miette!("DR-CLI-0087: envelope failed verification: {e}"))?;
    println!("disrobe envelope verify: OK");
    println!("  file:               {}", input.display());
    println!("  version:            {}", view.version);
    println!("  rung:               {:?}", view.rung);
    println!("  hot payload:        {} bytes", view.hot().len());
    println!("  cold sidecar:       {} bytes", view.cold().len());
    println!("  root hash (blake3): {}", hex32(&view.root_hash));
    Ok(())
}

fn inspect(input: PathBuf) -> miette::Result<()> {
    let env: disrobe_ir::Envelope = disrobe_ir::Envelope::read_from_path(&input)
        .map_err(|e| miette::miette!("DR-CLI-0080: cannot read envelope: {e}"))?;
    let cold: disrobe_ir::Sidecar = disrobe_ir::Sidecar::decode(&env.cold)
        .map_err(|e| miette::miette!("DR-CLI-0081: malformed sidecar: {e}"))?;
    println!("disrobe envelope inspect");
    println!("  file:               {}", input.display());
    println!("  version:            {}", env.version);
    println!("  rung:               {:?}", env.rung);
    println!("  flags:              0x{:02x}", env.flags);
    println!("  hot payload:        {} bytes", env.hot.len());
    println!("  cold sidecar:       {} bytes", env.cold.len());
    println!("  root hash (blake3): {}", hex32(&env.root_hash));
    println!(
        "  produced by:        {} v{}",
        cold.produced_by, cold.produced_by_version
    );
    if cold.capabilities.is_empty() {
        println!("  capabilities:       (none)");
    } else {
        println!("  capabilities:");
        for cap in &cold.capabilities {
            println!("    - {:?} {} v{}", cap.kind, cap.name, cap.major);
        }
    }
    if !cold.provenance.is_empty() {
        println!("  provenance:");
        for (k, v) in &cold.provenance {
            println!("    {k} = {v}");
        }
    }
    Ok(())
}

fn create(
    input: PathBuf,
    out: PathBuf,
    rung: String,
    produced_by: Option<String>,
    format: Option<String>,
) -> miette::Result<()> {
    if !rung.eq_ignore_ascii_case("raw") {
        return Err(miette::miette!(
            "DR-CLI-0082: only --rung raw is implemented in v0.1; got {rung}"
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0083: cannot read source: {e}"))?;
    let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    let payload: disrobe_ir::RawPayload = disrobe_ir::RawPayload {
        source_path: input.display().to_string(),
        source_bytes: bytes,
        source_hash,
        detected_format: format,
    };
    let hot: Vec<u8> = disrobe_ir::encode_raw(&payload)
        .map_err(|e| miette::miette!("DR-CLI-0084: rkyv encode failed: {e}"))?;
    let sidecar: disrobe_ir::Sidecar = disrobe_ir::Sidecar {
        produced_by: produced_by.unwrap_or_else(|| "disrobe-cli".to_owned()),
        produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: vec![disrobe_core::Capability::produces("raw", 1)],
        provenance: BTreeMap::default(),
    };
    let cold: Vec<u8> = sidecar
        .encode()
        .map_err(|e| miette::miette!("DR-CLI-0085: postcard encode failed: {e}"))?;
    let env: disrobe_ir::Envelope = disrobe_ir::Envelope::new(disrobe_ir::Rung::Raw, hot, cold);
    env.write_to_path(&out)
        .map_err(|e| miette::miette!("DR-CLI-0086: cannot write envelope: {e}"))?;
    println!("disrobe envelope create: OK");
    println!("  input:      {}", input.display());
    println!("  out:        {}", out.display());
    println!("  rung:       Raw");
    println!("  source hash: {}", hex32(&source_hash));
    println!("  root hash:  {}", hex32(&env.root_hash));
    Ok(())
}

#[inline]
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out: String = String::with_capacity(64);
    for b in bytes {
        let _: std::fmt::Result = write!(out, "{b:02x}");
    }
    out
}
