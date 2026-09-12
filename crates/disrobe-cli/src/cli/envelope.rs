#![allow(clippy::needless_pass_by_value)]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::Subcommand;
use disrobe_core::{Cache, CacheKeyBuilder, Capability, CapabilityKind};
use disrobe_ir::TranscodeRegistry;
use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Debug, Clone)]
pub(crate) struct CacheSettings {
    pub(crate) enabled: bool,
    pub(crate) dir: Option<PathBuf>,
}

impl CacheSettings {
    fn store(&self) -> Option<Cache> {
        if !self.enabled {
            return None;
        }
        self.dir
            .clone()
            .map_or_else(Cache::at_default_dir, |dir: PathBuf| Some(Cache::new(dir)))
    }
}

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
    #[command(
        about = "structurally diff two .dr envelopes: version, rung, flags, root hash, producer, capability set, provenance"
    )]
    Diff {
        #[arg(help = "left .dr envelope")]
        a: PathBuf,
        #[arg(help = "right .dr envelope")]
        b: PathBuf,
    },
    #[command(
        about = "validate that migrating envelope FROM to TO's (version, rung) is sound: a transcode path exists and every Requires capability stays satisfiable"
    )]
    MigrateCheck {
        #[arg(help = "source .dr envelope (migrate FROM)")]
        from: PathBuf,
        #[arg(help = "target .dr envelope (migrate TO)")]
        to: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EnvDifference {
    scope: &'static str,
    field: &'static str,
    left: String,
    right: String,
}

#[derive(Debug, Clone, Serialize)]
struct EnvDiffReport {
    a: String,
    b: String,
    identical: bool,
    differences: Vec<EnvDifference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MigrationIssue {
    kind: &'static str,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct MigrationReport {
    from: String,
    to: String,
    path_exists: bool,
    sound: bool,
    issues: Vec<MigrationIssue>,
}

pub(crate) fn run(
    action: EnvelopeCmd,
    fmt: OutputFormat,
    cache: &CacheSettings,
) -> miette::Result<()> {
    match action {
        EnvelopeCmd::Inspect { input } => inspect(input),
        EnvelopeCmd::Create {
            input,
            out,
            rung,
            produced_by,
            format,
        } => create(input, out, rung, produced_by, format, cache),
        EnvelopeCmd::Verify { input } => verify(input),
        EnvelopeCmd::Diff { a, b } => diff(a, b, fmt),
        EnvelopeCmd::MigrateCheck { from, to } => migrate_check(from, to, fmt),
    }
}

fn read_pair(
    a: &PathBuf,
    b: &PathBuf,
) -> miette::Result<(
    disrobe_ir::Envelope,
    disrobe_ir::Sidecar,
    disrobe_ir::Envelope,
    disrobe_ir::Sidecar,
)> {
    let env_a: disrobe_ir::Envelope = disrobe_ir::Envelope::read_from_path(a)
        .map_err(|e| miette::miette!("DR-CLI-0088: cannot read envelope {}: {e}", a.display()))?;
    let env_b: disrobe_ir::Envelope = disrobe_ir::Envelope::read_from_path(b)
        .map_err(|e| miette::miette!("DR-CLI-0088: cannot read envelope {}: {e}", b.display()))?;
    let side_a: disrobe_ir::Sidecar = disrobe_ir::Sidecar::decode(&env_a.cold)
        .map_err(|e| miette::miette!("DR-CLI-0088: malformed sidecar in {}: {e}", a.display()))?;
    let side_b: disrobe_ir::Sidecar = disrobe_ir::Sidecar::decode(&env_b.cold)
        .map_err(|e| miette::miette!("DR-CLI-0088: malformed sidecar in {}: {e}", b.display()))?;
    Ok((env_a, side_a, env_b, side_b))
}

fn diff(a: PathBuf, b: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let (env_a, side_a, env_b, side_b): (
        disrobe_ir::Envelope,
        disrobe_ir::Sidecar,
        disrobe_ir::Envelope,
        disrobe_ir::Sidecar,
    ) = read_pair(&a, &b)?;
    let differences: Vec<EnvDifference> = collect_differences(&env_a, &side_a, &env_b, &side_b);
    let identical: bool = differences.is_empty();
    let report: EnvDiffReport = EnvDiffReport {
        a: a.display().to_string(),
        b: b.display().to_string(),
        identical,
        differences,
    };
    emit(fmt, &report, || {
        if report.identical {
            println!("envelopes are structurally identical");
        } else {
            println!("{} difference(s):", report.differences.len());
            for d in &report.differences {
                println!("  {} [{}]: {} != {}", d.scope, d.field, d.left, d.right);
            }
        }
    })
}

fn collect_differences(
    env_a: &disrobe_ir::Envelope,
    side_a: &disrobe_ir::Sidecar,
    env_b: &disrobe_ir::Envelope,
    side_b: &disrobe_ir::Sidecar,
) -> Vec<EnvDifference> {
    let mut d: Vec<EnvDifference> = Vec::new();

    push_if_ne(&mut d, "header", "version", env_a.version, env_b.version);
    if env_a.rung != env_b.rung {
        d.push(EnvDifference {
            scope: "header",
            field: "rung",
            left: format!("{:?}", env_a.rung),
            right: format!("{:?}", env_b.rung),
        });
    }
    if env_a.flags != env_b.flags {
        d.push(EnvDifference {
            scope: "header",
            field: "flags",
            left: format!("0x{:02x}", env_a.flags),
            right: format!("0x{:02x}", env_b.flags),
        });
    }
    if env_a.root_hash != env_b.root_hash {
        d.push(EnvDifference {
            scope: "header",
            field: "root-hash",
            left: hex32(&env_a.root_hash),
            right: hex32(&env_b.root_hash),
        });
    }

    if side_a.produced_by != side_b.produced_by {
        d.push(EnvDifference {
            scope: "sidecar",
            field: "produced-by",
            left: side_a.produced_by.clone(),
            right: side_b.produced_by.clone(),
        });
    }
    if side_a.produced_by_version != side_b.produced_by_version {
        d.push(EnvDifference {
            scope: "sidecar",
            field: "produced-by-version",
            left: side_a.produced_by_version.clone(),
            right: side_b.produced_by_version.clone(),
        });
    }

    capability_deltas(&mut d, &side_a.capabilities, &side_b.capabilities);
    provenance_deltas(&mut d, side_a, side_b);
    d
}

#[inline]
fn push_if_ne(
    d: &mut Vec<EnvDifference>,
    scope: &'static str,
    field: &'static str,
    l: u16,
    r: u16,
) {
    if l != r {
        d.push(EnvDifference {
            scope,
            field,
            left: l.to_string(),
            right: r.to_string(),
        });
    }
}

#[inline]
fn cap_key(c: &Capability) -> (CapabilityKind, String) {
    (c.kind, c.name.clone())
}

fn capability_deltas(d: &mut Vec<EnvDifference>, a: &[Capability], b: &[Capability]) {
    let a_map: BTreeMap<(CapabilityKind, String), u32> = a
        .iter()
        .map(|c: &Capability| (cap_key(c), c.major))
        .collect();
    let b_map: BTreeMap<(CapabilityKind, String), u32> = b
        .iter()
        .map(|c: &Capability| (cap_key(c), c.major))
        .collect();
    let mut keys: BTreeSet<(CapabilityKind, String)> = a_map.keys().cloned().collect();
    keys.extend(b_map.keys().cloned());
    for k in keys {
        let label: String = format!("{:?} {}", k.0, k.1);
        match (a_map.get(&k), b_map.get(&k)) {
            (Some(_), None) => d.push(EnvDifference {
                scope: "capability",
                field: "removed",
                left: label,
                right: "(absent)".to_owned(),
            }),
            (None, Some(_)) => d.push(EnvDifference {
                scope: "capability",
                field: "added",
                left: "(absent)".to_owned(),
                right: label,
            }),
            (Some(la), Some(lb)) if la != lb => d.push(EnvDifference {
                scope: "capability",
                field: "major-changed",
                left: format!("{label} v{la}"),
                right: format!("{label} v{lb}"),
            }),
            _ => {}
        }
    }
}

fn provenance_deltas(d: &mut Vec<EnvDifference>, a: &disrobe_ir::Sidecar, b: &disrobe_ir::Sidecar) {
    let mut keys: BTreeSet<&String> = a.provenance.keys().collect();
    keys.extend(b.provenance.keys());
    for k in keys {
        match (a.provenance.get(k), b.provenance.get(k)) {
            (Some(_), None) => d.push(EnvDifference {
                scope: "provenance",
                field: "removed",
                left: k.clone(),
                right: "(absent)".to_owned(),
            }),
            (None, Some(_)) => d.push(EnvDifference {
                scope: "provenance",
                field: "added",
                left: "(absent)".to_owned(),
                right: k.clone(),
            }),
            (Some(va), Some(vb)) if va != vb => d.push(EnvDifference {
                scope: "provenance",
                field: "changed",
                left: format!("{k}={va}"),
                right: format!("{k}={vb}"),
            }),
            _ => {}
        }
    }
}

fn evaluate_migration(
    env_from: &disrobe_ir::Envelope,
    side_from: &disrobe_ir::Sidecar,
    env_to: &disrobe_ir::Envelope,
    side_to: &disrobe_ir::Sidecar,
    registry: &TranscodeRegistry,
    from_label: String,
    to_label: String,
) -> MigrationReport {
    let mut issues: Vec<MigrationIssue> = Vec::new();

    let path_exists: bool = match env_from.transcode_to(env_to.version, env_to.rung, registry) {
        Ok(_) => true,
        Err(e) => {
            issues.push(MigrationIssue {
                kind: "no-transcode-path",
                detail: e.to_string(),
            });
            false
        }
    };

    let produced_from: Vec<&Capability> = side_from
        .capabilities
        .iter()
        .filter(|c: &&Capability| matches!(c.kind, CapabilityKind::Produces))
        .collect();
    for req in side_to
        .capabilities
        .iter()
        .filter(|c: &&Capability| matches!(c.kind, CapabilityKind::Requires))
    {
        let satisfied: bool = produced_from.iter().any(|p: &&Capability| p.satisfies(req));
        if !satisfied {
            let downgraded: bool = produced_from
                .iter()
                .any(|p: &&Capability| p.name == req.name && p.major != req.major);
            issues.push(MigrationIssue {
                kind: if downgraded {
                    "capability-major-mismatch"
                } else {
                    "unsatisfied-requires"
                },
                detail: format!(
                    "target Requires {} v{} not produced by source",
                    req.name, req.major
                ),
            });
        }
    }

    for prod in &produced_from {
        let dropped: bool = !side_to.capabilities.iter().any(|c: &Capability| {
            matches!(c.kind, CapabilityKind::Produces)
                && c.name == prod.name
                && c.major == prod.major
        });
        let downgraded: bool = side_to.capabilities.iter().any(|c: &Capability| {
            matches!(c.kind, CapabilityKind::Produces)
                && c.name == prod.name
                && c.major < prod.major
        });
        if downgraded {
            issues.push(MigrationIssue {
                kind: "produces-major-downgrade",
                detail: format!(
                    "source produces {} v{} but target downgrades it",
                    prod.name, prod.major
                ),
            });
        } else if dropped {
            issues.push(MigrationIssue {
                kind: "produces-dropped",
                detail: format!(
                    "source produces {} v{} silently dropped by target",
                    prod.name, prod.major
                ),
            });
        }
    }

    let sound: bool = path_exists && issues.is_empty();
    MigrationReport {
        from: from_label,
        to: to_label,
        path_exists,
        sound,
        issues,
    }
}

fn migrate_check(from: PathBuf, to: PathBuf, fmt: OutputFormat) -> miette::Result<()> {
    let (env_from, side_from, env_to, side_to): (
        disrobe_ir::Envelope,
        disrobe_ir::Sidecar,
        disrobe_ir::Envelope,
        disrobe_ir::Sidecar,
    ) = read_pair(&from, &to)?;
    let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
    let report: MigrationReport = evaluate_migration(
        &env_from,
        &side_from,
        &env_to,
        &side_to,
        &registry,
        from.display().to_string(),
        to.display().to_string(),
    );
    emit(fmt, &report, || {
        if report.sound {
            println!("migration is SOUND: transcode path exists and capabilities are compatible");
        } else {
            println!("migration is UNSOUND ({} issue(s)):", report.issues.len());
            for i in &report.issues {
                println!("  [{}] {}", i.kind, i.detail);
            }
        }
    })?;
    if report.sound {
        Ok(())
    } else {
        Err(miette::miette!(
            "DR-CLI-0089: migration from {} to {} is unsound: {} issue(s)",
            report.from,
            report.to,
            report.issues.len()
        ))
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
    cache: &CacheSettings,
) -> miette::Result<()> {
    if !rung.eq_ignore_ascii_case("raw") {
        return Err(miette::miette!(
            "DR-CLI-0082: only --rung raw is implemented in v0.1; got {rung}"
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0083: cannot read source: {e}"))?;
    let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    let producer: String = produced_by.unwrap_or_else(|| "disrobe-cli".to_owned());

    let store: Option<Cache> = cache.store();
    let key: Option<disrobe_core::CacheKey> = store.as_ref().map(|_| {
        let mut b: CacheKeyBuilder = CacheKeyBuilder::new("envelope.create");
        b.field("rung", b"raw");
        b.field("producer", producer.as_bytes());
        b.field("format", format.as_deref().unwrap_or("").as_bytes());
        b.field(
            "envelope_format_version",
            &disrobe_ir::ENVELOPE_FORMAT_VERSION.to_le_bytes(),
        );
        b.input(&bytes)
    });

    if let (Some(store), Some(key)) = (store.as_ref(), key.as_ref())
        && let Some(cached) = store.get(key)
        && let Ok(env) = disrobe_ir::Envelope::decode(&cached)
    {
        write_envelope_bytes(&out, &cached)?;
        println!("disrobe envelope create: OK (cache hit)");
        println!("  input:      {}", input.display());
        println!("  out:        {}", out.display());
        println!("  rung:       Raw");
        println!("  source hash: {}", hex32(&source_hash));
        println!("  root hash:  {}", hex32(&env.root_hash));
        return Ok(());
    }

    let payload: disrobe_ir::RawPayload = disrobe_ir::RawPayload {
        source_path: input.display().to_string(),
        source_bytes: bytes,
        source_hash,
        detected_format: format,
    };
    let hot: Vec<u8> = disrobe_ir::encode_raw(&payload)
        .map_err(|e| miette::miette!("DR-CLI-0084: rkyv encode failed: {e}"))?;
    let sidecar: disrobe_ir::Sidecar = disrobe_ir::Sidecar {
        produced_by: producer,
        produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: vec![disrobe_core::Capability::produces("raw", 1)],
        provenance: BTreeMap::default(),
    };
    let cold: Vec<u8> = sidecar
        .encode()
        .map_err(|e| miette::miette!("DR-CLI-0085: postcard encode failed: {e}"))?;
    let env: disrobe_ir::Envelope = disrobe_ir::Envelope::new(disrobe_ir::Rung::Raw, hot, cold);
    let encoded: Vec<u8> = env
        .encode()
        .map_err(|e| miette::miette!("DR-CLI-0086: cannot encode envelope: {e}"))?;
    write_envelope_bytes(&out, &encoded)?;
    if let (Some(store), Some(key)) = (store.as_ref(), key.as_ref()) {
        let _: std::io::Result<()> = store.put(key, &encoded);
    }
    println!("disrobe envelope create: OK");
    println!("  input:      {}", input.display());
    println!("  out:        {}", out.display());
    println!("  rung:       Raw");
    println!("  source hash: {}", hex32(&source_hash));
    println!("  root hash:  {}", hex32(&env.root_hash));
    Ok(())
}

fn write_envelope_bytes(out: &std::path::Path, bytes: &[u8]) -> miette::Result<()> {
    use std::io::Write as _;
    let mut opts: std::fs::OpenOptions = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    let mut file: std::fs::File = opts
        .open(out)
        .map_err(|e| miette::miette!("DR-CLI-0086: cannot write envelope: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0086: cannot write envelope: {e}"))?;
    file.sync_all()
        .map_err(|e| miette::miette!("DR-CLI-0086: cannot write envelope: {e}"))?;
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_ir::{Envelope, RawPayload, Rung, Sidecar, encode_raw};

    fn env_with(
        rung: Rung,
        caps: Vec<Capability>,
        prov: BTreeMap<String, String>,
        producer: &str,
    ) -> (Envelope, Sidecar) {
        let hot: Vec<u8> = encode_raw(&RawPayload {
            source_path: "x.bin".to_owned(),
            source_bytes: vec![1, 2, 3],
            source_hash: [0u8; 32],
            detected_format: None,
        })
        .expect("encode raw");
        let side: Sidecar = Sidecar {
            produced_by: producer.to_owned(),
            produced_by_version: "0.1.0".to_owned(),
            capabilities: caps,
            provenance: prov,
        };
        let cold: Vec<u8> = side.encode().expect("encode sidecar");
        (Envelope::new(rung, hot, cold), side)
    }

    #[test]
    fn identical_envelopes_have_no_differences() {
        let (ea, sa): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "disrobe-cli",
        );
        let (eb, sb): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "disrobe-cli",
        );
        assert!(collect_differences(&ea, &sa, &eb, &sb).is_empty());
    }

    #[test]
    fn capability_major_bump_is_a_difference() {
        let (ea, sa): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("mir.core", 1)],
            BTreeMap::new(),
            "p",
        );
        let (eb, sb): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("mir.core", 2)],
            BTreeMap::new(),
            "p",
        );
        let diffs: Vec<EnvDifference> = collect_differences(&ea, &sa, &eb, &sb);
        let cap: &EnvDifference = diffs
            .iter()
            .find(|d: &&EnvDifference| d.scope == "capability")
            .expect("a capability difference");
        assert_eq!(cap.field, "major-changed");
        assert!(
            diffs
                .iter()
                .all(
                    |d: &EnvDifference| (d.scope == "capability" && d.field == "major-changed")
                        || (d.scope == "header" && d.field == "root-hash")
                ),
            "unexpected extra differences: {diffs:?}"
        );
    }

    #[test]
    fn rung_change_is_a_difference() {
        let (ea, sa): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "p",
        );
        let (eb, sb): (Envelope, Sidecar) = env_with(
            Rung::Disasm,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "p",
        );
        let diffs: Vec<EnvDifference> = collect_differences(&ea, &sa, &eb, &sb);
        assert!(diffs.iter().any(|d: &EnvDifference| d.field == "rung"));
    }

    #[test]
    fn provenance_value_change_is_a_difference() {
        let mut pa: BTreeMap<String, String> = BTreeMap::new();
        pa.insert("k".to_owned(), "a".to_owned());
        let mut pb: BTreeMap<String, String> = BTreeMap::new();
        pb.insert("k".to_owned(), "b".to_owned());
        let (ea, sa): (Envelope, Sidecar) =
            env_with(Rung::Raw, vec![Capability::produces("raw", 1)], pa, "p");
        let (eb, sb): (Envelope, Sidecar) =
            env_with(Rung::Raw, vec![Capability::produces("raw", 1)], pb, "p");
        let diffs: Vec<EnvDifference> = collect_differences(&ea, &sa, &eb, &sb);
        let prov: &EnvDifference = diffs
            .iter()
            .find(|d: &&EnvDifference| d.scope == "provenance")
            .expect("a provenance difference");
        assert_eq!(prov.field, "changed");
        assert!(
            diffs.iter().all(
                |d: &EnvDifference| (d.scope == "provenance" && d.field == "changed")
                    || (d.scope == "header" && d.field == "root-hash")
            ),
            "unexpected extra differences: {diffs:?}"
        );
    }

    #[test]
    fn migrate_sound_for_identical() {
        let (ef, sf): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "p",
        );
        let (et, st): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![
                Capability::produces("raw", 1),
                Capability::requires("raw", 1),
            ],
            BTreeMap::new(),
            "p",
        );
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        let report: MigrationReport = evaluate_migration(
            &ef,
            &sf,
            &et,
            &st,
            &registry,
            "from".to_owned(),
            "to".to_owned(),
        );
        assert!(report.path_exists);
        assert!(report.sound, "expected sound, issues: {:?}", report.issues);
    }

    #[test]
    fn migrate_unsound_on_capability_major_bump() {
        let (ef, sf): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("mir.core", 1)],
            BTreeMap::new(),
            "p",
        );
        let (et, st): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::requires("mir.core", 2)],
            BTreeMap::new(),
            "p",
        );
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        let report: MigrationReport = evaluate_migration(
            &ef,
            &sf,
            &et,
            &st,
            &registry,
            "from".to_owned(),
            "to".to_owned(),
        );
        assert!(!report.sound);
        assert!(
            report
                .issues
                .iter()
                .any(|i: &MigrationIssue| i.kind == "capability-major-mismatch")
        );
    }

    #[test]
    fn migrate_unsound_on_missing_transcode_path() {
        let (ef, sf): (Envelope, Sidecar) = env_with(
            Rung::Raw,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "p",
        );
        let (et, st): (Envelope, Sidecar) = env_with(
            Rung::Surface,
            vec![Capability::produces("raw", 1)],
            BTreeMap::new(),
            "p",
        );
        let registry: TranscodeRegistry = TranscodeRegistry::baseline_v0_1();
        let report: MigrationReport = evaluate_migration(
            &ef,
            &sf,
            &et,
            &st,
            &registry,
            "from".to_owned(),
            "to".to_owned(),
        );
        assert!(!report.path_exists);
        assert!(!report.sound);
    }
}
