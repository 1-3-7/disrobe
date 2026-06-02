#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use disrobe_pass_php::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, PeelOptions, PeelReport,
    PharArchive, ioncube_encoder, parse_phar, peel_eval_chain, sourceguardian_encoder,
    zend_guard_encoder,
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum PhpCmd {
    #[command(about = "decode a PHP encoder envelope: phar / ionCube / SourceGuardian / ZendGuard")]
    Decode {
        #[arg(help = "input PHP file or .phar archive")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-php)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t = PhpEncoderChoice::Auto,
            help = "force a specific encoder family; default auto-detects"
        )]
        encoder: PhpEncoderChoice,
        #[arg(
            long,
            help = "acknowledge authorization for commercial encoders (ionCube / SourceGuardian / ZendGuard)"
        )]
        i_have_authorization: bool,
    },
    #[command(about = "peel eval()/base64_decode/gzinflate chains until residue is plain PHP")]
    Deobfuscate {
        #[arg(help = "obfuscated PHP source")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the peeled source (default: ./out/<stem>.peeled.php)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "extract entries from a .phar archive (Phar manifest walker)")]
    Extract {
        #[arg(help = "input .phar archive")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-phar)")]
        out: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhpEncoderChoice {
    Auto,
    Phar,
    Ioncube,
    Sourceguardian,
    Zendguard,
}

pub(crate) fn run(action: PhpCmd) -> miette::Result<()> {
    match action {
        PhpCmd::Decode {
            input,
            out,
            encoder,
            i_have_authorization,
        } => decode(input, out, encoder, i_have_authorization),
        PhpCmd::Deobfuscate { input, out, emit } => deobfuscate(input, out, emit),
        PhpCmd::Extract { input, out } => extract(input, out),
    }
}

fn decode(
    input: PathBuf,
    out: Option<PathBuf>,
    encoder: PhpEncoderChoice,
    i_have_authorization: bool,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0550: cannot read input: {e}"))?;
    let g: globals::Globals = globals::current();
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("php-decode")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-php")));

    let resolved: PhpEncoderChoice = match encoder {
        PhpEncoderChoice::Auto => auto_detect_encoder(&bytes, &input),
        other => other,
    };

    if g.dry_run {
        println!("php decode: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  encoder:      {resolved:?}");
        return Ok(());
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0551: cannot create out dir: {e}"))?;

    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let auth: Option<AuthorizationToken> = if i_have_authorization {
        Some(AuthorizationToken::user_attested())
    } else {
        None
    };

    let manifest: serde_json::Value = match resolved {
        PhpEncoderChoice::Phar => {
            let archive: PharArchive =
                parse_phar(&bytes).map_err(|e| miette::miette!("DR-CLI-0552: phar parse: {e}"))?;
            for entry in archive.entries.values() {
                let extracted: Vec<u8> =
                    disrobe_pass_php::extract_phar_entry(&archive, &bytes, &entry.name)
                        .map_err(|e| miette::miette!("DR-CLI-0553: phar entry: {e}"))?;
                let safe: PathBuf = sanitize_entry_path(&out_dir, &entry.name);
                if let Some(parent) = safe.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        miette::miette!("DR-CLI-0554: cannot create entry dir: {e}")
                    })?;
                }
                std::fs::write(&safe, &extracted)
                    .map_err(|e| miette::miette!("DR-CLI-0555: cannot write entry: {e}"))?;
            }
            serde_json::json!({
                "schema": "disrobe.php.decode/v0",
                "input": input.display().to_string(),
                "encoder": "phar",
                "entries": archive.entries.len(),
                "api_version": archive.api_version,
            })
        }
        PhpEncoderChoice::Ioncube => decode_encoder(
            "ioncube",
            &bytes,
            &out_dir,
            &stem,
            &input,
            auth,
            EncoderFamily::IonCube,
        )?,
        PhpEncoderChoice::Sourceguardian => decode_encoder(
            "sourceguardian",
            &bytes,
            &out_dir,
            &stem,
            &input,
            auth,
            EncoderFamily::SourceGuardian,
        )?,
        PhpEncoderChoice::Zendguard => decode_encoder(
            "zendguard",
            &bytes,
            &out_dir,
            &stem,
            &input,
            auth,
            EncoderFamily::ZendGuard,
        )?,
        PhpEncoderChoice::Auto => {
            return Err(miette::miette!(
                "DR-CLI-0556: cannot auto-detect a PHP encoder envelope for {}",
                input.display()
            ));
        }
    };

    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0557: cannot write manifest: {e}"))?;

    println!("php decode: OK");
    println!("  input:        {}", input.display());
    println!("  encoder:      {resolved:?}");
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn deobfuscate(
    input: PathBuf,
    out: Option<PathBuf>,
    emit_kinds: Vec<String>,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0560: cannot read input: {e}"))?;
    let g: globals::Globals = globals::current();
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("php-deob")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.peeled.php")));
    if g.dry_run {
        println!("php deobfuscate: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }
    let report: PeelReport = peel_eval_chain(&bytes, PeelOptions::default())
        .map_err(|e| miette::miette!("DR-CLI-0561: php peel: {e}"))?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0562: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, &report.final_source)
        .map_err(|e| miette::miette!("DR-CLI-0563: cannot write output: {e}"))?;
    let manifest_path: PathBuf = out_path.with_extension("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.php.deob/v0",
        "input": input.display().to_string(),
        "layers": report.layers.len(),
        "layer_counts": report.layer_counts.iter()
            .map(|(k, v)| (format!("{k:?}"), *v))
            .collect::<std::collections::BTreeMap<_, _>>(),
        "residual_eval": report.residual_eval,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0564: cannot write manifest: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    apply_emit_stubs(&emit_kinds, stub_dir, &stem, "php-deob")?;
    println!("php deobfuscate: OK");
    println!("  input:        {}", input.display());
    println!("  layers:       {}", report.layers.len());
    println!("  residual_eval:{}", report.residual_eval);
    println!("  wrote:        {}", out_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0570: cannot read input: {e}"))?;
    let archive: PharArchive =
        parse_phar(&bytes).map_err(|e| miette::miette!("DR-CLI-0571: phar parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("phar-extract")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-phar")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0572: cannot create out dir: {e}"))?;
    for entry in archive.entries.values() {
        let extracted: Vec<u8> =
            disrobe_pass_php::extract_phar_entry(&archive, &bytes, &entry.name)
                .map_err(|e| miette::miette!("DR-CLI-0573: phar entry: {e}"))?;
        let safe: PathBuf = sanitize_entry_path(&out_dir, &entry.name);
        if let Some(parent) = safe.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0574: cannot create entry dir: {e}"))?;
        }
        std::fs::write(&safe, &extracted)
            .map_err(|e| miette::miette!("DR-CLI-0575: cannot write entry: {e}"))?;
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.php.phar.extract/v0",
        "input": input.display().to_string(),
        "entries": archive.entries.len(),
        "api_version": archive.api_version,
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0576: cannot write manifest: {e}"))?;
    println!("php extract: OK");
    println!("  input:        {}", input.display());
    println!("  entries:      {}", archive.entries.len());
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn auto_detect_encoder(bytes: &[u8], path: &std::path::Path) -> PhpEncoderChoice {
    if path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("phar"))
    {
        return PhpEncoderChoice::Phar;
    }
    if ioncube_encoder::detect(bytes).is_some() {
        return PhpEncoderChoice::Ioncube;
    }
    if sourceguardian_encoder::detect(bytes).is_some() {
        return PhpEncoderChoice::Sourceguardian;
    }
    if zend_guard_encoder::detect(bytes).is_some() {
        return PhpEncoderChoice::Zendguard;
    }
    if parse_phar(bytes).is_ok() {
        return PhpEncoderChoice::Phar;
    }
    PhpEncoderChoice::Auto
}

fn decode_encoder(
    label: &'static str,
    bytes: &[u8],
    out_dir: &std::path::Path,
    stem: &str,
    input: &std::path::Path,
    auth: Option<AuthorizationToken>,
    family: EncoderFamily,
) -> miette::Result<serde_json::Value> {
    let detection: EncoderDetection = match family {
        EncoderFamily::IonCube => ioncube_encoder::detect(bytes),
        EncoderFamily::SourceGuardian => sourceguardian_encoder::detect(bytes),
        EncoderFamily::ZendGuard => zend_guard_encoder::detect(bytes),
    }
    .ok_or_else(|| {
        miette::miette!(
            "DR-CLI-0580: {label} envelope marker not found in {}",
            input.display()
        )
    })?;
    let outcome: DecodeOutcome = match family {
        EncoderFamily::IonCube => ioncube_encoder::decode(bytes, auth),
        EncoderFamily::SourceGuardian => sourceguardian_encoder::decode(bytes, auth),
        EncoderFamily::ZendGuard => zend_guard_encoder::decode(bytes, auth),
    }
    .map_err(|e| miette::miette!("DR-CLI-0581: {label} decode: {e}"))?;
    let payload_path: PathBuf = out_dir.join(format!("{stem}.{label}.bin"));
    let (cipher_len, plain_len): (usize, usize) = match &outcome {
        DecodeOutcome::StructuralOnly { ciphertext, .. } => {
            std::fs::write(&payload_path, ciphertext)
                .map_err(|e| miette::miette!("DR-CLI-0582: cannot write payload: {e}"))?;
            (ciphertext.len(), 0)
        }
        DecodeOutcome::PartialPlaintext {
            recovered,
            residual_ciphertext,
            ..
        } => {
            std::fs::write(&payload_path, recovered)
                .map_err(|e| miette::miette!("DR-CLI-0582: cannot write payload: {e}"))?;
            (residual_ciphertext.len(), recovered.len())
        }
    };
    Ok(serde_json::json!({
        "schema": "disrobe.php.decode/v0",
        "input": input.display().to_string(),
        "encoder": label,
        "version_label": detection.version_label,
        "marker_offset": detection.marker_offset,
        "confident": detection.confident,
        "payload_path": payload_path.display().to_string(),
        "ciphertext_len": cipher_len,
        "plaintext_len": plain_len,
    }))
}

fn sanitize_entry_path(out_dir: &std::path::Path, raw: &str) -> PathBuf {
    let cleaned: String = raw.replace('\\', "/");
    let mut resolved: PathBuf = out_dir.to_path_buf();
    for segment in cleaned.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            continue;
        }
        resolved.push(segment);
    }
    resolved
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the php pass in this build",
        )?;
    }
    Ok(())
}
