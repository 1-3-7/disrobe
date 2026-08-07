use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Subcommand, ValueEnum};
use disrobe_plugin_host::{
    Limits, LoaderError, Manifest, ManifestError, PluginHost, PublicKey, SandboxError,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PluginFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PluginCmd {
    #[command(
        about = "verify and run a signed WebAssembly component plugin under the disrobe-plugin-host sandbox"
    )]
    Run {
        #[arg(value_name = "COMPONENT", help = "path to the signed .wasm component")]
        component: PathBuf,
        #[arg(
            long,
            value_name = "PUBKEY",
            help = "minisign public key file trusted to sign this plugin"
        )]
        trusted_key: PathBuf,
        #[arg(
            long,
            value_name = "FILE",
            help = "input bytes for the plugin (default: read from stdin)"
        )]
        input: Option<PathBuf>,
        #[arg(
            long,
            value_name = "FILE",
            help = "write the plugin's output bytes here"
        )]
        out: PathBuf,
        #[arg(
            long,
            value_name = "N",
            help = "fuel budget, clamped to the sandbox's compiled-in ceiling"
        )]
        fuel: Option<u64>,
        #[arg(
            long,
            value_name = "MS",
            help = "wall-clock deadline in milliseconds, clamped to the sandbox's compiled-in ceiling"
        )]
        wall_deadline_ms: Option<u64>,
        #[arg(
            long,
            value_name = "BYTES",
            help = "memory cap in bytes, clamped to the sandbox's compiled-in ceiling"
        )]
        memory_cap_bytes: Option<usize>,
        #[arg(long, value_enum, default_value_t = PluginFormat::Text, help = "output format: text or json")]
        format: PluginFormat,
    },
    #[command(
        about = "verify a signed WebAssembly component plugin's signature and capability manifest without running it"
    )]
    Verify {
        #[arg(value_name = "COMPONENT", help = "path to the signed .wasm component")]
        component: PathBuf,
        #[arg(
            long,
            value_name = "PUBKEY",
            help = "minisign public key file trusted to sign this plugin"
        )]
        trusted_key: PathBuf,
        #[arg(long, value_enum, default_value_t = PluginFormat::Text, help = "output format: text or json")]
        format: PluginFormat,
    },
    #[command(
        about = "list plugin bundles (a `<name>.wasm` component beside its `<name>.wasm.minisig` signature and `<name>.toml` manifest) in a directory"
    )]
    List {
        #[arg(value_name = "DIR", help = "directory of plugin bundles")]
        dir: PathBuf,
        #[arg(
            long,
            value_name = "PUBKEY",
            help = "minisign public key file; when given, each bundle is also signature- and capability-verified"
        )]
        trusted_key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = PluginFormat::Text, help = "output format: text or json")]
        format: PluginFormat,
    },
}

#[derive(Debug, Error)]
pub(crate) enum PluginCliError {
    #[error("plugin component not found at {0}")]
    ComponentNotFound(PathBuf),
    #[error("expected a plugin component file at {0}, found a directory")]
    ComponentIsDirectory(PathBuf),
    #[error(
        "plugin signature not found at {0} (expected beside the component, named `<component>.minisig`)"
    )]
    SignatureNotFound(PathBuf),
    #[error(
        "plugin manifest not found at {0} (expected beside the component, named `<component-stem>.toml`)"
    )]
    ManifestNotFound(PathBuf),
    #[error("plugin manifest at {0} is not valid utf-8")]
    ManifestNotUtf8(PathBuf),
    #[error("plugin input file not found at {0}")]
    InputNotFound(PathBuf),
    #[error("{0} already exists; pass --force to overwrite")]
    OutputExists(PathBuf),
    #[error(
        "no --input given and stdin is a terminal; pass --input <FILE> (an empty file runs the guest on zero-length input) or pipe input through stdin"
    )]
    StdinIsTerminal,
    #[error("plugin manifest at {path} is invalid: {source}")]
    ManifestInvalid {
        path: PathBuf,
        #[source]
        source: ManifestError,
    },
    #[error("trusted public key at {path} could not be read: {detail}")]
    TrustedKey { path: PathBuf, detail: String },
    #[error("plugin directory not found at {0}")]
    PluginsDirNotFound(PathBuf),
    #[error("expected a directory of plugins at {0}, found a file")]
    PluginsDirIsFile(PathBuf),
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read plugin input from stdin: {0}")]
    Stdin(std::io::Error),
    #[error(transparent)]
    Rejected(#[from] LoaderError),
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
}

pub(crate) fn run(action: PluginCmd) -> miette::Result<()> {
    match action {
        PluginCmd::Run {
            component,
            trusted_key,
            input,
            out,
            fuel,
            wall_deadline_ms,
            memory_cap_bytes,
            format,
        } => run_plugin(
            &component,
            &trusted_key,
            input.as_deref(),
            &out,
            fuel,
            wall_deadline_ms,
            memory_cap_bytes,
            format,
        )
        .map_err(|e| miette::miette!("{e}")),
        PluginCmd::Verify {
            component,
            trusted_key,
            format,
        } => verify_plugin(&component, &trusted_key, format).map_err(|e| miette::miette!("{e}")),
        PluginCmd::List {
            dir,
            trusted_key,
            format,
        } => list_plugins(&dir, trusted_key.as_deref(), format).map_err(|e| miette::miette!("{e}")),
    }
}

struct LoadedBundle {
    component_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    manifest: Manifest,
    trusted_key: PublicKey,
    component_blake3: blake3::Hash,
}

fn signature_path(component: &Path) -> PathBuf {
    let mut name: std::ffi::OsString = component.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

fn manifest_path(component: &Path) -> PathBuf {
    component.with_extension("toml")
}

fn read_required(
    path: &Path,
    missing: impl FnOnce(PathBuf) -> PluginCliError,
) -> Result<Vec<u8>, PluginCliError> {
    std::fs::read(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            missing(path.to_path_buf())
        } else {
            PluginCliError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn load_manifest(path: &Path) -> Result<Manifest, PluginCliError> {
    let bytes: Vec<u8> = read_required(path, PluginCliError::ManifestNotFound)?;
    let text: String = String::from_utf8(bytes)
        .map_err(|_| PluginCliError::ManifestNotUtf8(path.to_path_buf()))?;
    Manifest::from_toml(&text).map_err(|source| PluginCliError::ManifestInvalid {
        path: path.to_path_buf(),
        source,
    })
}

fn load_trusted_key(path: &Path) -> Result<PublicKey, PluginCliError> {
    PublicKey::from_file(path).map_err(|source| PluginCliError::TrustedKey {
        path: path.to_path_buf(),
        detail: source.to_string(),
    })
}

fn load_bundle(component: &Path, trusted_key_path: &Path) -> Result<LoadedBundle, PluginCliError> {
    let meta: std::fs::Metadata = std::fs::metadata(component).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PluginCliError::ComponentNotFound(component.to_path_buf())
        } else {
            PluginCliError::Io {
                path: component.to_path_buf(),
                source,
            }
        }
    })?;
    if meta.is_dir() {
        return Err(PluginCliError::ComponentIsDirectory(
            component.to_path_buf(),
        ));
    }
    let component_bytes: Vec<u8> =
        std::fs::read(component).map_err(|source| PluginCliError::Io {
            path: component.to_path_buf(),
            source,
        })?;
    let component_blake3: blake3::Hash = blake3::hash(&component_bytes);
    let signature_bytes: Vec<u8> = read_required(
        &signature_path(component),
        PluginCliError::SignatureNotFound,
    )?;
    let manifest: Manifest = load_manifest(&manifest_path(component))?;
    let trusted_key: PublicKey = load_trusted_key(trusted_key_path)?;
    Ok(LoadedBundle {
        component_bytes,
        signature_bytes,
        manifest,
        trusted_key,
        component_blake3,
    })
}

fn build_limits(
    fuel: Option<u64>,
    wall_deadline_ms: Option<u64>,
    memory_cap_bytes: Option<usize>,
) -> Limits {
    let defaults: Limits = Limits::default();
    Limits {
        fuel_budget: fuel.unwrap_or(defaults.fuel_budget),
        wall_deadline: wall_deadline_ms.map_or(defaults.wall_deadline, Duration::from_millis),
        memory_cap_bytes: memory_cap_bytes.unwrap_or(defaults.memory_cap_bytes),
    }
}

fn read_stdin() -> Result<Vec<u8>, PluginCliError> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return Err(PluginCliError::StdinIsTerminal);
    }
    let mut buffer: Vec<u8> = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(PluginCliError::Stdin)?;
    Ok(buffer)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut acc: String, byte: &u8| {
            let _: Result<(), std::fmt::Error> = write!(acc, "{byte:02x}");
            acc
        },
    )
}

fn provenance_json(
    component: &Path,
    bundle: &LoadedBundle,
    output_len: Option<usize>,
    out_path: Option<&Path>,
) -> serde_json::Value {
    serde_json::json!({
        "component_path": component.display().to_string(),
        "component_blake3": bundle.component_blake3.to_hex().to_string(),
        "signing_key_id": to_hex(bundle.trusted_key.keynum()),
        "manifest_name": bundle.manifest.name,
        "manifest_version": bundle.manifest.version,
        "manifest_version_authenticated": false,
        "capabilities_granted": bundle.manifest.capabilities().iter().collect::<Vec<_>>(),
        "output_len": output_len,
        "output_path": out_path.map(|p| p.display().to_string()),
    })
}

fn print_provenance_text(
    label: &str,
    component: &Path,
    bundle: &LoadedBundle,
    output_len: Option<usize>,
    out_path: Option<&Path>,
) {
    println!("plugin {label}: OK");
    println!("  component:          {}", component.display());
    println!("  component blake3:   {}", bundle.component_blake3.to_hex());
    println!(
        "  signing key id:     {}",
        to_hex(bundle.trusted_key.keynum())
    );
    println!("  manifest name:      {}", bundle.manifest.name);
    match &bundle.manifest.version {
        Some(version) => println!(
            "  manifest version:   {version} (manifest-declared, not covered by the signature)"
        ),
        None => println!("  manifest version:   (none declared)"),
    }
    let capabilities: Vec<&String> = bundle.manifest.capabilities().iter().collect();
    if capabilities.is_empty() {
        println!("  capabilities:       (none granted)");
    } else {
        println!(
            "  capabilities:       {}",
            capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<&str>>()
                .join(", ")
        );
    }
    if let Some(len) = output_len {
        println!("  output bytes:       {len}");
    }
    if let Some(path) = out_path {
        println!("  output path:        {}", path.display());
    }
}

fn run_plugin(
    component: &Path,
    trusted_key: &Path,
    input: Option<&Path>,
    out: &Path,
    fuel: Option<u64>,
    wall_deadline_ms: Option<u64>,
    memory_cap_bytes: Option<usize>,
    format: PluginFormat,
) -> Result<(), PluginCliError> {
    if out.exists() && !crate::cli::globals::current().force {
        return Err(PluginCliError::OutputExists(out.to_path_buf()));
    }
    let bundle: LoadedBundle = load_bundle(component, trusted_key)?;
    let input_bytes: Vec<u8> = match input {
        Some(path) => read_required(path, PluginCliError::InputNotFound)?,
        None => read_stdin()?,
    };
    let limits: Limits = build_limits(fuel, wall_deadline_ms, memory_cap_bytes);
    let host: PluginHost = PluginHost::new().map_err(PluginCliError::Sandbox)?;
    let compiled: wasmtime::component::Component = host.load(
        &bundle.component_bytes,
        &bundle.signature_bytes,
        &bundle.trusted_key,
        &bundle.manifest,
    )?;
    let output: Vec<u8> = host.run_component(&compiled, &input_bytes, limits)?;
    std::fs::write(out, &output).map_err(|source| PluginCliError::Io {
        path: out.to_path_buf(),
        source,
    })?;
    match format {
        PluginFormat::Text => {
            print_provenance_text("run", component, &bundle, Some(output.len()), Some(out));
        }
        PluginFormat::Json => {
            let value: serde_json::Value =
                provenance_json(component, &bundle, Some(output.len()), Some(out));
            println!("{value}");
        }
    }
    Ok(())
}

fn verify_plugin(
    component: &Path,
    trusted_key: &Path,
    format: PluginFormat,
) -> Result<(), PluginCliError> {
    let bundle: LoadedBundle = load_bundle(component, trusted_key)?;
    let host: PluginHost = PluginHost::new().map_err(PluginCliError::Sandbox)?;
    let _compiled: wasmtime::component::Component = host.load(
        &bundle.component_bytes,
        &bundle.signature_bytes,
        &bundle.trusted_key,
        &bundle.manifest,
    )?;
    match format {
        PluginFormat::Text => {
            print_provenance_text("verify", component, &bundle, None, None);
        }
        PluginFormat::Json => {
            let value: serde_json::Value = provenance_json(component, &bundle, None, None);
            println!("{value}");
        }
    }
    Ok(())
}

fn list_plugins(
    dir: &Path,
    trusted_key: Option<&Path>,
    format: PluginFormat,
) -> Result<(), PluginCliError> {
    let meta: std::fs::Metadata = std::fs::metadata(dir).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PluginCliError::PluginsDirNotFound(dir.to_path_buf())
        } else {
            PluginCliError::Io {
                path: dir.to_path_buf(),
                source,
            }
        }
    })?;
    if !meta.is_dir() {
        return Err(PluginCliError::PluginsDirIsFile(dir.to_path_buf()));
    }
    let trusted: Option<PublicKey> = trusted_key.map(load_trusted_key).transpose()?;
    let mut components: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| PluginCliError::Io {
            path: dir.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| path.extension().is_some_and(|ext| ext == "wasm"))
        .collect();
    components.sort();

    let host: PluginHost = PluginHost::new().map_err(PluginCliError::Sandbox)?;
    let mut records: Vec<serde_json::Value> = Vec::with_capacity(components.len());
    for component in &components {
        match describe_listed_plugin(&host, component, trusted.as_ref()) {
            Ok(value) => records.push(value),
            Err(err) => records.push(serde_json::json!({
                "component_path": component.display().to_string(),
                "error": err.to_string(),
            })),
        }
    }

    match format {
        PluginFormat::Text => {
            println!(
                "plugin list: {} bundle(s) at {}",
                records.len(),
                dir.display()
            );
            for record in &records {
                if let Some(err) = record.get("error").and_then(serde_json::Value::as_str) {
                    println!(
                        "  {}: ERROR {err}",
                        record
                            .get("component_path")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?")
                    );
                } else {
                    let name: &str = record
                        .get("manifest_name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?");
                    let version: &str = record
                        .get("manifest_version")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("(none)");
                    let verified: &str =
                        match record.get("verified").and_then(serde_json::Value::as_bool) {
                            Some(true) => "verified",
                            Some(false) => "signature/capability check failed",
                            None => "not checked (no --trusted-key given)",
                        };
                    println!(
                        "  {}: {name} {version} [{verified}]",
                        record
                            .get("component_path")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?")
                    );
                }
            }
        }
        PluginFormat::Json => {
            let value: serde_json::Value = serde_json::json!({ "plugins": records });
            println!("{value}");
        }
    }
    Ok(())
}

fn describe_listed_plugin(
    host: &PluginHost,
    component: &Path,
    trusted: Option<&PublicKey>,
) -> Result<serde_json::Value, PluginCliError> {
    let manifest: Manifest = load_manifest(&manifest_path(component))?;
    let component_bytes: Vec<u8> =
        std::fs::read(component).map_err(|source| PluginCliError::Io {
            path: component.to_path_buf(),
            source,
        })?;
    let component_blake3: blake3::Hash = blake3::hash(&component_bytes);
    let mut value: serde_json::Value = serde_json::json!({
        "component_path": component.display().to_string(),
        "component_blake3": component_blake3.to_hex().to_string(),
        "manifest_name": manifest.name,
        "manifest_version": manifest.version,
        "manifest_version_authenticated": false,
        "capabilities_granted": manifest.capabilities().iter().collect::<Vec<_>>(),
    });
    if let Some(trusted_key) = trusted {
        let signature_bytes: Vec<u8> = read_required(
            &signature_path(component),
            PluginCliError::SignatureNotFound,
        )?;
        let verified: bool = host
            .load(&component_bytes, &signature_bytes, trusted_key, &manifest)
            .is_ok();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("verified".to_owned(), serde_json::json!(verified));
        }
    }
    Ok(value)
}
