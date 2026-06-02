#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use disrobe_pass_mobile::{
    DetectedKind, DisassemblyReport, FlutterApkLayout, HermesModule, JsLiftReport, LibAppLayout,
    NativeScriptReport, RnExtractionReport, SnapshotSection, WebviewExtractionReport,
    XamarinReport, detect_kind, disassemble_hermes, extract_from_apk_or_ipa,
    extract_nativescript_bundle, extract_webview_bundle, extract_xamarin_bundle,
    hermes_lift_to_js_surface, parse_flutter_apk, parse_hermes_module, parse_libapp_so,
};

#[derive(Subcommand, Debug)]
pub(crate) enum MobileCmd {
    #[command(
        about = "detect the mobile runtime of an apk / ipa / bundle (React Native, Hermes, Flutter, Cordova, Capacitor, NativeScript, Xamarin)"
    )]
    Detect {
        #[arg(help = "input apk / ipa / bundle / libapp.so")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the detection JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "extract React Native JS bundles (Hermes or plain JS) out of an apk / ipa container"
    )]
    Extract {
        #[arg(help = "input apk / ipa")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-mobile-extracted)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "disassemble a Hermes bundle & emit a JS surface (identifiers, strings, function signatures)"
    )]
    Hermes {
        #[arg(help = "input Hermes bundle (index.android.bundle / main.jsbundle)")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-hermes)")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "dump the Dart snapshot symbol layout from a Flutter libapp.so / libflutter.so"
    )]
    Flutter {
        #[arg(help = "input Flutter libapp.so / libflutter.so")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the layout JSON")]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: MobileCmd) -> miette::Result<()> {
    match action {
        MobileCmd::Detect { input, out } => detect(input, out),
        MobileCmd::Extract { input, out } => extract(input, out),
        MobileCmd::Hermes { input, out } => hermes(input, out),
        MobileCmd::Flutter { input, out } => flutter(input, out),
    }
}

fn stem_of(input: &Path, fallback: &str) -> String {
    input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn write_json(path: &Path, value: &serde_json::Value) -> miette::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0810: cannot create dir: {e}"))?;
    }
    let bytes: Vec<u8> = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("DR-CLI-0811: json serialize: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| miette::miette!("DR-CLI-0812: cannot write json: {e}"))
}

const fn detected_label(kind: DetectedKind) -> &'static str {
    match kind {
        DetectedKind::ReactNativeApk => "react-native-apk",
        DetectedKind::ReactNativeIpa => "react-native-ipa",
        DetectedKind::HermesRawBytecode => "hermes-raw-bytecode",
        DetectedKind::FlutterLibAppSo => "flutter-libapp-so",
        DetectedKind::XamarinApk => "xamarin-apk",
        DetectedKind::CordovaApk => "cordova-apk",
        DetectedKind::CapacitorApk => "capacitor-apk",
        DetectedKind::NativeScriptApk => "nativescript-apk",
        DetectedKind::Ipa => "ipa",
        DetectedKind::Unknown => "unknown",
    }
}

fn detect(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0800: cannot read input: {e}"))?;
    let kind: DetectedKind = detect_kind(&bytes);
    let label: &'static str = detected_label(kind);
    let stem: String = stem_of(&input, "mobile");
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-mobile-detect.json")));
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.detect/v1",
        "input": input.display().to_string(),
        "detected": label,
        "bytes": bytes.len(),
        "blake3": blake3::hash(&bytes).to_hex().to_string(),
    });
    write_json(&out_path, &manifest)?;
    println!("mobile detect: OK");
    println!("  input:        {}", input.display());
    println!("  detected:     {label}");
    println!("  manifest:     {}", out_path.display());
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0801: cannot read input: {e}"))?;
    let kind: DetectedKind = detect_kind(&bytes);
    let stem: String = stem_of(&input, "mobile");
    let out_dir: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-mobile-extracted")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0803: cannot create out dir: {e}"))?;
    let label: &'static str = detected_label(kind);
    match kind {
        DetectedKind::ReactNativeApk | DetectedKind::ReactNativeIpa | DetectedKind::Ipa => {
            extract_react_native(&input, &bytes, &out_dir, label)
        }
        DetectedKind::CordovaApk | DetectedKind::CapacitorApk => {
            extract_webview(&input, &bytes, &out_dir, label)
        }
        DetectedKind::NativeScriptApk => extract_nativescript(&input, &bytes, &out_dir, label),
        DetectedKind::XamarinApk => extract_xamarin(&input, &bytes, &out_dir, label),
        DetectedKind::FlutterLibAppSo => extract_flutter(&input, &bytes, &out_dir, label),
        DetectedKind::HermesRawBytecode | DetectedKind::Unknown => Err(miette::miette!(
            "DR-CLI-0816: `mobile extract` operates on apk/ipa containers; detected {label}. Use `mobile hermes` for raw Hermes bytecode."
        )),
    }
}

fn extract_flutter(input: &Path, bytes: &[u8], out_dir: &Path, label: &str) -> miette::Result<()> {
    let is_elf: bool = bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'];
    let (libapp_path, layout): (String, LibAppLayout) = if is_elf {
        (
            input.display().to_string(),
            parse_libapp_so(bytes)
                .map_err(|e| miette::miette!("DR-CLI-0826: libapp parse: {e}"))?,
        )
    } else {
        let apk: FlutterApkLayout = parse_flutter_apk(bytes)
            .map_err(|e| miette::miette!("DR-CLI-0826: flutter apk parse: {e}"))?;
        (apk.libapp_path, apk.layout)
    };
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.extract/v1",
        "framework": label,
        "input": input.display().to_string(),
        "libapp_path": libapp_path,
        "layout": layout,
    });
    write_json(&manifest_path, &manifest)?;
    let recovered: usize = [
        layout.vm_snapshot_data.as_ref(),
        layout.vm_snapshot_instructions.as_ref(),
        layout.isolate_snapshot_data.as_ref(),
        layout.isolate_snapshot_instructions.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count();
    println!("mobile extract: OK");
    println!("  input:        {}", input.display());
    println!("  framework:    {label}");
    println!("  libapp.so:    {libapp_path}");
    println!("  dart symbols: {recovered}/4 recovered");
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn extract_react_native(
    input: &Path,
    bytes: &[u8],
    out_dir: &Path,
    label: &str,
) -> miette::Result<()> {
    let report: RnExtractionReport = extract_from_apk_or_ipa(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0802: react-native extract failed: {e}"))?;
    let mut written: Vec<serde_json::Value> = Vec::with_capacity(report.bundles.len());
    for (idx, bundle) in report.bundles.iter().enumerate() {
        let file_name: String = Path::new(&bundle.container_path)
            .file_name()
            .and_then(OsStr::to_str)
            .map_or_else(|| format!("bundle-{idx}.jsbundle"), str::to_owned);
        let bundle_path: PathBuf = out_dir.join(&file_name);
        std::fs::write(&bundle_path, &bundle.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0804: cannot write bundle: {e}"))?;
        written.push(serde_json::json!({
            "container_path": bundle.container_path,
            "platform": format!("{:?}", bundle.platform),
            "format": format!("{:?}", bundle.format),
            "bytes": bundle.bytes_len,
            "blake3": blake3::Hash::from(bundle.blake3).to_hex().to_string(),
            "disk_path": bundle_path.display().to_string(),
        }));
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.extract/v1",
        "framework": label,
        "input": input.display().to_string(),
        "manifest_entries_scanned": report.manifest_entries_scanned,
        "bundles": written,
    });
    write_json(&manifest_path, &manifest)?;
    print_extract_summary(input, label, report.bundles.len(), out_dir, &manifest_path);
    Ok(())
}

fn extract_webview(input: &Path, bytes: &[u8], out_dir: &Path, label: &str) -> miette::Result<()> {
    let report: WebviewExtractionReport = extract_webview_bundle(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0817: webview extract failed: {e}"))?;
    let mut written: Vec<serde_json::Value> = Vec::with_capacity(report.assets.len());
    for asset in &report.assets {
        let disk_path: PathBuf = out_dir.join(sanitize_relpath(&asset.container_path));
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0818: cannot create asset dir: {e}"))?;
        }
        std::fs::write(&disk_path, &asset.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0819: cannot write asset: {e}"))?;
        written.push(serde_json::json!({
            "container_path": asset.container_path,
            "mime_hint": asset.mime_hint,
            "bytes": asset.bytes_len,
            "disk_path": disk_path.display().to_string(),
        }));
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.extract/v1",
        "framework": label,
        "input": input.display().to_string(),
        "kind": format!("{:?}", report.kind),
        "entry_html": report.entry_html,
        "assets": written,
    });
    write_json(&manifest_path, &manifest)?;
    print_extract_summary(input, label, report.assets.len(), out_dir, &manifest_path);
    Ok(())
}

fn extract_nativescript(
    input: &Path,
    bytes: &[u8],
    out_dir: &Path,
    label: &str,
) -> miette::Result<()> {
    let report: NativeScriptReport = extract_nativescript_bundle(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0820: nativescript extract failed: {e}"))?;
    let mut written: Vec<serde_json::Value> = Vec::with_capacity(report.bundles.len());
    for bundle in &report.bundles {
        let disk_path: PathBuf = out_dir.join(sanitize_relpath(&bundle.container_path));
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0821: cannot create bundle dir: {e}"))?;
        }
        std::fs::write(&disk_path, &bundle.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0822: cannot write bundle: {e}"))?;
        written.push(serde_json::json!({
            "container_path": bundle.container_path,
            "bytes": bundle.bytes_len,
            "disk_path": disk_path.display().to_string(),
        }));
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.extract/v1",
        "framework": label,
        "input": input.display().to_string(),
        "has_runtime_marker": report.has_runtime_marker,
        "bundles": written,
    });
    write_json(&manifest_path, &manifest)?;
    print_extract_summary(input, label, report.bundles.len(), out_dir, &manifest_path);
    Ok(())
}

fn extract_xamarin(input: &Path, bytes: &[u8], out_dir: &Path, label: &str) -> miette::Result<()> {
    let report: XamarinReport = extract_xamarin_bundle(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0823: xamarin extract failed: {e}"))?;
    let mut written: Vec<serde_json::Value> = Vec::with_capacity(report.assemblies.len());
    for asm in &report.assemblies {
        let disk_path: PathBuf = out_dir.join(sanitize_relpath(&asm.container_path));
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0824: cannot create assembly dir: {e}"))?;
        }
        std::fs::write(&disk_path, &asm.bytes)
            .map_err(|e| miette::miette!("DR-CLI-0825: cannot write assembly: {e}"))?;
        written.push(serde_json::json!({
            "container_path": asm.container_path,
            "bytes": asm.bytes_len,
            "disk_path": disk_path.display().to_string(),
        }));
    }
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.mobile.extract/v1",
        "framework": label,
        "input": input.display().to_string(),
        "kind": format!("{:?}", report.kind),
        "assembly_store_header": report.assembly_store_header,
        "assemblies": written,
    });
    write_json(&manifest_path, &manifest)?;
    print_extract_summary(
        input,
        label,
        report.assemblies.len(),
        out_dir,
        &manifest_path,
    );
    Ok(())
}

fn print_extract_summary(
    input: &Path,
    label: &str,
    artifact_count: usize,
    out_dir: &Path,
    manifest_path: &Path,
) {
    println!("mobile extract: OK");
    println!("  input:        {}", input.display());
    println!("  framework:    {label}");
    println!("  artifacts:    {artifact_count}");
    println!("  out dir:      {}", out_dir.display());
    println!("  manifest:     {}", manifest_path.display());
}

fn sanitize_relpath(container_path: &str) -> PathBuf {
    let mut out: PathBuf = PathBuf::new();
    for comp in container_path.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        out.push(comp);
    }
    if out.as_os_str().is_empty() {
        out.push("asset.bin");
    }
    out
}

fn hermes(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0805: cannot read input: {e}"))?;
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0806: not a Hermes bundle: {e}"))?;
    let disasm: DisassemblyReport = disassemble_hermes(&module);
    let lift: JsLiftReport = hermes_lift_to_js_surface(&module);
    let stem: String = stem_of(&input, "hermes");
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-hermes")));
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0807: cannot create out dir: {e}"))?;
    let disasm_path: PathBuf = out_dir.join(format!("{stem}.disasm.json"));
    let lift_path: PathBuf = out_dir.join(format!("{stem}.lifted.json"));
    write_json(
        &disasm_path,
        &serde_json::to_value(&disasm)
            .map_err(|e| miette::miette!("DR-CLI-0808: disasm serialize: {e}"))?,
    )?;
    write_json(
        &lift_path,
        &serde_json::to_value(&lift)
            .map_err(|e| miette::miette!("DR-CLI-0809: lift serialize: {e}"))?,
    )?;
    println!("mobile hermes: OK");
    println!("  input:        {}", input.display());
    println!("  version:      {}", module.header.version);
    println!("  functions:    {}", module.header.function_count);
    println!("  disasm:       {}", disasm_path.display());
    println!("  lifted js:    {}", lift_path.display());
    Ok(())
}

fn flutter(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0813: cannot read input: {e}"))?;
    let is_elf: bool = bytes.len() >= 4 && bytes[..4] == [0x7f, b'E', b'L', b'F'];
    let mut libapp_path: Option<String> = None;
    let layout: LibAppLayout = if is_elf {
        parse_libapp_so(&bytes).map_err(|e| miette::miette!("DR-CLI-0814: libapp parse: {e}"))?
    } else {
        let apk: FlutterApkLayout = parse_flutter_apk(&bytes)
            .map_err(|e| miette::miette!("DR-CLI-0814: flutter apk parse: {e}"))?;
        libapp_path = Some(apk.libapp_path);
        apk.layout
    };
    let stem: String = stem_of(&input, "flutter");
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-mobile-flutter.json")));
    write_json(
        &out_path,
        &serde_json::to_value(&layout)
            .map_err(|e| miette::miette!("DR-CLI-0815: layout serialize: {e}"))?,
    )?;
    let recovered: usize = [
        layout.vm_snapshot_data.as_ref(),
        layout.vm_snapshot_instructions.as_ref(),
        layout.isolate_snapshot_data.as_ref(),
        layout.isolate_snapshot_instructions.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count();
    println!("mobile flutter: OK");
    println!("  input:        {}", input.display());
    if let Some(p) = libapp_path.as_ref() {
        println!("  libapp.so:    {p} (from apk)");
    }
    println!("  sections:     {}", layout.section_names.len());
    println!("  dart symbols: {recovered}/4 recovered");
    print_snapshot_symbol("vm data     ", layout.vm_snapshot_data.as_ref());
    print_snapshot_symbol("vm instr    ", layout.vm_snapshot_instructions.as_ref());
    print_snapshot_symbol("isolate data", layout.isolate_snapshot_data.as_ref());
    print_snapshot_symbol(
        "isolate inst",
        layout.isolate_snapshot_instructions.as_ref(),
    );
    println!("  out:          {}", out_path.display());
    Ok(())
}

fn print_snapshot_symbol(label: &str, section: Option<&SnapshotSection>) {
    match section {
        Some(s) => println!(
            "  {label}: {} @ {:#x} size {} ({:.1} KiB)",
            s.symbol,
            s.address,
            s.size,
            s.size as f64 / 1024.0
        ),
        None => println!("  {label}: <missing>"),
    }
}
