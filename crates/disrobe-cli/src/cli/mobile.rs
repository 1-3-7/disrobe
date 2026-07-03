#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use disrobe_pass_mobile::{
    ApkReconReport, DetectedKind, DisassemblyReport, FlutterApkLayout, HermesModule, JsLiftReport,
    LibAppLayout, NativeLibrary, NativeScriptReport, ProtectorWall, RnExtractionReport,
    SnapshotSection, SurfacedEndpoint, SurfacedSecret, WebviewExtractionReport, XamarinReport,
    analyze_apk_recon, detect_kind, disassemble_hermes, extract_android_bundle_children,
    extract_android_dex_children, extract_from_apk_or_ipa, extract_nativescript_bundle,
    extract_webview_bundle, extract_xamarin_bundle, hermes_lift_to_js_surface, parse_flutter_apk,
    parse_hermes_module, parse_libapp_so,
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
    #[command(
        about = "static reconnaissance of an apk / ipa: decoded manifest, resources, native libraries + ABIs, surfaced secrets & network endpoints, packer/shield walls, and the APK Signing Block signer certificate SHA-256 fingerprints"
    )]
    Recon {
        #[arg(help = "input apk / ipa container")]
        input: PathBuf,
        #[arg(
            long,
            help = "emit the full recon report as machine-clean JSON to stdout (no human-readable summary)"
        )]
        json: bool,
    },
}

pub(crate) fn run(action: MobileCmd) -> miette::Result<()> {
    match action {
        MobileCmd::Detect { input, out } => detect(input, out),
        MobileCmd::Extract { input, out } => extract(input, out),
        MobileCmd::Hermes { input, out } => hermes(input, out),
        MobileCmd::Flutter { input, out } => flutter(input, out),
        MobileCmd::Recon { input, json } => recon(input, json),
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
        DetectedKind::FlutterDartKernel => "flutter-dart-kernel",
        DetectedKind::XamarinApk => "xamarin-apk",
        DetectedKind::CordovaApk => "cordova-apk",
        DetectedKind::CapacitorApk => "capacitor-apk",
        DetectedKind::NativeScriptApk => "nativescript-apk",
        DetectedKind::Ipa => "ipa",
        DetectedKind::AndroidDexApk => "android-apk-dex",
        DetectedKind::AndroidBundle => "android-bundle",
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
        DetectedKind::AndroidDexApk => extract_android_dex(&input, &bytes, &out_dir, label),
        DetectedKind::AndroidBundle => extract_android_bundle(&input, &bytes, &out_dir, label),
        DetectedKind::HermesRawBytecode
        | DetectedKind::FlutterDartKernel
        | DetectedKind::Unknown => Err(miette::miette!(
            "DR-CLI-0816: `mobile extract` operates on apk/ipa containers; detected {label}. Use `mobile hermes` for raw Hermes bytecode or `flutter kernel` for a Dart .dill."
        )),
    }
}

fn extract_android_bundle(
    input: &Path,
    bytes: &[u8],
    out_dir: &Path,
    label: &str,
) -> miette::Result<()> {
    let children: Vec<(String, Vec<u8>)> = extract_android_bundle_children(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0820: android bundle extract: {e}"))?;
    if children.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0821: bundle contains no inner apk or dex entries"
        ));
    }
    let mut written: Vec<String> = Vec::with_capacity(children.len());
    for (name, data) in &children {
        let safe: String = name.replace(['/', '\\'], "_");
        let dest: PathBuf = out_dir.join(&safe);
        std::fs::write(&dest, data)
            .map_err(|e| miette::miette!("DR-CLI-0822: cannot write {}: {e}", dest.display()))?;
        written.push(format!("{} ({} bytes)", dest.display(), data.len()));
    }
    println!("mobile extract: OK");
    println!("  input:        {}", input.display());
    println!("  detected:     {label}");
    for entry in &written {
        println!("  wrote:        {entry}");
    }
    Ok(())
}

fn extract_android_dex(
    input: &Path,
    bytes: &[u8],
    out_dir: &Path,
    label: &str,
) -> miette::Result<()> {
    let dex_children: Vec<(String, Vec<u8>)> = extract_android_dex_children(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0817: android dex extract: {e}"))?;
    if dex_children.is_empty() {
        return Err(miette::miette!(
            "DR-CLI-0818: apk contains no top-level classes*.dex entries"
        ));
    }
    let mut written: Vec<String> = Vec::with_capacity(dex_children.len());
    for (name, data) in &dex_children {
        let dest: PathBuf = out_dir.join(name);
        std::fs::write(&dest, data)
            .map_err(|e| miette::miette!("DR-CLI-0819: cannot write {}: {e}", dest.display()))?;
        written.push(format!("{} ({} bytes)", dest.display(), data.len()));
    }
    println!("mobile extract: OK");
    println!("  input:        {}", input.display());
    println!("  detected:     {label}");
    for line in &written {
        println!("  dex:          {line}");
    }
    Ok(())
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
    let js_path: PathBuf = out_dir.join(format!("{stem}.js"));
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
    let js_source: String = render_hermes_js_surface(&module, &lift);
    std::fs::write(&js_path, js_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0827: cannot write lifted js: {e}"))?;
    println!("mobile hermes: OK");
    println!("  input:        {}", input.display());
    println!("  version:      {}", module.header.version);
    println!("  functions:    {}", module.header.function_count);
    println!("  disasm:       {}", disasm_path.display());
    println!("  lift report:  {}", lift_path.display());
    println!("  lifted js:    {}", js_path.display());
    Ok(())
}

fn render_hermes_js_surface(module: &HermesModule, lift: &JsLiftReport) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(lift.function_surface.len() * 96 + 256);
    let _ = writeln!(
        out,
        "// disrobe hermes lift: JS surface (hermes_version={}, functions={}, identifiers={}, strings={}).",
        module.header.version,
        module.functions.len(),
        module.identifiers.len(),
        module.strings.len()
    );
    for surface in &lift.function_surface {
        out.push_str(surface);
        out.push('\n');
    }
    out
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

fn recon(input: PathBuf, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0830: cannot read input: {e}"))?;
    let report: ApkReconReport = analyze_apk_recon(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0831: apk recon failed: {e}"))?;
    if json {
        let value: serde_json::Value = serde_json::to_value(&report)
            .map_err(|e| miette::miette!("DR-CLI-0832: recon serialize: {e}"))?;
        let text: String = serde_json::to_string_pretty(&value)
            .map_err(|e| miette::miette!("DR-CLI-0833: recon render: {e}"))?;
        println!("{text}");
        return Ok(());
    }
    print_recon_summary(&input, &report);
    Ok(())
}

fn print_recon_summary(input: &Path, report: &ApkReconReport) {
    println!("mobile recon: OK");
    println!("  input:        {}", input.display());
    match report.manifest.as_ref() {
        Some(m) => {
            println!(
                "  manifest:     decoded (package={}, activities={}, services={}, receivers={}, providers={}, permissions={})",
                m.package.as_deref().unwrap_or("?"),
                m.activities.len(),
                m.services.len(),
                m.receivers.len(),
                m.providers.len(),
                m.permissions.len()
            );
        }
        None => println!("  manifest:     <not decoded>"),
    }
    if let Some(res) = report.resources.as_ref() {
        println!(
            "  resources:    packages={}, value-strings={}, types={}",
            res.package_names.len(),
            res.value_string_count,
            res.type_names.len()
        );
    }
    println!(
        "  native libs:  {} ({} abi(s): {})",
        report.native_libraries.len(),
        report.abis.len(),
        if report.abis.is_empty() {
            "none".to_owned()
        } else {
            report.abis.join(", ")
        }
    );
    for lib in &report.native_libraries {
        print_native_lib(lib);
    }
    if !report.ios_frameworks.is_empty() {
        println!("  ios frameworks: {}", report.ios_frameworks.join(", "));
    }
    if !report.ios_dylibs.is_empty() {
        println!("  ios dylibs:   {}", report.ios_dylibs.len());
    }
    println!("  routed child: {}", report.routed_children.len());
    print_recon_secrets(&report.secrets);
    print_recon_endpoints(&report.endpoints);
    print_recon_protectors(&report.protector_walls);
    print_recon_signing(report);
}

fn print_native_lib(lib: &NativeLibrary) {
    println!(
        "    - {} (abi={}, {} bytes, elf={})",
        lib.container_path,
        lib.abi.as_deref().unwrap_or("?"),
        lib.size,
        lib.is_elf
    );
}

fn print_recon_secrets(secrets: &[SurfacedSecret]) {
    if secrets.is_empty() {
        println!("  secrets:      none surfaced");
        return;
    }
    println!("  secrets:      {}", secrets.len());
    for s in secrets {
        println!(
            "    - [{}] {} in {}: {}",
            s.code, s.kind, s.container_path, s.redacted_preview
        );
    }
}

fn print_recon_endpoints(endpoints: &[SurfacedEndpoint]) {
    if endpoints.is_empty() {
        println!("  endpoints:    none surfaced");
        return;
    }
    println!("  endpoints:    {}", endpoints.len());
    for e in endpoints {
        println!("    - [{}] {} in {}", e.kind, e.value, e.container_path);
    }
}

fn print_recon_protectors(walls: &[ProtectorWall]) {
    if walls.is_empty() {
        println!("  protectors:   none detected");
        return;
    }
    println!("  protectors:   {}", walls.len());
    for w in walls {
        let tag: &str = if w.recoverable { "recoverable" } else { "WALL" };
        println!(
            "    - {:?} [{tag}]: {} ({})",
            w.protector, w.evidence, w.note
        );
    }
}

fn print_recon_signing(report: &ApkReconReport) {
    let signing: &disrobe_pass_mobile::ApkSigningBlockReport = &report.signing;
    if !signing.signing_block_present {
        println!("  signing:      no APK Signing Block (v1-only or unsigned)");
        return;
    }
    let schemes: Vec<String> = signing
        .schemes
        .iter()
        .map(|s: &disrobe_pass_mobile::SchemeBlock| format!("{:?}", s.scheme))
        .collect();
    println!(
        "  signing:      block present (schemes: {})",
        if schemes.is_empty() {
            "none".to_owned()
        } else {
            schemes.join(", ")
        }
    );
    for scheme in &signing.schemes {
        for signer in &scheme.signers {
            for cert in &signer.certificates {
                println!(
                    "    - signer cert SHA-256: {} (subject={}, serial={})",
                    cert.sha256_fingerprint, cert.subject, cert.serial_hex
                );
            }
        }
    }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn hello_hermes_bundle() -> Option<Vec<u8>> {
        let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("mobile")
            .join("hermes")
            .join("hello")
            .join("index.android.bundle");
        std::fs::read(&path).ok()
    }

    #[test]
    fn hermes_writes_lifted_js_surface_file() {
        let Some(bytes): Option<Vec<u8>> = hello_hermes_bundle() else {
            return;
        };
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("mobile-hermes-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let in_path: PathBuf = scratch.join("index.android.bundle");
        std::fs::write(&in_path, &bytes).expect("write hermes bundle");
        let out_dir: PathBuf = scratch.join("out");

        hermes(in_path, Some(out_dir.clone())).expect("mobile hermes ok");

        let js_path: PathBuf = out_dir.join("index.android.js");
        assert!(
            js_path.is_file(),
            "mobile hermes must write a lifted .js surface like hermes decompile does"
        );
        let js: String = std::fs::read_to_string(&js_path).expect("read lifted js");
        assert!(
            js.contains("function "),
            "lifted js surface must contain real function declarations: {js}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
