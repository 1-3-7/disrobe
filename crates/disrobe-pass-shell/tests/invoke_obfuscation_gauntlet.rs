#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    Detection, Dialect, Family, InvokeObfuscationLevel, ReverseReport, detect, reverse_compress,
    reverse_encoding, reverse_string, reverse_token,
};

fn gauntlet_path(name: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root must exist");
    workspace_root
        .join("corpus")
        .join("shell")
        .join("invoke-obfuscation")
        .join("gauntlet")
        .join(name)
}

fn read_gauntlet(name: &str) -> String {
    let p: PathBuf = gauntlet_path(name);
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} failed: {e}", p.display()))
}

#[test]
fn gauntlet_token_layer_strips_backticks_and_folds_format_ops() {
    let src: String = read_gauntlet("token_obfuscated.ps1");
    let r: ReverseReport = reverse_token(&src);
    assert_eq!(r.level, InvokeObfuscationLevel::Token);
    assert!(
        r.transformations
            .contains(&"strip-backtick-escapes".to_owned()),
        "expected strip-backtick-escapes in {:?}",
        r.transformations
    );
    let out_lower: String = r.output.to_ascii_lowercase();
    assert!(
        out_lower.contains("write-h") || out_lower.contains("write"),
        "token pass must surface Write-Host fragment, got: {}",
        &r.output.chars().take(300).collect::<String>()
    );
    assert!(
        r.output.contains("Get-WmiO") || r.output.contains("Get-Wmi"),
        "token pass must surface Get-WmiO fragment, got: {}",
        &r.output.chars().take(300).collect::<String>()
    );
}

#[test]
fn gauntlet_token_layer_string_format_unwraps_cmdlets() {
    let src: String = read_gauntlet("token_obfuscated.ps1");
    let r: ReverseReport = reverse_string(&src);
    assert_eq!(r.level, InvokeObfuscationLevel::String);
    assert!(
        r.transformations
            .contains(&"fold-format-strings".to_owned()),
        "expected fold-format-strings in {:?}",
        r.transformations
    );
    let out: &str = &r.output;
    assert!(
        out.contains("Write-Host") || out.to_ascii_lowercase().contains("write-host"),
        "string pass must recover Write-Host, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Get-WmiObject") || out.contains("Get-WmiO"),
        "string pass must recover Get-WmiObject fragment, got: {}",
        &out.chars().take(300).collect::<String>()
    );
}

#[test]
fn gauntlet_string_layer_folds_all_format_ops() {
    let src: String = read_gauntlet("string_obfuscated.ps1");
    let r: ReverseReport = reverse_string(&src);
    assert_eq!(r.level, InvokeObfuscationLevel::String);
    assert!(
        r.transformations
            .contains(&"fold-format-strings".to_owned()),
        "expected fold-format-strings in {:?}",
        r.transformations
    );
    let out: &str = &r.output;
    assert!(
        out.contains("Write-Host") || out.to_ascii_lowercase().contains("write-host"),
        "must recover Write-Host from string-layer sample, got: {}",
        &out.chars().take(400).collect::<String>()
    );
    assert!(
        out.contains("Win32_OperatingSystem") || out.contains("Win32_Operating"),
        "must recover Win32_OperatingSystem, got: {}",
        &out.chars().take(400).collect::<String>()
    );
    assert!(
        out.contains("Win32_Processor"),
        "must recover Win32_Processor, got: {}",
        &out.chars().take(400).collect::<String>()
    );
    assert!(
        out.contains("Get-SystemInfo") || out.contains("SystemInfo"),
        "must recover Get-SystemInfo, got: {}",
        &out.chars().take(400).collect::<String>()
    );
}

#[test]
fn gauntlet_encoding_layer_detect_and_decode() -> disrobe_pass_shell::Result<()> {
    let src: String = read_gauntlet("encoding_obfuscated.ps1");
    let det: Detection = detect(src.as_bytes());
    assert_eq!(
        det.dialect,
        Dialect::PowerShell,
        "dialect must be PowerShell"
    );
    assert_eq!(
        det.family,
        Family::InvokeObfuscationEncoding,
        "family must be InvokeObfuscationEncoding"
    );
    let r: ReverseReport = reverse_encoding(&src)?;
    assert_eq!(r.level, InvokeObfuscationLevel::Encoding);
    assert!(
        r.transformations
            .contains(&"extract-encodedcommand".to_owned()),
        "must apply extract-encodedcommand, got: {:?}",
        r.transformations
    );
    assert!(
        r.transformations.contains(&"base64-decode".to_owned()),
        "must apply base64-decode, got: {:?}",
        r.transformations
    );
    let out: &str = &r.output;
    assert!(
        out.contains("Get-SystemInfo"),
        "encoding decode must surface Get-SystemInfo, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Write-Host"),
        "encoding decode must surface Write-Host, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Win32_OperatingSystem"),
        "encoding decode must surface Win32_OperatingSystem, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Get-WmiObject"),
        "encoding decode must surface Get-WmiObject, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    Ok(())
}

#[test]
fn gauntlet_compress_layer_inflates_payload() -> disrobe_pass_shell::Result<()> {
    let src: String = read_gauntlet("compress_obfuscated.ps1");
    let r: ReverseReport = reverse_compress(&src)?;
    assert_eq!(r.level, InvokeObfuscationLevel::Compress);
    assert!(
        r.transformations
            .contains(&"extract-compress-payload".to_owned()),
        "must apply extract-compress-payload, got: {:?}",
        r.transformations
    );
    assert!(
        r.transformations.contains(&"base64-decode".to_owned()),
        "must apply base64-decode, got: {:?}",
        r.transformations
    );
    assert!(
        r.transformations.contains(&"gzip-inflate".to_owned()),
        "must apply gzip-inflate, got: {:?}",
        r.transformations
    );
    let out: &str = &r.output;
    assert!(
        out.contains("Get-SystemInfo"),
        "compress inflate must recover Get-SystemInfo, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Write-Host"),
        "compress inflate must recover Write-Host, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Win32_OperatingSystem"),
        "compress inflate must recover Win32_OperatingSystem, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    assert!(
        out.contains("Get-WmiObject"),
        "compress inflate must recover Get-WmiObject, got: {}",
        &out.chars().take(300).collect::<String>()
    );
    Ok(())
}

#[test]
fn string_layer_format_op_honours_dotnet_escaped_braces() {
    let src: &str = "(\"{0}{{literal}}{1}\" -f 'Get','Process')";
    let r: ReverseReport = reverse_string(src);
    let powershell_string_format_oracle: &str = "\"Get{literal}Process\"";
    assert!(
        r.transformations
            .contains(&"fold-format-strings".to_owned()),
        "expected fold-format-strings in {:?}",
        r.transformations
    );
    assert_eq!(
        r.output, powershell_string_format_oracle,
        "format-op fold must match real PowerShell String.Format escaped-brace semantics"
    );
}

#[test]
fn string_layer_format_op_preserves_alignment_placeholder_verbatim() {
    let src: &str = "(\"{0,5}-{1}\" -f 'Get','Process')";
    let r: ReverseReport = reverse_string(src);
    assert!(
        r.output.contains("{0,5}"),
        "alignment placeholder must be left intact, not silently mis-substituted: {}",
        r.output
    );
}

fn locate_powershell() -> Option<&'static str> {
    for candidate in ["pwsh", "powershell"] {
        let ok: bool = std::process::Command::new(candidate)
            .args(["-NoProfile", "-Command", "exit 0"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s: std::process::ExitStatus| s.success());
        if ok {
            return Some(candidate);
        }
    }
    None
}

fn real_powershell_eval(exe: &str, expr: &str) -> Option<String> {
    let out: std::process::Output = std::process::Command::new(exe)
        .args(["-NoProfile", "-Command", expr])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(text.trim_end_matches(['\r', '\n']).to_owned())
}

#[test]
fn string_format_fold_matches_live_powershell_string_format() {
    let Some(exe): Option<&str> = locate_powershell() else {
        eprintln!("skip: no pwsh/powershell on PATH; live String.Format oracle unavailable");
        return;
    };
    let expressions: [&str; 6] = [
        "(\"{0}{1}{2}\" -f 'a,','b',',c')",
        "(\"{1}{0}\" -f ',World','Hello')",
        "(\"{0}\" -f 'x,y')",
        "(\"{0}{1}\" -f 'it''s ','here')",
        "(\"{2}{0}{1}\" -f 'bje','ct','Get-WmiO')",
        "(\"{0}{1}{2}{3}\" -f 'Win','32_','Opera','tingSystem')",
    ];
    let mut graded: usize = 0;
    for expr in expressions {
        let Some(expected): Option<String> = real_powershell_eval(exe, expr) else {
            panic!(
                "{exe} was located above and `{expr}` is a fixed expression in this file, so a \
                 failure to evaluate it is a defect in this probe rather than a reason to grade \
                 one expression fewer"
            );
        };
        let r: ReverseReport = reverse_string(expr);
        let folded: &str = r.output.trim_matches('"');
        assert_eq!(
            folded, expected,
            "disrobe String.Format fold of `{expr}` must equal live PowerShell output"
        );
        graded = graded.saturating_add(1);
    }
    assert_eq!(
        graded,
        expressions.len(),
        "every expression must be graded against live PowerShell, or this case reports success \
         over a population it never measured"
    );
}
