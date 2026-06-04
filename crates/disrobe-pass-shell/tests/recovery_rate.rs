#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    BatchCfg, BatchReport, ObfuscatorDetection, PsObfuscator, ReverseReport, VbsReport,
    deobfuscate_vbs, obfuscator_detect, resolve_cfg, reverse_batch, reverse_chameleon,
    reverse_compress, reverse_encoding, reverse_invoke_stealth, reverse_string, reverse_token,
};

fn corpus_path(relative: &str) -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &std::path::Path = manifest_dir
        .parent()
        .and_then(|p: &std::path::Path| p.parent())
        .expect("workspace root");
    workspace_root.join("corpus").join("shell").join(relative)
}

fn read(relative: &str) -> String {
    let bytes: Vec<u8> = std::fs::read(corpus_path(relative))
        .unwrap_or_else(|e: std::io::Error| panic!("read {relative}: {e}"));
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

struct Case {
    name: &'static str,
    recovered: bool,
}

fn rate(cases: &[Case]) -> f64 {
    if cases.is_empty() {
        return 0.0;
    }
    let hits: usize = cases.iter().filter(|c: &&Case| c.recovered).count();
    hits as f64 / cases.len() as f64
}

fn powershell_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();

    let token_src: String = read("powershell/invoke-obfuscation/token/hello.ps1");
    let token: ReverseReport = reverse_token(&token_src);
    let token_then_string: ReverseReport = reverse_string(&token.output);
    cases.push(Case {
        name: "io-token",
        recovered: token_then_string
            .output
            .to_ascii_lowercase()
            .contains("write-host")
            && token_then_string.output.contains("hello world"),
    });

    let string: ReverseReport =
        reverse_string(&read("powershell/invoke-obfuscation/string/hello.ps1"));
    cases.push(Case {
        name: "io-string",
        recovered: string.output.to_ascii_lowercase().contains("write-host"),
    });

    let enc: ReverseReport =
        reverse_encoding(&read("powershell/invoke-obfuscation/encoding/hello.ps1"))
            .expect("decode encoding");
    cases.push(Case {
        name: "io-encoding",
        recovered: enc.output.contains("hello world"),
    });

    let comp: ReverseReport =
        reverse_compress(&read("powershell/invoke-obfuscation/compress/hello.ps1"))
            .expect("inflate compress");
    cases.push(Case {
        name: "io-compress",
        recovered: comp.output.contains("hello world"),
    });

    let cham: String = reverse_chameleon(&read("powershell/chameleon/hello.ps1")).output;
    cases.push(Case {
        name: "chameleon",
        recovered: cham.to_ascii_lowercase().contains("write-host")
            || cham.to_ascii_lowercase().contains("hello world")
            || cham.to_ascii_lowercase().contains("frombase64"),
    });

    let stealth: String =
        reverse_invoke_stealth(&read("powershell/invoke-stealth/hello.ps1")).output;
    cases.push(Case {
        name: "invoke-stealth",
        recovered: stealth.to_ascii_lowercase().contains("write-host")
            || stealth.to_ascii_lowercase().contains("hello world")
            || stealth.to_ascii_lowercase().contains("frombase64"),
    });

    let bxor_src: &str = "(72,73,74 | %{[char]($_ -bxor 0)}) -join ''";
    let bxor: ReverseReport = reverse_token(bxor_src);
    cases.push(Case {
        name: "bxor-pipeline",
        recovered: bxor.output.contains("\"HIJ\""),
    });

    let comspec: ReverseReport = reverse_token("&( $env:ComSpec[4,15,25]-Join'')( 'x' )");
    cases.push(Case {
        name: "iex-indirection",
        recovered: comspec.output.contains("Invoke-Expression"),
    });

    let det: ObfuscatorDetection =
        obfuscator_detect("# SIG # Begin signature block\n$x=[char]73\n");
    cases.push(Case {
        name: "obfuscator-detect",
        recovered: det.obfuscator != PsObfuscator::None && det.confidence > 0.0,
    });

    cases
}

fn bash_cases() -> Vec<Case> {
    use disrobe_pass_shell::{BashfuscatorLevel, BashfuscatorReport, reverse_bashfuscator};
    let mut cases: Vec<Case> = Vec::new();

    let obf: BashfuscatorReport = reverse_bashfuscator(
        BashfuscatorLevel::Obfuscate,
        &read("bash/bashfuscator/obfuscate/hello.sh"),
    )
    .expect("obfuscate");
    cases.push(Case {
        name: "bf-obfuscate",
        recovered: {
            let o: String = obf.output.to_ascii_lowercase();
            o.contains("echo") && o.contains("hello") && o.contains("world")
        },
    });

    let comp: BashfuscatorReport = reverse_bashfuscator(
        BashfuscatorLevel::Compress,
        &read("bash/bashfuscator/compress/hello.sh"),
    )
    .expect("compress");
    cases.push(Case {
        name: "bf-compress",
        recovered: {
            let o: String = comp.output.to_ascii_lowercase();
            o.contains("echo") || o.contains("hello") || o.contains("world")
        },
    });

    cases
}

fn batch_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();

    let baseline: BatchReport = reverse_batch(&read("batch/baseline/hello.bat"));
    cases.push(Case {
        name: "batch-baseline",
        recovered: baseline.output.contains("echo hello world"),
    });

    let call: BatchReport = reverse_batch(&read("batch/call/hello.bat"));
    cases.push(Case {
        name: "batch-call",
        recovered: call.output.contains("echo hello world"),
    });

    let cfg: BatchCfg = resolve_cfg(&read("batch/megafile/edge_cases.bat"));
    cases.push(Case {
        name: "batch-cfg-labels",
        recovered: cfg.labels.contains_key("MAIN_FLOW")
            && cfg.call_targets.contains(&"SUM_TWO".to_owned()),
    });

    cases
}

fn vbs_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();

    let chr: VbsReport = deobfuscate_vbs(&read("vbs/chr_chain/hello.vbs"));
    cases.push(Case {
        name: "vbs-chr-chain",
        recovered: chr.output.to_ascii_lowercase().contains("wscript"),
    });

    let plain: VbsReport = deobfuscate_vbs(&read("vbs/hello.vbs"));
    cases.push(Case {
        name: "vbs-baseline",
        recovered: plain.output.contains("WScript.Echo"),
    });

    cases
}

#[test]
fn measured_recovery_rates_meet_floor() {
    let ps: Vec<Case> = powershell_cases();
    let bash: Vec<Case> = bash_cases();
    let batch: Vec<Case> = batch_cases();
    let vbs: Vec<Case> = vbs_cases();

    let ps_rate: f64 = rate(&ps);
    let bash_rate: f64 = rate(&bash);
    let batch_rate: f64 = rate(&batch);
    let vbs_rate: f64 = rate(&vbs);

    for (label, set) in [
        ("powershell", &ps),
        ("bash", &bash),
        ("batch", &batch),
        ("vbs", &vbs),
    ] {
        for c in set {
            eprintln!("[{label}] {} = {}", c.name, c.recovered);
        }
    }
    eprintln!("---");
    eprintln!("powershell recovery: {:.1}%", ps_rate * 100.0);
    eprintln!("bash recovery:       {:.1}%", bash_rate * 100.0);
    eprintln!("batch recovery:      {:.1}%", batch_rate * 100.0);
    eprintln!("vbs recovery:        {:.1}%", vbs_rate * 100.0);

    assert!(
        ps_rate >= 0.99,
        "powershell corpus recovery regressed: {ps_rate}"
    );
    assert!(
        bash_rate >= 0.99,
        "bash corpus recovery regressed: {bash_rate}"
    );
    assert!(
        batch_rate >= 0.99,
        "batch corpus recovery regressed: {batch_rate}"
    );
    assert!(
        vbs_rate >= 0.99,
        "vbs corpus recovery regressed: {vbs_rate}"
    );
}
