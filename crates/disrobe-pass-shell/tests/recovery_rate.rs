#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_shell::{
    BatchCfg, BatchReport, ReverseReport, VbsReport, deobfuscate_vbs, resolve_cfg, reverse_batch,
    reverse_chameleon, reverse_compress, reverse_encoding, reverse_invoke_stealth, reverse_string,
    reverse_token,
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

fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn produced(produced: &str, cleartext: &str) -> bool {
    let still_encoded: bool = {
        let lower: String = produced.to_ascii_lowercase();
        lower.contains("frombase64string") || lower.contains("convert]::frombase64")
    };
    !still_encoded && norm(produced).contains(&norm(cleartext))
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
        recovered: produced(&token_then_string.output, "Write-Host")
            && produced(&token_then_string.output, "hello world"),
    });

    let string: ReverseReport =
        reverse_string(&read("powershell/invoke-obfuscation/string/hello.ps1"));
    cases.push(Case {
        name: "io-string",
        recovered: produced(&string.output, "Write-Host"),
    });

    let enc: ReverseReport =
        reverse_encoding(&read("powershell/invoke-obfuscation/encoding/hello.ps1"))
            .expect("decode encoding");
    cases.push(Case {
        name: "io-encoding",
        recovered: produced(&enc.output, "Write-Host \"hello world\""),
    });

    let comp: ReverseReport =
        reverse_compress(&read("powershell/invoke-obfuscation/compress/hello.ps1"))
            .expect("inflate compress");
    cases.push(Case {
        name: "io-compress",
        recovered: produced(&comp.output, "Write-Host \"hello world\""),
    });

    let cham: String = reverse_chameleon(&read("powershell/chameleon/hello.ps1")).output;
    cases.push(Case {
        name: "chameleon",
        recovered: produced(&cham, "Write-Host \"hello world\""),
    });

    let stealth: String =
        reverse_invoke_stealth(&read("powershell/invoke-stealth/hello.ps1")).output;
    cases.push(Case {
        name: "invoke-stealth",
        recovered: produced(&stealth, "Write-Host \"hello world\""),
    });

    let key: u32 = 0x5A;
    let encoded: String = "Get-Process"
        .bytes()
        .map(|b: u8| (u32::from(b) ^ key).to_string())
        .collect::<Vec<String>>()
        .join(",");
    let bxor_src: String = format!("({encoded} | %{{[char]($_ -bxor {key})}}) -join ''");
    let bxor: ReverseReport = reverse_token(&bxor_src);
    cases.push(Case {
        name: "bxor-pipeline",
        recovered: produced(&bxor.output, "Get-Process"),
    });

    let comspec: ReverseReport = reverse_token("&( $env:ComSpec[4,15,25]-Join'')( 'x' )");
    cases.push(Case {
        name: "iex-indirection",
        recovered: produced(&comspec.output, "Invoke-Expression"),
    });

    let mk_plain: &str = "Invoke-Mimikatz";
    let mk_key: [u32; 3] = [0x11, 0x37, 0x5A];
    let mk_encoded: String = mk_plain
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| (u32::from(b) ^ mk_key[i % mk_key.len()]).to_string())
        .collect::<Vec<String>>()
        .join(",");
    let mk_src: String = format!(
        "$k=@(17,55,90); ({mk_encoded} | ForEach-Object {{[char]($_ -bxor $k[$i++ % $k.Count])}}) -join ''"
    );
    let multikey: ReverseReport = reverse_token(&mk_src);
    cases.push(Case {
        name: "multikey-xor-pipeline",
        recovered: produced(&multikey.output, mk_plain),
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
        recovered: produced(&obf.output, "echo") && produced(&obf.output, "hello world"),
    });

    let comp: BashfuscatorReport = reverse_bashfuscator(
        BashfuscatorLevel::Compress,
        &read("bash/bashfuscator/compress/hello.sh"),
    )
    .expect("compress");
    cases.push(Case {
        name: "bf-compress",
        recovered: produced(&comp.output, "echo") && produced(&comp.output, "hello world"),
    });

    cases
}

fn batch_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();

    let call: BatchReport = reverse_batch(&read("batch/call/hello.bat"));
    cases.push(Case {
        name: "batch-call-indirection",
        recovered: call.set_substitutions >= 1 && produced(&call.output, "echo hello world"),
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
        recovered: chr.chr_substitutions >= 8 && produced(&chr.output, "WScript.Echo"),
    });

    cases
}

#[test]
fn oracle_rejects_still_encoded_and_passthrough() {
    assert!(
        produced("Write-Host \"hello world\"", "Write-Host \"hello world\""),
        "oracle must accept exact decoded plaintext"
    );
    assert!(
        !produced(
            "iex([Convert]::FromBase64String('V3JpdGUtSG9zdA=='))",
            "Write-Host"
        ),
        "oracle must reject still-encoded FromBase64String output"
    );
    assert!(
        !produced("$obf = 'ZWNobyBoaQ=='", "echo hi"),
        "oracle must reject base64-only passthrough that lacks the plaintext"
    );
    assert!(
        produced("ECHO   HELLO    WORLD", "echo hello world"),
        "oracle normalises whitespace and case for the plaintext match"
    );
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

    let all: Vec<&Case> = ps
        .iter()
        .chain(bash.iter())
        .chain(batch.iter())
        .chain(vbs.iter())
        .collect();
    let total: usize = all.len();
    let hits: usize = all.iter().filter(|c: &&&Case| c.recovered).count();
    let overall: f64 = hits as f64 / total as f64;

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
    eprintln!(
        "powershell recovery: {:.1}% ({}/{})",
        ps_rate * 100.0,
        ps.iter().filter(|c: &&Case| c.recovered).count(),
        ps.len()
    );
    eprintln!(
        "bash recovery:       {:.1}% ({}/{})",
        bash_rate * 100.0,
        bash.iter().filter(|c: &&Case| c.recovered).count(),
        bash.len()
    );
    eprintln!(
        "batch recovery:      {:.1}% ({}/{})",
        batch_rate * 100.0,
        batch.iter().filter(|c: &&Case| c.recovered).count(),
        batch.len()
    );
    eprintln!(
        "vbs recovery:        {:.1}% ({}/{})",
        vbs_rate * 100.0,
        vbs.iter().filter(|c: &&Case| c.recovered).count(),
        vbs.len()
    );
    eprintln!(
        "OVERALL recovery:    {:.1}% ({hits}/{total})",
        overall * 100.0
    );

    assert_eq!(
        hits,
        total,
        "every measured case must recover the produced plaintext; {} of {} failed",
        total - hits,
        total
    );
}
