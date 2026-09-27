#!/usr/bin/env pwsh
# Regenerates the committed .wasm fixtures: the two assembled from .wat by wasm-tools (on PATH),
# and the four built by clang 22.1.6 and rustc 1.96.1 that records.toml pins.
# Run from anywhere: pwsh crates/disrobe-pass-wasm-deob/tests/fixtures/regen.ps1
param(
    [string]$Clang = "clang",
    [string]$Rustc = "rustc",
    [switch]$SelectOnly
)

$ErrorActionPreference = "Stop"
[string]$dir = $PSScriptRoot
if (-not $SelectOnly) {
    foreach ($stem in @("arith4", "wasm_name_obf_clean")) {
        [string]$wat = Join-Path $dir "$stem.wat"
        [string]$wasm = Join-Path $dir "$stem.wasm"
        & wasm-tools parse $wat -o $wasm
        Write-Host "regenerated $wasm"
    }
}

[object[]]$selectFixtures = @(
    @{ Source = "cff_cond_select.clean.c"; Output = "cff_cond_select.clean.wasm"; Optimize = "-O3"; Sha256 = "A5D20EF31BC3984584FDEC9658AFD4DAA1EBAF9AF053937F18DEC0E691BD2568" },
    @{ Source = "cff_cond_select.c"; Output = "cff_cond_select.obf.wasm"; Optimize = "-O0"; Sha256 = "9AA3FC55F1207580FD29EB079D010A4D36EF7240702694F40E74F82D84DB7208" },
    @{ Source = "cff_cond_select.mutant.c"; Output = "cff_cond_select.mutant.wasm"; Optimize = "-O0"; Sha256 = "589E82D358FA7A4D971DC8AA10CC6381F02B782127B97B815F5F3F29227B3232" }
)

& $Clang --version | Select-Object -First 1
foreach ($fixture in $selectFixtures) {
    [string]$source = Join-Path $dir $fixture.Source
    [string]$output = Join-Path $dir $fixture.Output
    & $Clang "--target=wasm32" $fixture.Optimize "-nostdlib" "-Wl,--no-entry" "-Wl,--strip-all" "-Wl,--no-stack-first" -o $output $source
    if ($LASTEXITCODE -ne 0) {
        throw "clang failed to regenerate $($fixture.Output)"
    }
    [string]$actual = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    if ($actual -ne $fixture.Sha256) {
        throw "unexpected SHA-256 for $($fixture.Output): $actual"
    }
    Write-Host "regenerated $output"
}

# rustc output is not byte-stable across releases, so another rustc fails the hash check.
# wasm-ld writes the output file name into the module name, so the fixture links as loc.O0.wasm.
[object[]]$rustcFixtures = @(
    @{ Source = "cff_rustc_temp_state.rs"; LinkedAs = "loc.O0.wasm"; Output = "cff_rustc_temp_state.obf.wasm"; Optimize = "0"; Sha256 = "7C8DDBCA3DE23D75858E8153B1759A4FBF157F3A201E1E253CF9229069EA7239" }
)

& $Rustc --version
foreach ($fixture in $rustcFixtures) {
    [string]$source = Join-Path $dir $fixture.Source
    [string]$linked = Join-Path $dir $fixture.LinkedAs
    [string]$output = Join-Path $dir $fixture.Output
    & $Rustc "--target" "wasm32-unknown-unknown" "-C" "opt-level=$($fixture.Optimize)" "-C" "panic=abort" "--crate-type" "cdylib" "-o" $linked $source
    if ($LASTEXITCODE -ne 0) {
        throw "rustc failed to regenerate $($fixture.Output)"
    }
    Move-Item -LiteralPath $linked -Destination $output -Force
    [string]$actual = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    if ($actual -ne $fixture.Sha256) {
        throw "unexpected SHA-256 for $($fixture.Output): $actual"
    }
    Write-Host "regenerated $output"
}
