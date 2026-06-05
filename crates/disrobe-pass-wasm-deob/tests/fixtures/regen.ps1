#!/usr/bin/env pwsh
# Regenerates the .wasm fixtures from their .wat sources using wasm-tools (on PATH).
# Run from anywhere: pwsh crates/disrobe-pass-wasm-deob/tests/fixtures/regen.ps1
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
Get-ChildItem -Path $dir -Filter "*.wat" | ForEach-Object {
    $wat = $_.FullName
    $wasm = [System.IO.Path]::ChangeExtension($wat, ".wasm")
    & wasm-tools parse $wat -o $wasm
    Write-Host "regenerated $wasm"
}
