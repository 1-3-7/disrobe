#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $env:CARGO_INCREMENTAL = '0'
    cargo run -p xtask -- evidence @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output 'evidence rendered into evidence/results/; read evidence/results/EVIDENCE.md'
} finally {
    Pop-Location
}
