param(
    [string]$OutDir = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'corpus/python/obfuscators')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$OutDir = (Resolve-Path -Path (Split-Path -Parent $OutDir)).Path | Join-Path -ChildPath (Split-Path -Leaf $OutDir)

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

Write-Host "[bake] repo=$RepoRoot out=$OutDir"
Push-Location $RepoRoot
try {
    & cargo run --quiet --example bake_obfuscators -- $OutDir
    if ($LASTEXITCODE -ne 0) {
        throw "bake_obfuscators exited with $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$count = (Get-ChildItem -Path $OutDir -Recurse -File).Count
$bytes = (Get-ChildItem -Path $OutDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host "[bake] fixtures=$count bytes=$bytes"
