#requires -Version 5.1
<#
.SYNOPSIS
Measures the code Ghidra recovers under static analysis from a packed PE versus the
loadable PE that disrobe rebuilds from it.

.DESCRIPTION
For each committed packed fixture under corpus/native/packers/ the harness:
  1. runs `disrobe native export --format ghidra` to rebuild a loadable PE,
  2. runs `analyzeHeadless` (static analysis, no sample execution) on the packed
     original and on the rebuilt PE with the GhidraReport post-script, and
  3. records functions, instructions, defined bytes, and strings for both, then the delta.
Output is written as results.json and results.md under -OutDir.

.PARAMETER Disrobe
Path to the disrobe executable. Defaults to target/release/disrobe(.exe).

.PARAMETER GhidraHome
Ghidra install root containing support/analyzeHeadless(.bat). Falls back to GHIDRA_HOME.

.PARAMETER Corpus
Repository corpus directory. Defaults to corpus/ at the repository root.

.PARAMETER OutDir
Where to write results.json and results.md. Defaults to this script's directory.

.PARAMETER Scratch
Working directory for Ghidra projects and exported PEs. Defaults to a temp dir.
#>
[CmdletBinding()]
param(
    [string]$Disrobe,
    [string]$GhidraHome = $env:GHIDRA_HOME,
    [string]$Corpus,
    [string]$OutDir,
    [string]$Scratch
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $Corpus) { $Corpus = Join-Path $repoRoot 'corpus' }
if (-not $OutDir) { $OutDir = $PSScriptRoot }
if (-not $Scratch) { $Scratch = Join-Path ([System.IO.Path]::GetTempPath()) 'disrobe-ghidra-cleaner' }

if (-not $Disrobe) {
    $cand = Join-Path $repoRoot 'target/release/disrobe.exe'
    if (-not (Test-Path $cand)) { $cand = Join-Path $repoRoot 'target/release/disrobe' }
    $Disrobe = $cand
}
if (-not (Test-Path $Disrobe)) {
    throw "disrobe executable not found at '$Disrobe'. Build it with: cargo build --release -p disrobe-cli"
}

if (-not $GhidraHome) {
    throw "Ghidra not located. Pass -GhidraHome <dir> or set GHIDRA_HOME."
}
$analyze = Join-Path $GhidraHome 'support/analyzeHeadless.bat'
if (-not (Test-Path $analyze)) { $analyze = Join-Path $GhidraHome 'support/analyzeHeadless' }
if (-not (Test-Path $analyze)) {
    throw "analyzeHeadless not found under '$GhidraHome/support'."
}

$ghidraVersion = 'unknown'
$appProps = Join-Path $GhidraHome 'Ghidra/application.properties'
if (Test-Path $appProps) {
    $line = Select-String -Path $appProps -Pattern '^application\.version=' | Select-Object -First 1
    if ($line) { $ghidraVersion = ($line.Line -split '=', 2)[1].Trim() }
}

$reportScript = Join-Path $PSScriptRoot 'GhidraReport.java'
if (-not (Test-Path $reportScript)) { throw "GhidraReport.java not found next to this script." }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$projects = Join-Path $Scratch 'projects'
$exports = Join-Path $Scratch 'export'
$reportsDir = Join-Path $Scratch 'reports'
$logDir = Join-Path $Scratch 'logs'
foreach ($d in @($projects, $exports, $reportsDir, $logDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

$samples = @(
    [pscustomobject]@{ id = 'upx_hello';            packer = 'UPX';       binary = 'hello (Rust x64)';      rel = 'native/packers/upx/hello.packed.nrv2b.exe' }
    [pscustomobject]@{ id = 'aspack_clockres';      packer = 'ASPack';    binary = 'Clockres';             rel = 'native/packers/aspack/Clockres.packed.aspack.exe' }
    [pscustomobject]@{ id = 'aspack_accessenum';    packer = 'ASPack';    binary = 'AccessEnum';           rel = 'native/packers/aspack/AccessEnum.packed.aspack.exe' }
    [pscustomobject]@{ id = 'pecompact_clockres';   packer = 'PECompact'; binary = 'Clockres';             rel = 'native/packers/pecompact/Clockres.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'pecompact_accessenum'; packer = 'PECompact'; binary = 'AccessEnum';           rel = 'native/packers/pecompact/AccessEnum.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'mew_clockres';         packer = 'MEW';       binary = 'Clockres';             rel = 'native/packers/mew/Clockres.packed.mew.exe' }
    [pscustomobject]@{ id = 'mew_accessenum';       packer = 'MEW';       binary = 'AccessEnum';           rel = 'native/packers/mew/AccessEnum.packed.mew.exe' }
    [pscustomobject]@{ id = 'mew_autologon';        packer = 'MEW';       binary = 'Autologon';            rel = 'native/packers/mew/Autologon.packed.mew.exe' }
    [pscustomobject]@{ id = 'kkrunchy_classic';     packer = 'kkrunchy';  binary = 'hello (NASM PE32)';     rel = 'native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe' }
)

function Invoke-Headless {
    param([string]$Binary, [string]$Tag)
    $proj = Join-Path $projects $Tag
    if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }
    New-Item -ItemType Directory -Force -Path $proj | Out-Null
    $outJson = Join-Path $reportsDir "$Tag.json"
    $log = Join-Path $logDir "$Tag.log"
    if (Test-Path $outJson) { Remove-Item -Force $outJson }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $analyze $proj $Tag -import $Binary -postScript GhidraReport.java $outJson `
            -scriptPath $PSScriptRoot -deleteProject -overwrite 2>&1 | Out-File -FilePath $log -Encoding utf8
    } finally {
        $ErrorActionPreference = $prev
    }
    if (-not (Test-Path $outJson)) {
        throw "report not produced for '$Tag' (see $log)"
    }
    return Get-Content -Raw $outJson | ConvertFrom-Json
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($s in $samples) {
    $packed = Join-Path $Corpus $s.rel
    if (-not (Test-Path $packed)) {
        Write-Warning "skipping $($s.id): fixture not present at $packed"
        continue
    }
    Write-Host "[$($s.id)] export ..."
    $exportDir = Join-Path $exports $s.id
    $exportOk = $true
    $exportError = ''
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Disrobe native export --format ghidra $packed --out $exportDir 2>&1 |
            Out-File -FilePath (Join-Path $logDir "$($s.id).export.log") -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            $exportOk = $false
            $exportError = "export exit code $LASTEXITCODE"
        }
    } catch {
        $exportOk = $false
        $exportError = $_.Exception.Message
    } finally {
        $ErrorActionPreference = $prevEap
    }

    Write-Host "[$($s.id)] analyze packed ..."
    $packedReport = Invoke-Headless -Binary $packed -Tag "$($s.id)_packed"

    $unpackedReport = $null
    if ($exportOk) {
        $rebuilt = Get-ChildItem -Path $exportDir -Filter '*.unpacked.exe' | Select-Object -First 1
        if ($rebuilt) {
            Write-Host "[$($s.id)] analyze unpacked ..."
            $unpackedReport = Invoke-Headless -Binary $rebuilt.FullName -Tag "$($s.id)_unpacked"
        } else {
            $exportOk = $false
            $exportError = 'no *.unpacked.exe emitted'
        }
    }

    $rows.Add([pscustomobject]@{
        id = $s.id
        packer = $s.packer
        binary = $s.binary
        fixture = $s.rel
        export_ok = $exportOk
        export_error = $exportError
        packed = $packedReport
        unpacked = $unpackedReport
    })
}

$disrobeVersion = 'unknown'
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $verOut = & $Disrobe --version 2>$null
    if ($verOut) { $disrobeVersion = ($verOut | Select-Object -First 1).Trim() }
} catch {
    $disrobeVersion = 'unknown'
} finally {
    $ErrorActionPreference = $prevEap
}

$result = [pscustomobject]@{
    schema = 'disrobe.bench.ghidra-cleaner-input/v1'
    ghidra_version = $ghidraVersion
    analysis = 'analyzeHeadless static analysis only (the sample is never executed)'
    disrobe_version = $disrobeVersion
    export_command = 'disrobe native export --format ghidra <packed> --out <dir>'
    headless_command = 'analyzeHeadless <proj> <name> -import <bin> -postScript GhidraReport.java <out.json> -deleteProject -overwrite'
    samples = $rows
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$jsonPath = Join-Path $OutDir 'results.json'
[System.IO.File]::WriteAllText($jsonPath, ($result | ConvertTo-Json -Depth 8), $utf8NoBom)
Write-Host "wrote $jsonPath"

function Delta {
    param($before, $after)
    if ($null -eq $after) { return 'n/a' }
    $sign = ''
    $d = [int64]$after - [int64]$before
    if ($d -gt 0) { $sign = '+' }
    return "$before -> $after ($sign$d)"
}

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# disrobe feeds Ghidra cleaner input')
$md.Add('')
$intro = 'Ghidra ' + $ghidraVersion + ', `analyzeHeadless` default analysis. Each fixture is a real benign packed PE from `corpus/native/packers/` (Sysinternals utilities and small hello programs; see `corpus/native/packers/MANIFEST.toml` for provenance and SHA-256). `analyzeHeadless` performs static analysis only and never executes the sample. The packed column is the original packed file; the unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds from it. Metrics come from the committed `GhidraReport.java` post-script. Regenerate with `benches/ghidra-cleaner-input/run.ps1 -GhidraHome <dir>`.'
$md.Add($intro)
$md.Add('')
$md.Add('| packer | binary | functions (packed -> unpacked) | instructions (packed -> unpacked) | defined bytes (packed -> unpacked) | strings (packed -> unpacked) |')
$md.Add('|---|---|---|---|---|---|')
foreach ($r in $rows) {
    if (-not $r.export_ok -or $null -eq $r.unpacked) {
        $p = $r.packed
        $md.Add("| $($r.packer) | $($r.binary) | packed $($p.functions); export n/a ($($r.export_error)) | packed $($p.instructions) | packed $($p.defined_bytes) | packed $($p.defined_strings) |")
        continue
    }
    $p = $r.packed; $u = $r.unpacked
    $md.Add("| $($r.packer) | $($r.binary) | $(Delta $p.functions $u.functions) | $(Delta $p.instructions $u.instructions) | $(Delta $p.defined_bytes $u.defined_bytes) | $(Delta $p.defined_strings $u.defined_strings) |")
}
$md.Add('')
$md.Add('Reproduce:')
$md.Add('')
$md.Add('```')
$md.Add($result.export_command)
$md.Add($result.headless_command)
$md.Add('```')

$mdPath = Join-Path $OutDir 'results.md'
[System.IO.File]::WriteAllText($mdPath, (($md -join "`n") + "`n"), $utf8NoBom)
Write-Host "wrote $mdPath"
