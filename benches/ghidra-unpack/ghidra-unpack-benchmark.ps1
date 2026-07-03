#requires -Version 5.1
<#
.SYNOPSIS
Measures what a headless Ghidra analysis recovers from a packed binary versus the
loadable PE that `disrobe native export` rebuilds from it.

.DESCRIPTION
For each committed packed fixture the harness:
  1. runs `disrobe native export --format ghidra` to rebuild a loadable PE,
  2. runs `analyzeHeadless` on the packed original and on the rebuilt PE with the
     DisrobeMetrics post-script, and
  3. records functions, instructions, decompiled functions, defined strings,
     resolved imports, and executable bytes for both.
Output is written as results.json and results.md under -OutDir.

.PARAMETER Disrobe
Path to the disrobe executable. Defaults to target/release/disrobe(.exe).

.PARAMETER GhidraHome
Ghidra install root containing support/analyzeHeadless(.bat). Falls back to the
GHIDRA_HOME environment variable.

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
if (-not $Scratch) { $Scratch = Join-Path ([System.IO.Path]::GetTempPath()) 'disrobe-ghidra-bench' }

if (-not $Disrobe) {
    $cand = Join-Path $repoRoot 'target/release/disrobe.exe'
    if (-not (Test-Path $cand)) { $cand = Join-Path $repoRoot 'target/release/disrobe' }
    $Disrobe = $cand
}
if (-not (Test-Path $Disrobe)) {
    throw "disrobe executable not found at '$Disrobe'. Build it with: cargo build --release -p disrobe-cli"
}

if (-not $GhidraHome) {
    throw "Ghidra not located. Pass -GhidraHome <dir> or set GHIDRA_HOME (install with: disrobe install-deps ghidra)."
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

$metricsScript = Join-Path $PSScriptRoot 'DisrobeMetrics.java'
if (-not (Test-Path $metricsScript)) { throw "DisrobeMetrics.java not found next to this script." }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$projects = Join-Path $Scratch 'projects'
$exports = Join-Path $Scratch 'export'
$metricsDir = Join-Path $Scratch 'metrics'
$logDir = Join-Path $Scratch 'logs'
foreach ($d in @($projects, $exports, $metricsDir, $logDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

$samples = @(
    [pscustomobject]@{ id = 'upx_hello';            packer = 'UPX';       binary = 'hello (Rust)';        rel = 'native/packers/upx/hello.packed.nrv2b.exe' }
    [pscustomobject]@{ id = 'aspack_clockres';      packer = 'ASPack';    binary = 'Clockres';            rel = 'native/packers/aspack/Clockres.packed.aspack.exe' }
    [pscustomobject]@{ id = 'aspack_accessenum';    packer = 'ASPack';    binary = 'AccessEnum';          rel = 'native/packers/aspack/AccessEnum.packed.aspack.exe' }
    [pscustomobject]@{ id = 'pecompact_clockres';   packer = 'PECompact'; binary = 'Clockres';            rel = 'native/packers/pecompact/Clockres.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'pecompact_accessenum'; packer = 'PECompact'; binary = 'AccessEnum';          rel = 'native/packers/pecompact/AccessEnum.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'kkrunchy_classic';     packer = 'kkrunchy';  binary = 'hello (NASM, classic)'; rel = 'native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe' }
)

function Invoke-Headless {
    param([string]$Binary, [string]$Tag)
    $proj = Join-Path $projects $Tag
    if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }
    New-Item -ItemType Directory -Force -Path $proj | Out-Null
    $outJson = Join-Path $metricsDir "$Tag.json"
    $log = Join-Path $logDir "$Tag.log"
    if (Test-Path $outJson) { Remove-Item -Force $outJson }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $analyze $proj $Tag -import $Binary -postScript DisrobeMetrics.java $outJson `
            -scriptPath $PSScriptRoot -deleteProject -overwrite 2>&1 | Out-File -FilePath $log -Encoding utf8
    } finally {
        $ErrorActionPreference = $prev
    }
    if (-not (Test-Path $outJson)) {
        throw "metrics not produced for '$Tag' (see $log)"
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
    $packedMetrics = Invoke-Headless -Binary $packed -Tag "$($s.id)_packed"

    $unpackedMetrics = $null
    if ($exportOk) {
        $rebuilt = Get-ChildItem -Path $exportDir -Filter '*.unpacked.exe' | Select-Object -First 1
        if ($rebuilt) {
            Write-Host "[$($s.id)] analyze unpacked ..."
            $unpackedMetrics = Invoke-Headless -Binary $rebuilt.FullName -Tag "$($s.id)_unpacked"
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
        packed = $packedMetrics
        unpacked = $unpackedMetrics
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
    schema = 'disrobe.bench.ghidra-unpack/v1'
    ghidra_version = $ghidraVersion
    analyze_headless = 'support/analyzeHeadless'
    disrobe_version = $disrobeVersion
    export_command = 'disrobe native export --format ghidra <packed> --out <dir>'
    headless_command = 'analyzeHeadless <proj> <name> -import <bin> -postScript DisrobeMetrics.java <out.json> -deleteProject -overwrite'
    samples = $rows
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$jsonPath = Join-Path $OutDir 'results.json'
[System.IO.File]::WriteAllText($jsonPath, ($result | ConvertTo-Json -Depth 8), $utf8NoBom)
Write-Host "wrote $jsonPath"

function Delta {
    param($before, $after)
    if ($null -eq $after) { return 'n/a' }
    return "$before -> $after"
}

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Headless Ghidra: packed vs disrobe-unpacked')
$md.Add('')
$intro = 'Ghidra ' + $ghidraVersion + ', `analyzeHeadless` default analysis. Each fixture is a real packed PE from `corpus/native/packers/`. The unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds; the packed column is the original packed file. Metrics come from the committed `benches/ghidra-unpack/DisrobeMetrics.java` post-script. Regenerate with `benches/ghidra-unpack/ghidra-unpack-benchmark.ps1`.'
$md.Add($intro)
$md.Add('')
$md.Add('| packer | binary | functions | instructions | decompiled | strings | imports | exec bytes |')
$md.Add('|---|---|---|---|---|---|---|---|')
foreach ($r in $rows) {
    if (-not $r.export_ok -or $null -eq $r.unpacked) {
        $md.Add("| $($r.packer) | $($r.binary) | packed: $($r.packed.functions); export n/a ($($r.export_error)) | | | | | |")
        continue
    }
    $p = $r.packed; $u = $r.unpacked
    $md.Add("| $($r.packer) | $($r.binary) | $(Delta $p.functions $u.functions) | $(Delta $p.instructions $u.instructions) | $(Delta $p.decompiled_ok $u.decompiled_ok) | $(Delta $p.defined_strings $u.defined_strings) | $(Delta $p.resolved_imports $u.resolved_imports) | $(Delta $p.executable_bytes $u.executable_bytes) |")
}
$md.Add('')
$md.Add('Commands:')
$md.Add('')
$md.Add('```')
$md.Add($result.export_command)
$md.Add($result.headless_command)
$md.Add('```')
$md.Add('')
$md.Add('Notes: UPX recovers the decompressed code in place at the packed section RVA, so Ghidra disassembles the full program. The structural-carve packers (ASPack/PECompact via the phase-1 CLI path) append carved section bytes that Ghidra does not map at the load address, so their delta is small; kkrunchy classic recovery is partial. The figures are the raw post-analysis counts, not rounded.')

$mdPath = Join-Path $OutDir 'results.md'
[System.IO.File]::WriteAllText($mdPath, (($md -join "`n") + "`n"), $utf8NoBom)
Write-Host "wrote $mdPath"
