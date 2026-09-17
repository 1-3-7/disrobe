#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Disrobe,
    [string]$GhidraHome = $env:GHIDRA_HOME,
    [string]$GhidraArchive,
    [string]$ToolchainManifest,
    [string]$Corpus,
    [string]$OutDir,
    [string]$Scratch,
    [string]$ResumeRunDirectory,
    [ValidateRange(1048576, 1099511627776)][long]$ScratchSizeLimitBytes = 8GB,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $PSScriptRoot '..\ghidra-harness.psm1') -Force

if (-not $Corpus) { $Corpus = Join-Path $repoRoot 'corpus' }
if (-not $OutDir) { $OutDir = $PSScriptRoot }
if (-not $Scratch) { $Scratch = Join-Path ([System.IO.Path]::GetTempPath()) 'disrobe-ghidra-bench' }
if (-not $ToolchainManifest) { $ToolchainManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'ghidra-toolchain.json' }

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
if (-not $GhidraArchive) {
    throw 'Pass -GhidraArchive <zip> so the installed Ghidra files can be verified.'
}
$analyze = Join-Path $GhidraHome 'support/analyzeHeadless.bat'
if (-not (Test-Path $analyze)) { $analyze = Join-Path $GhidraHome 'support/analyzeHeadless' }
if (-not (Test-Path $analyze)) {
    throw "analyzeHeadless not found under '$GhidraHome/support'."
}

$toolchain = Assert-GhidraHarnessToolchain -ManifestPath $ToolchainManifest -ArchivePath $GhidraArchive -GhidraHome $GhidraHome
$ghidraVersion = $toolchain.version

$metricsScript = Join-Path $PSScriptRoot 'DisrobeMetrics.java'
if (-not (Test-Path $metricsScript)) { throw "DisrobeMetrics.java not found next to this script." }
$javaExecutable = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { $null }
$resumeIdentity = [pscustomobject]@{
    disrobe_sha256 = Get-GhidraHarnessHash -Path $Disrobe
    analyzer_sha256 = Get-GhidraHarnessHash -Path $analyze
    post_script_sha256 = Get-GhidraHarnessHash -Path $metricsScript
    script_sha256 = Get-GhidraHarnessHash -Path $PSCommandPath
    module_sha256 = Get-GhidraHarnessHash -Path (Join-Path $PSScriptRoot '..\ghidra-harness.psm1')
    toolchain = $toolchain.archive.sha256
    java_home = $env:JAVA_HOME
    java_executable_sha256 = if ($javaExecutable -and (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) { Get-GhidraHarnessHash -Path $javaExecutable } else { $null }
    ghidra_headless_maxmem = $env:GHIDRA_HEADLESS_MAXMEM
    ghidra_maxmem = $env:GHIDRA_MAXMEM
    ghidra_headless_java_options = $env:GHIDRA_HEADLESS_JAVA_OPTIONS
    ghidra_java_options = $env:GHIDRA_JAVA_OPTIONS
    schema = 'unpack'
    timeout_seconds = $TimeoutSeconds
    headless_arguments = '-import|-postScript DisrobeMetrics.java|-scriptPath|-deleteProject|-overwrite'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$historicalResultsPresent = (Test-Path (Join-Path $OutDir 'results.json')) -or (Test-Path (Join-Path $OutDir 'results.md'))
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$samples = @(
    [pscustomobject]@{ id = 'upx_hello';            packer = 'UPX';       binary = 'hello (Rust)';        rel = 'native/packers/upx/hello.packed.nrv2b.exe' }
    [pscustomobject]@{ id = 'aspack_clockres';      packer = 'ASPack';    binary = 'Clockres';            rel = 'native/packers/aspack/Clockres.packed.aspack.exe' }
    [pscustomobject]@{ id = 'aspack_accessenum';    packer = 'ASPack';    binary = 'AccessEnum';          rel = 'native/packers/aspack/AccessEnum.packed.aspack.exe' }
    [pscustomobject]@{ id = 'pecompact_clockres';   packer = 'PECompact'; binary = 'Clockres';            rel = 'native/packers/pecompact/Clockres.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'pecompact_accessenum'; packer = 'PECompact'; binary = 'AccessEnum';          rel = 'native/packers/pecompact/AccessEnum.packed.pecompact.exe' }
    [pscustomobject]@{ id = 'kkrunchy_classic';     packer = 'kkrunchy';  binary = 'hello (NASM, classic)'; rel = 'native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe' }
)
$fixtures = @(Assert-GhidraHarnessRoster -Corpus $Corpus -Samples $samples)
if ($ResumeRunDirectory) {
    $runDirectory = [pscustomobject]@{ path = Assert-GhidraHarnessResumeDirectory -OwnerRoot $Scratch -Path $ResumeRunDirectory }
} else {
    $runDirectory = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $Scratch -Name 'ghidra-unpack'
}
$published = $false
try {
$projects = Join-Path $runDirectory.path 'projects'
$exports = Join-Path $runDirectory.path 'export'
$metricsDir = Join-Path $runDirectory.path 'metrics'
$logDir = Join-Path $runDirectory.path 'logs'
foreach ($d in @($projects, $exports, $metricsDir, $logDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
$resumePath = Join-Path $runDirectory.path 'resume.json'
$priorRows = if ($ResumeRunDirectory) { @(Read-GhidraHarnessResumeState -Path $resumePath -Schema unpack -Roster $fixtures -Identity $resumeIdentity) } else { @() }
if (-not $ResumeRunDirectory) { Write-GhidraHarnessResumeState -Path $resumePath -Schema unpack -Roster $fixtures -Identity $resumeIdentity -Rows @() }
if ($ResumeRunDirectory) {
    $seenIds = @{}
    foreach ($prior in $priorRows) {
        if ([string]::IsNullOrWhiteSpace($prior.id) -or $seenIds.ContainsKey($prior.id) -or @($fixtures | Where-Object { $_.sample.id -eq $prior.id }).Count -ne 1) { throw 'resume state contains an unknown or duplicate fixture ID' }
        $seenIds[$prior.id] = $true
        foreach ($path in @($prior.packed_report_path, $prior.unpacked_report_path, $prior.export_directory.path)) {
            if ($path) {
                $fullPath = [System.IO.Path]::GetFullPath($path)
                if (-not $fullPath.StartsWith($runDirectory.path.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) { throw 'resume state contains a path outside the owned run directory' }
            }
        }
    }
}

function Invoke-Headless {
    param([string]$Binary, [string]$Tag)
    $projectDirectory = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $projects -Name $Tag
    $proj = $projectDirectory.path
    $outJson = Join-Path $metricsDir "$([System.IO.Path]::GetFileName($proj)).json"
    $log = Join-Path $logDir "$Tag.log"
    $measurement = Invoke-GhidraHarnessMeasurement -FilePath $analyze -ArgumentList @(
        $proj, $Tag, '-import', $Binary, '-postScript', 'DisrobeMetrics.java', $outJson,
        '-scriptPath', $PSScriptRoot, '-deleteProject', '-overwrite'
    ) -LogPath $log -ReportPath $outJson -Schema unpack -TimeoutSeconds $TimeoutSeconds
    Assert-GhidraHarnessDirectorySize -Path $runDirectory.path -MaximumBytes $ScratchSizeLimitBytes | Out-Null
    return $measurement
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($fixture in $fixtures) {
    $s = $fixture.sample
    $packed = $fixture.path
    $prior = @($priorRows | Where-Object { $_.id -eq $s.id })
    if ($prior.Count -eq 1 -and $prior[0].fixture_sha256 -eq $fixture.sha256 -and $null -ne $prior[0].unpacked -and (Test-Path -LiteralPath $prior[0].packed_report_path -PathType Leaf) -and (Test-Path -LiteralPath $prior[0].unpacked_report_path -PathType Leaf) -and (Get-GhidraHarnessHash -Path $prior[0].packed_report_path) -eq $prior[0].packed_report_sha256 -and (Get-GhidraHarnessHash -Path $prior[0].unpacked_report_path) -eq $prior[0].unpacked_report_sha256) {
        $prior[0].packed = Read-GhidraHarnessReport -Path $prior[0].packed_report_path -Schema unpack
        $prior[0].unpacked = Read-GhidraHarnessReport -Path $prior[0].unpacked_report_path -Schema unpack
        $rows.Add($prior[0])
        Write-Host "[$($s.id)] resume existing measurement"
        continue
    }
    Write-Host "[$($s.id)] export ..."
    $exportDirectory = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $exports -Name $s.id
    $exportDir = $exportDirectory.path
    $exportOk = $true
    $exportError = ''
    $exportOutcome = $null
    $exportOutcome = Invoke-GhidraHarnessProcess -FilePath $Disrobe -ArgumentList @(
        'native', 'export', '--format', 'ghidra', $packed, '--out', $exportDir
    ) -LogPath (Join-Path $logDir "$($s.id).export.log") -TimeoutSeconds $TimeoutSeconds
    Assert-GhidraHarnessDirectorySize -Path $runDirectory.path -MaximumBytes $ScratchSizeLimitBytes | Out-Null
    if ($exportOutcome.exit_code -ne 0) {
        $exportOk = $false
        $exportError = "export exit code $($exportOutcome.exit_code)"
    }

    Write-Host "[$($s.id)] analyze packed ..."
    $packedMetrics = Invoke-Headless -Binary $packed -Tag "$($s.id)_packed"

    $unpackedMetrics = $null
    $rebuilt = $null
    if ($exportOk) {
        try {
            $rebuilt = Get-GhidraHarnessExportArtifact -ExportDirectory $exportDir
        } catch {
            $exportOk = $false
            $exportError = $_.Exception.Message
        }
        if ($null -ne $rebuilt) {
            Write-Host "[$($s.id)] analyze unpacked ..."
            $unpackedMetrics = Invoke-Headless -Binary $rebuilt.path -Tag "$($s.id)_unpacked"
        }
    }

    $row = [pscustomobject]@{
        id = $s.id
        packer = $s.packer
        binary = $s.binary
        fixture = $s.rel
        fixture_sha256 = $fixture.sha256
        export_ok = $exportOk
        export_error = $exportError
        export_directory = $exportDirectory
        export_outcome = $exportOutcome
        rebuilt_sha256 = if ($null -eq $rebuilt) { $null } else { $rebuilt.sha256 }
        packed = $packedMetrics.report
        packed_outcome = $packedMetrics.outcome
        packed_report_sha256 = $packedMetrics.report_sha256
        unpacked = if ($null -eq $unpackedMetrics) { $null } else { $unpackedMetrics.report }
        unpacked_outcome = if ($null -eq $unpackedMetrics) { $null } else { $unpackedMetrics.outcome }
        unpacked_report_sha256 = if ($null -eq $unpackedMetrics) { $null } else { $unpackedMetrics.report_sha256 }
        packed_report_path = $packedMetrics.report_path
        unpacked_report_path = if ($null -eq $unpackedMetrics) { $null } else { $unpackedMetrics.report_path }
    }
    $rows.Add($row)
    Write-GhidraHarnessResumeState -Path $resumePath -Schema unpack -Roster $fixtures -Identity $resumeIdentity -Rows @($rows | ForEach-Object { $_ })
}

$exportCommand = 'disrobe native export --format ghidra <packed> --out <dir>'
$headlessCommand = 'analyzeHeadless <proj> <name> -import <bin> -postScript DisrobeMetrics.java <out.json> -deleteProject -overwrite'
$reports = @($rows | ForEach-Object { $_.packed; if ($null -ne $_.unpacked) { $_.unpacked } })
$provenance = Get-GhidraHarnessProvenance -RepositoryRoot $repoRoot -Disrobe $Disrobe -Analyzer $analyze `
    -ScriptPath $PSCommandPath -PostScriptPath $metricsScript -LogDirectory $logDir -Toolchain $toolchain -Reports $reports `
    -ExportCommand $exportCommand -HeadlessCommand $headlessCommand -TimeoutSeconds $TimeoutSeconds
Assert-GhidraHarnessDirectorySize -Path $runDirectory.path -MaximumBytes $ScratchSizeLimitBytes | Out-Null
$evidenceBytes = (Assert-GhidraHarnessDirectorySize -Path $logDir -MaximumBytes 64MB) + (Assert-GhidraHarnessDirectorySize -Path $metricsDir -MaximumBytes 64MB)
if ($evidenceBytes -gt 64MB) { throw 'raw benchmark evidence exceeds its 67108864 byte ceiling' }
$evidenceDirectories = @($logDir, $metricsDir)
$rawEvidenceRelativeRoot = 'raw-evidence'
$rawEvidenceFiles = @(foreach ($directory in $evidenceDirectories) {
    $name = Split-Path -Leaf $directory
    Get-ChildItem -LiteralPath $directory -Recurse -File | ForEach-Object {
        [pscustomobject]@{ path = "$name/$($_.FullName.Substring($directory.Length + 1).Replace('\', '/'))"; sha256 = Get-GhidraHarnessHash -Path $_.FullName }
    }
})
$rawEvidenceFiles = @($rawEvidenceFiles | Sort-Object path)
foreach ($row in $rows) {
    $row.export_directory = [pscustomobject]@{ run_relative_path = $row.export_directory.path.Substring($runDirectory.path.Length + 1).Replace('\', '/'); cleaned_after_run = $true }
    foreach ($property in @('export_outcome', 'packed_outcome', 'unpacked_outcome')) {
        $outcome = $row.$property
        if ($null -ne $outcome) { $outcome.log = "$rawEvidenceRelativeRoot/logs/$([System.IO.Path]::GetFileName($outcome.log))" }
    }
    foreach ($property in @('packed_report_path', 'unpacked_report_path')) { $row.PSObject.Properties.Remove($property) }
}
$provenance.tools.disrobe.version_outcome.log = "$rawEvidenceRelativeRoot/logs/$([System.IO.Path]::GetFileName($provenance.tools.disrobe.version_outcome.log))"
$provenance.source.tracked_diff.path = "$rawEvidenceRelativeRoot/logs/$([System.IO.Path]::GetFileName($provenance.source.tracked_diff.path))"
$provenance.source.untracked_manifest.path = "$rawEvidenceRelativeRoot/logs/$([System.IO.Path]::GetFileName($provenance.source.untracked_manifest.path))"

$result = [pscustomobject]@{
    schema = 'disrobe.bench.ghidra-unpack/v1'
    measurement_status = 'newly_measured_verified'
    measurement_verification = $provenance.verification
    raw_evidence = [pscustomobject]@{ directory = $rawEvidenceRelativeRoot; size_bytes = $evidenceBytes; files = $rawEvidenceFiles }
    historical_results_present = $historicalResultsPresent
    replaces_historical_results = $false
    ghidra_version = $ghidraVersion
    analyze_headless = 'support/analyzeHeadless'
    provenance = $provenance
    export_command = $exportCommand
    headless_command = $headlessCommand
    samples = $rows
}

function Delta {
    param($before, $after)
    if ($null -eq $after) { return 'n/a' }
    return "$before -> $after"
}

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Headless Ghidra: packed vs disrobe-unpacked')
$md.Add('')
$md.Add("Toolchain: Ghidra $ghidraVersion from archive SHA-256 $($provenance.harness.ghidra_distribution.archive.sha256); JVM $($provenance.tools.ghidra_selected_jvm.version) ($($provenance.tools.ghidra_selected_jvm.vendor)); source $($provenance.source.revision) with identity SHA-256 $($provenance.source.identity_sha256); $($rows.Count) fixtures measured at $($provenance.utc).")
$md.Add('')
$intro = 'Ghidra ' + $ghidraVersion + ', `analyzeHeadless` default analysis. Each fixture is a packed PE from `corpus/native/packers/`. The unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds; the packed column is the original packed file. The post-script attempts every non-thunk, non-external function with four workers and a 45-second timeout per function. Both columns use these same settings. Metrics come from `benches/ghidra-unpack/DisrobeMetrics.java`. Regenerate with `benches/ghidra-unpack/ghidra-unpack-benchmark.ps1 -GhidraHome <dir> -GhidraArchive <zip>`.'
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
$md.Add('These counts describe what Ghidra analyzes in each image. A decompiled function has a completed, nonempty C rendering; that count does not establish source correctness. Per-function failures remain in decompile_attempts in the JSON report. Byte recovery is measured separately in the native-unpack benchmark.')

$written = Publish-GhidraHarnessResults -OutputDirectory $OutDir -Json ($result | ConvertTo-Json -Depth 8) -Markdown (($md -join "`n") + "`n") -EvidenceDirectories $evidenceDirectories
$published = $true
Write-Host "wrote $($written.json)"
Write-Host "wrote $($written.markdown)"
Write-Host "selected by $($written.pointer)"
} catch {
    $failureDirectory = Join-Path $OutDir ('failures/' + [System.IO.Path]::GetFileName($runDirectory.path))
    [System.IO.Directory]::CreateDirectory($failureDirectory) | Out-Null
    foreach ($directory in @($logDir, $metricsDir)) {
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Assert-GhidraHarnessDirectorySize -Path $directory -MaximumBytes 64MB | Out-Null
            Copy-Item -LiteralPath $directory -Destination $failureDirectory -Recurse
        }
    }
    Write-Host "Failure evidence: $failureDirectory"
    throw
} finally {
    if ($published) {
        Remove-GhidraHarnessOutputDirectory -Path $runDirectory.path -OwnerRoot $Scratch
    } else {
        Write-Host "Retained incomplete run: $($runDirectory.path)"
    }
}
