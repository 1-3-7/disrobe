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
if (-not $Scratch) { $Scratch = Join-Path ([System.IO.Path]::GetTempPath()) 'disrobe-ghidra-cleaner' }
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
    throw "Ghidra not located. Pass -GhidraHome <dir> or set GHIDRA_HOME."
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

$reportScript = Join-Path $PSScriptRoot 'GhidraReport.java'
if (-not (Test-Path $reportScript)) { throw "GhidraReport.java not found next to this script." }
$javaExecutable = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { $null }
$resumeIdentity = [pscustomobject]@{
    disrobe_sha256 = Get-GhidraHarnessHash -Path $Disrobe
    analyzer_sha256 = Get-GhidraHarnessHash -Path $analyze
    post_script_sha256 = Get-GhidraHarnessHash -Path $reportScript
    script_sha256 = Get-GhidraHarnessHash -Path $PSCommandPath
    module_sha256 = Get-GhidraHarnessHash -Path (Join-Path $PSScriptRoot '..\ghidra-harness.psm1')
    toolchain = $toolchain.archive.sha256
    java_home = $env:JAVA_HOME
    java_executable_sha256 = if ($javaExecutable -and (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) { Get-GhidraHarnessHash -Path $javaExecutable } else { $null }
    ghidra_headless_maxmem = $env:GHIDRA_HEADLESS_MAXMEM
    ghidra_maxmem = $env:GHIDRA_MAXMEM
    ghidra_headless_java_options = $env:GHIDRA_HEADLESS_JAVA_OPTIONS
    ghidra_java_options = $env:GHIDRA_JAVA_OPTIONS
    schema = 'cleaner'
    timeout_seconds = $TimeoutSeconds
    headless_arguments = '-import|-postScript GhidraReport.java|-scriptPath|-deleteProject|-overwrite'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$historicalResultsPresent = (Test-Path (Join-Path $OutDir 'results.json')) -or (Test-Path (Join-Path $OutDir 'results.md'))
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
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
$fixtures = @(Assert-GhidraHarnessRoster -Corpus $Corpus -Samples $samples)
if ($ResumeRunDirectory) {
    $runDirectory = [pscustomobject]@{ path = Assert-GhidraHarnessResumeDirectory -OwnerRoot $Scratch -Path $ResumeRunDirectory }
} else {
    $runDirectory = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $Scratch -Name 'ghidra-cleaner-input'
}
$published = $false
try {
$projects = Join-Path $runDirectory.path 'projects'
$exports = Join-Path $runDirectory.path 'export'
$reportsDir = Join-Path $runDirectory.path 'reports'
$logDir = Join-Path $runDirectory.path 'logs'
foreach ($d in @($projects, $exports, $reportsDir, $logDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
$resumePath = Join-Path $runDirectory.path 'resume.json'
$priorRows = if ($ResumeRunDirectory) { @(Read-GhidraHarnessResumeState -Path $resumePath -Schema cleaner -Roster $fixtures -Identity $resumeIdentity) } else { @() }
if (-not $ResumeRunDirectory) { Write-GhidraHarnessResumeState -Path $resumePath -Schema cleaner -Roster $fixtures -Identity $resumeIdentity -Rows @() }
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
    $outJson = Join-Path $reportsDir "$([System.IO.Path]::GetFileName($proj)).json"
    $log = Join-Path $logDir "$Tag.log"
    $measurement = Invoke-GhidraHarnessMeasurement -FilePath $analyze -ArgumentList @(
        $proj, $Tag, '-import', $Binary, '-postScript', 'GhidraReport.java', $outJson,
        '-scriptPath', $PSScriptRoot, '-deleteProject', '-overwrite'
    ) -LogPath $log -ReportPath $outJson -Schema cleaner -TimeoutSeconds $TimeoutSeconds
    Assert-GhidraHarnessDirectorySize -Path $runDirectory.path -MaximumBytes $ScratchSizeLimitBytes | Out-Null
    return $measurement
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($fixture in $fixtures) {
    $s = $fixture.sample
    $packed = $fixture.path
    $prior = @($priorRows | Where-Object { $_.id -eq $s.id })
    if ($prior.Count -eq 1 -and $prior[0].fixture_sha256 -eq $fixture.sha256 -and $null -ne $prior[0].unpacked -and (Test-Path -LiteralPath $prior[0].packed_report_path -PathType Leaf) -and (Test-Path -LiteralPath $prior[0].unpacked_report_path -PathType Leaf) -and (Get-GhidraHarnessHash -Path $prior[0].packed_report_path) -eq $prior[0].packed_report_sha256 -and (Get-GhidraHarnessHash -Path $prior[0].unpacked_report_path) -eq $prior[0].unpacked_report_sha256) {
        $prior[0].packed = Read-GhidraHarnessReport -Path $prior[0].packed_report_path -Schema cleaner
        $prior[0].unpacked = Read-GhidraHarnessReport -Path $prior[0].unpacked_report_path -Schema cleaner
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
    $packedReport = Invoke-Headless -Binary $packed -Tag "$($s.id)_packed"

    $unpackedReport = $null
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
            $unpackedReport = Invoke-Headless -Binary $rebuilt.path -Tag "$($s.id)_unpacked"
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
        packed = $packedReport.report
        packed_outcome = $packedReport.outcome
        packed_report_sha256 = $packedReport.report_sha256
        unpacked = if ($null -eq $unpackedReport) { $null } else { $unpackedReport.report }
        unpacked_outcome = if ($null -eq $unpackedReport) { $null } else { $unpackedReport.outcome }
        unpacked_report_sha256 = if ($null -eq $unpackedReport) { $null } else { $unpackedReport.report_sha256 }
        packed_report_path = $packedReport.report_path
        unpacked_report_path = if ($null -eq $unpackedReport) { $null } else { $unpackedReport.report_path }
    }
    $rows.Add($row)
    Write-GhidraHarnessResumeState -Path $resumePath -Schema cleaner -Roster $fixtures -Identity $resumeIdentity -Rows @($rows | ForEach-Object { $_ })
}

$exportCommand = 'disrobe native export --format ghidra <packed> --out <dir>'
$headlessCommand = 'analyzeHeadless <proj> <name> -import <bin> -postScript GhidraReport.java <out.json> -deleteProject -overwrite'
$reports = @($rows | ForEach-Object { $_.packed; if ($null -ne $_.unpacked) { $_.unpacked } })
$provenance = Get-GhidraHarnessProvenance -RepositoryRoot $repoRoot -Disrobe $Disrobe -Analyzer $analyze `
    -ScriptPath $PSCommandPath -PostScriptPath $reportScript -LogDirectory $logDir -Toolchain $toolchain -Reports $reports `
    -ExportCommand $exportCommand -HeadlessCommand $headlessCommand -TimeoutSeconds $TimeoutSeconds
Assert-GhidraHarnessDirectorySize -Path $runDirectory.path -MaximumBytes $ScratchSizeLimitBytes | Out-Null
$evidenceBytes = (Assert-GhidraHarnessDirectorySize -Path $logDir -MaximumBytes 64MB) + (Assert-GhidraHarnessDirectorySize -Path $reportsDir -MaximumBytes 64MB)
if ($evidenceBytes -gt 64MB) { throw 'raw benchmark evidence exceeds its 67108864 byte ceiling' }
$evidenceDirectories = @($logDir, $reportsDir)
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
    schema = 'disrobe.bench.ghidra-cleaner-input/v1'
    measurement_status = 'newly_measured_verified'
    measurement_verification = $provenance.verification
    raw_evidence = [pscustomobject]@{ directory = $rawEvidenceRelativeRoot; size_bytes = $evidenceBytes; files = $rawEvidenceFiles }
    historical_results_present = $historicalResultsPresent
    replaces_historical_results = $false
    ghidra_version = $ghidraVersion
    analysis = 'analyzeHeadless static analysis only (the sample is never executed)'
    provenance = $provenance
    export_command = $exportCommand
    headless_command = $headlessCommand
    samples = $rows
}

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
$md.Add("Toolchain: Ghidra $ghidraVersion from archive SHA-256 $($provenance.harness.ghidra_distribution.archive.sha256); JVM $($provenance.tools.ghidra_selected_jvm.version) ($($provenance.tools.ghidra_selected_jvm.vendor)); source $($provenance.source.revision) with identity SHA-256 $($provenance.source.identity_sha256); $($rows.Count) fixtures measured at $($provenance.utc).")
$md.Add('')
$intro = 'Ghidra ' + $ghidraVersion + ', `analyzeHeadless` default analysis. Each fixture is a real benign packed PE from `corpus/native/packers/` (Sysinternals utilities and small hello programs; see `corpus/native/packers/MANIFEST.toml` for provenance and SHA-256). `analyzeHeadless` performs static analysis only and never executes the sample. The packed column is the original packed file; the unpacked column is the loadable PE that `disrobe native export --format ghidra` rebuilds from it. Metrics come from the committed `GhidraReport.java` post-script. Regenerate with `benches/ghidra-cleaner-input/run.ps1 -GhidraHome <dir> -GhidraArchive <zip>`.'
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

$written = Publish-GhidraHarnessResults -OutputDirectory $OutDir -Json ($result | ConvertTo-Json -Depth 8) -Markdown (($md -join "`n") + "`n") -EvidenceDirectories $evidenceDirectories
$published = $true
Write-Host "wrote $($written.json)"
Write-Host "wrote $($written.markdown)"
Write-Host "selected by $($written.pointer)"
} catch {
    $failureDirectory = Join-Path $OutDir ('failures/' + [System.IO.Path]::GetFileName($runDirectory.path))
    [System.IO.Directory]::CreateDirectory($failureDirectory) | Out-Null
    foreach ($directory in @($logDir, $reportsDir)) {
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
