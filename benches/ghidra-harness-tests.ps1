#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ghidra-harness.psm1') -Force

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("disrobe-ghidra-harness-test-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

function Assert-Throws {
    param([scriptblock]$Action, [string]$Contains)
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notlike "*$Contains*") {
            throw "expected error containing '$Contains', got '$($_.Exception.Message)'"
        }
        return
    }
    throw "expected error containing '$Contains'"
}

function New-StandIn {
    param([string]$Name, [string]$Body)
    $path = Join-Path $scratch "$Name.cmd"
    [System.IO.File]::WriteAllText($path, "@echo off`r`n$Body`r`n", [System.Text.UTF8Encoding]::new($false))
    return $path
}

function Assert-ReportRejected {
    param([string]$Name, [string]$Json, [string]$Contains)
    $path = Join-Path $scratch "$Name.json"
    [System.IO.File]::WriteAllText($path, $Json, [System.Text.UTF8Encoding]::new($false))
    Assert-Throws -Action { Read-GhidraHarnessReport -Path $path -Schema unpack } -Contains $Contains
}

try {
    $publicPin = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'ghidra-toolchain.json') | ConvertFrom-Json
    if ($publicPin.schema -ne 'disrobe.bench.ghidra-toolchain/v1' -or
        $publicPin.ghidra.version -ne '12.1.2' -or
        $publicPin.ghidra.archive -ne 'ghidra_12.1.2_PUBLIC_20260605.zip' -or
        $publicPin.ghidra.archive_size_bytes -ne 572803866 -or
        $publicPin.ghidra.archive_sha256 -ne 'b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d' -or
        $publicPin.ghidra.release_url -ne 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip' -or
        $publicPin.ghidra.home_directory -ne 'ghidra_12.1.2_PUBLIC') {
        throw 'public Ghidra toolchain pin changed unexpectedly'
    }

    $sample = [pscustomobject]@{ id = 'required'; rel = 'required.bin' }
    Assert-Throws -Action { Assert-GhidraHarnessRoster -Corpus $scratch -Samples @($sample) } -Contains 'required benchmark fixtures are missing'

    $fixture = Join-Path $scratch 'required.bin'
    [System.IO.File]::WriteAllBytes($fixture, [byte[]](1, 2, 3))
    $resolved = @(Assert-GhidraHarnessRoster -Corpus $scratch -Samples @($sample))
    if ($resolved.Count -ne 1 -or -not $resolved[0].sha256) { throw 'required fixture did not produce provenance' }

    $resumeRoot = Join-Path $scratch 'resume-root'
    $resumeRun = Join-Path $resumeRoot 'run'
    New-Item -ItemType Directory -Force -Path $resumeRun | Out-Null
    $resumeState = Join-Path $resumeRun 'resume.json'
    $resumeIdentity = [pscustomobject]@{ disrobe_sha256 = 'a'; analyzer_sha256 = 'b'; post_script_sha256 = 'c'; script_sha256 = 'g'; module_sha256 = 'h'; toolchain = 'd'; java_home = 'e'; java_executable_sha256 = 'f'; ghidra_headless_maxmem = '1G'; ghidra_maxmem = $null; ghidra_headless_java_options = $null; ghidra_java_options = $null; schema = 'unpack'; timeout_seconds = 10; headless_arguments = 'args' }
    Write-GhidraHarnessResumeState -Path $resumeState -Schema unpack -Roster $resolved -Identity $resumeIdentity -Rows @([pscustomobject]@{ id = 'required'; fixture_sha256 = $resolved[0].sha256; unpacked = [pscustomobject]@{ functions = 1 }; packed_report_path = $fixture; unpacked_report_path = $fixture; packed_report_sha256 = $resolved[0].sha256; unpacked_report_sha256 = $resolved[0].sha256 })
    $loadedResume = @(Read-GhidraHarnessResumeState -Path $resumeState -Schema unpack -Roster $resolved -Identity $resumeIdentity)
    if ($loadedResume.Count -ne 1 -or $loadedResume[0].id -ne 'required') { throw 'resume state did not round-trip' }
    if ((Assert-GhidraHarnessResumeDirectory -OwnerRoot $resumeRoot -Path $resumeRun) -ne (Get-Item -LiteralPath $resumeRun).FullName) { throw 'resume directory was not contained' }
    [System.IO.File]::WriteAllBytes($fixture, [byte[]](1, 2, 4))
    Assert-Throws -Action { Read-GhidraHarnessResumeState -Path $resumeState -Schema unpack -Roster @(Assert-GhidraHarnessRoster -Corpus $scratch -Samples @($sample)) -Identity $resumeIdentity } -Contains 'no longer matches'
    Assert-Throws -Action { Read-GhidraHarnessResumeState -Path $resumeState -Schema unpack -Roster $resolved -Identity ([pscustomobject]@{ disrobe_sha256 = 'changed'; analyzer_sha256 = 'b'; post_script_sha256 = 'c'; script_sha256 = 'g'; module_sha256 = 'h'; toolchain = 'd'; java_home = 'e'; java_executable_sha256 = 'f'; ghidra_headless_maxmem = '1G'; ghidra_maxmem = $null; ghidra_headless_java_options = $null; ghidra_java_options = $null; schema = 'unpack'; timeout_seconds = 10; headless_arguments = 'args' }) } -Contains 'measurement identity'
    Assert-Throws -Action { Read-GhidraHarnessResumeState -Path $resumeState -Schema unpack -Roster $resolved -Identity ([pscustomobject]@{ disrobe_sha256 = 'a'; analyzer_sha256 = 'b'; post_script_sha256 = 'c'; script_sha256 = 'g'; module_sha256 = 'h'; toolchain = 'd'; java_home = 'e'; java_executable_sha256 = 'f'; ghidra_headless_maxmem = '2G'; ghidra_maxmem = $null; ghidra_headless_java_options = $null; ghidra_java_options = $null; schema = 'unpack'; timeout_seconds = 10; headless_arguments = 'args' }) } -Contains 'measurement identity'
    [System.IO.File]::WriteAllBytes($fixture, [byte[]](1, 2, 3))

    $pathWithSpace = Join-Path $scratch 'path with space'
    New-Item -ItemType Directory -Path $pathWithSpace | Out-Null
    $pi = [char]0x03c0
    $lambda = [char]0x03bb
    $snow = [char]0x96ea
    $iDiaeresis = [char]0x00ef
    $unicodeRelativePath = "nested/na${iDiaeresis}ve-$snow.txt"
    $utf8Producer = Join-Path $scratch 'utf8-producer.ps1'
    [System.IO.File]::WriteAllText($utf8Producer, @'
$relativePath = "nested/na$([char]0x00ef)ve-$([char]0x96ea).txt"
$payload = [System.Text.Encoding]::UTF8.GetBytes("$relativePath`0")
$stdout = [Console]::OpenStandardOutput()
$stdout.Write($payload, 0, $payload.Length)
[Console]::Error.WriteLine('harmless diagnostic')
'@, [System.Text.UTF8Encoding]::new($true))
    $utf8Output = Join-Path $scratch 'utf8-output.bin'
    $utf8Log = Join-Path $scratch 'utf8-diagnostic.log'
    $powerShell = Join-Path $PSHOME 'powershell.exe'
    $utf8Outcome = Invoke-GhidraHarnessProcess -FilePath $powerShell -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $utf8Producer) -LogPath $utf8Log -TimeoutSeconds 10 -StructuredOutputPath $utf8Output -MaximumStructuredOutputBytes 1024
    $expectedUtf8 = Join-Path $scratch 'expected-utf8.bin'
    [System.IO.File]::WriteAllBytes($expectedUtf8, [System.Text.Encoding]::UTF8.GetBytes("$unicodeRelativePath`0"))
    if ($utf8Outcome.exit_code -ne 0 -or $utf8Outcome.structured_output_sha256 -ne (Get-GhidraHarnessHash -Path $expectedUtf8)) {
        throw 'structured process output did not preserve UTF-8 bytes'
    }
    if ([System.IO.File]::ReadAllText($utf8Output, [System.Text.Encoding]::UTF8) -like '*harmless diagnostic*' -or [System.IO.File]::ReadAllText($utf8Log, [System.Text.Encoding]::UTF8) -notlike '*harmless diagnostic*') {
        throw 'structured process output included stderr diagnostics'
    }
    $oversizedOutput = Join-Path $scratch 'oversized-output.bin'
    Assert-Throws -Action { Invoke-GhidraHarnessProcess -FilePath $powerShell -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $utf8Producer) -LogPath (Join-Path $scratch 'oversized-output.log') -TimeoutSeconds 10 -StructuredOutputPath $oversizedOutput -MaximumStructuredOutputBytes 8 } -Contains 'structured output exceeds its 8 byte ceiling'
    if (Test-Path -LiteralPath $oversizedOutput) { throw 'oversized structured output was retained' }

    $validJson = '{"runtime":{"ghidra_version":"0.0-stand-in","java_home":"C:\\Java","java_version":"25.0.4","java_vendor":"Eclipse Adoptium","java_vm_name":"OpenJDK 64-Bit Server VM"},"program":"fixture","language":"x","image_base":"00400000","functions":1,"thunks":0,"instructions":1,"defined_strings":0,"resolved_imports":0,"executable_bytes":1,"decompile_attempts":1,"decompiled_ok":1,"instruction_bytes":1,"defined_data_bytes":0,"defined_bytes":1,"undefined_in_exec":0,"executable_block_bytes":1,"total_block_bytes":1}'
    $valid = New-StandIn -Name 'valid' -Body "> `"%~1`" echo $validJson`r`nexit /b 0"
    $validResult = Invoke-GhidraHarnessMeasurement -FilePath $valid -ArgumentList @((Join-Path $pathWithSpace 'valid.json')) -LogPath (Join-Path $pathWithSpace 'valid.log') -ReportPath (Join-Path $pathWithSpace 'valid.json') -Schema unpack -TimeoutSeconds 10
    if ($validResult.report.functions -ne 1) { throw 'valid unpack measurement did not parse' }
    $validResult = Invoke-GhidraHarnessMeasurement -FilePath $valid -ArgumentList @((Join-Path $pathWithSpace 'cleaner.json')) -LogPath (Join-Path $pathWithSpace 'cleaner.log') -ReportPath (Join-Path $pathWithSpace 'cleaner.json') -Schema cleaner -TimeoutSeconds 10
    if ($validResult.report.defined_bytes -ne 1) { throw 'valid cleaner measurement did not parse' }

    $noReport = New-StandIn -Name 'no-report' -Body 'exit /b 0'
    $staleReportPath = Join-Path $pathWithSpace 'valid.json'
    $staleReportHash = Get-GhidraHarnessHash -Path $staleReportPath
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $noReport -ArgumentList @($staleReportPath) -LogPath (Join-Path $scratch 'stale.log') -ReportPath $staleReportPath -Schema unpack -TimeoutSeconds 10 } -Contains 'report path must not already exist'
    if ((Get-GhidraHarnessHash -Path $staleReportPath) -ne $staleReportHash) { throw 'rejecting a stale report changed the prior evidence' }
    $missingReportPath = Join-Path $scratch 'missing-report.json'
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $noReport -ArgumentList @($missingReportPath) -LogPath (Join-Path $scratch 'missing-report.log') -ReportPath $missingReportPath -Schema unpack -TimeoutSeconds 10 } -Contains 'analyzer did not produce a report'

    $failed = New-StandIn -Name 'failed' -Body "> `"%~1`" echo {`"program`":`"fixture`",`"functions`":1}`r`nexit /b 9"
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $failed -ArgumentList @((Join-Path $scratch 'failed.json')) -LogPath (Join-Path $scratch 'failed.log') -ReportPath (Join-Path $scratch 'failed.json') -Schema unpack -TimeoutSeconds 10 } -Contains 'analyzer failed with exit code 9'

    $malformed = New-StandIn -Name 'malformed' -Body "> `"%~1`" echo not-json`r`nexit /b 0"
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $malformed -ArgumentList @((Join-Path $scratch 'malformed.json')) -LogPath (Join-Path $scratch 'malformed.log') -ReportPath (Join-Path $scratch 'malformed.json') -Schema unpack -TimeoutSeconds 10 } -Contains 'not valid JSON'

    $incomplete = New-StandIn -Name 'incomplete' -Body "> `"%~1`" echo {`"runtime`":{`"ghidra_version`":`"0.0-stand-in`",`"java_home`":`"C:\\Java`",`"java_version`":`"25.0.4`",`"java_vendor`":`"Eclipse Adoptium`",`"java_vm_name`":`"OpenJDK 64-Bit Server VM`"},`"program`":`"fixture`",`"language`":`"x`",`"image_base`":`"0`"}`r`nexit /b 0"
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $incomplete -ArgumentList @((Join-Path $scratch 'incomplete.json')) -LogPath (Join-Path $scratch 'incomplete.log') -ReportPath (Join-Path $scratch 'incomplete.json') -Schema unpack -TimeoutSeconds 10 } -Contains "missing required field 'functions'"

    $invalid = New-StandIn -Name 'invalid' -Body "> `"%~1`" echo {`"runtime`":{`"ghidra_version`":`"0.0-stand-in`",`"java_home`":`"C:\\Java`",`"java_version`":`"25.0.4`",`"java_vendor`":`"Eclipse Adoptium`",`"java_vm_name`":`"OpenJDK 64-Bit Server VM`"},`"program`":`"fixture`",`"language`":`"x`",`"image_base`":`"0`",`"functions`":1,`"thunks`":2,`"instructions`":1,`"defined_strings`":0,`"resolved_imports`":0,`"executable_bytes`":1,`"decompile_attempts`":1,`"decompiled_ok`":1}`r`nexit /b 0"
    Assert-Throws -Action { Invoke-GhidraHarnessMeasurement -FilePath $invalid -ArgumentList @((Join-Path $scratch 'invalid.json')) -LogPath (Join-Path $scratch 'invalid.log') -ReportPath (Join-Path $scratch 'invalid.json') -Schema unpack -TimeoutSeconds 10 } -Contains 'inconsistent function'

    Assert-ReportRejected -Name 'null-report' -Json 'null' -Contains 'must be a JSON object'
    Assert-ReportRejected -Name 'array-report' -Json '[]' -Contains 'must be a JSON object'
    Assert-ReportRejected -Name 'scalar-report' -Json '"value"' -Contains 'must be a JSON object'
    Assert-ReportRejected -Name 'null-metric' -Json ($validJson.Replace('"functions":1', '"functions":null')) -Contains "field 'functions' must be an integer"
    Assert-ReportRejected -Name 'string-metric' -Json ($validJson.Replace('"functions":1', '"functions":"1"')) -Contains "field 'functions' must be an integer"
    Assert-ReportRejected -Name 'negative-metric' -Json ($validJson.Replace('"functions":1', '"functions":-1')) -Contains "field 'functions' must be nonnegative"
    Assert-ReportRejected -Name 'fractional-metric' -Json ($validJson.Replace('"functions":1', '"functions":1.5')) -Contains "field 'functions' must be an integer"
    Assert-ReportRejected -Name 'invalid-image-base' -Json ($validJson.Replace('"image_base":"00400000"', '"image_base":"ram:00400000"')) -Contains "field 'image_base' must be a hexadecimal address"
    $invalidRuntime = $validJson | ConvertFrom-Json
    $invalidRuntime.PSObject.Properties.Remove('runtime')
    Assert-ReportRejected -Name 'missing-runtime' -Json ($invalidRuntime | ConvertTo-Json -Depth 4 -Compress) -Contains "field 'runtime' must be a JSON object"
    $invalidRuntime = $validJson | ConvertFrom-Json
    $invalidRuntime.runtime.PSObject.Properties.Remove('java_version')
    Assert-ReportRejected -Name 'missing-runtime-field' -Json ($invalidRuntime | ConvertTo-Json -Depth 4 -Compress) -Contains "runtime is missing required field 'java_version'"
    $invalidRuntime = $validJson | ConvertFrom-Json
    $invalidRuntime.runtime.java_vendor = 25
    Assert-ReportRejected -Name 'invalid-runtime-field' -Json ($invalidRuntime | ConvertTo-Json -Depth 4 -Compress) -Contains "runtime field 'java_vendor' must be a non-empty string"
    $invalidRuntime = $validJson | ConvertFrom-Json
    $invalidRuntime.runtime.java_home = 'relative-java-home'
    Assert-ReportRejected -Name 'relative-java-home' -Json ($invalidRuntime | ConvertTo-Json -Depth 4 -Compress) -Contains "runtime field 'java_home' must be an absolute path"

    $sourceRepository = Join-Path $scratch 'source-repository'
    New-Item -ItemType Directory -Path $sourceRepository | Out-Null
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    & $git -C $sourceRepository init --quiet
    & $git -C $sourceRepository config user.name 'Harness Test'
    & $git -C $sourceRepository config user.email 'harness@example.invalid'
    $trackedSourceName = "tracked-$pi.txt"
    $stagedSourceName = "staged-$snow.txt"
    $trackedSource = Join-Path $sourceRepository $trackedSourceName
    $stagedSource = Join-Path $sourceRepository $stagedSourceName
    [System.IO.File]::WriteAllText($trackedSource, "first $pi", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($stagedSource, "alpha $snow", [System.Text.UTF8Encoding]::new($false))
    & $git -C $sourceRepository add -- $trackedSourceName $stagedSourceName
    & $git -C $sourceRepository -c commit.gpgsign=false commit --quiet -m baseline
    if ($LASTEXITCODE -ne 0) { throw 'failed to create source provenance test repository' }
    $firstSourceLogs = Join-Path $scratch 'source-logs-first'
    New-Item -ItemType Directory -Path $firstSourceLogs | Out-Null
    $firstSource = Get-GhidraHarnessSourceProvenance -RepositoryRoot $sourceRepository -LogDirectory $firstSourceLogs -TimeoutSeconds 10
    [System.IO.File]::WriteAllText($trackedSource, "second $pi$snow", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($stagedSource, "beta $lambda$snow", [System.Text.UTF8Encoding]::new($false))
    & $git -C $sourceRepository add -- $stagedSourceName
    if ($LASTEXITCODE -ne 0) { throw 'failed to stage source provenance test content' }
    $untrackedDirectory = Join-Path $sourceRepository 'nested'
    New-Item -ItemType Directory -Path $untrackedDirectory | Out-Null
    $untrackedSource = Join-Path $sourceRepository $unicodeRelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    [System.IO.File]::WriteAllText($untrackedSource, "untracked $pi$snow", [System.Text.UTF8Encoding]::new($false))
    $secondSourceLogs = Join-Path $scratch 'source-logs-second'
    New-Item -ItemType Directory -Path $secondSourceLogs | Out-Null
    $secondSource = Get-GhidraHarnessSourceProvenance -RepositoryRoot $sourceRepository -LogDirectory $secondSourceLogs -TimeoutSeconds 10
    if ($firstSource.identity_sha256 -eq $secondSource.identity_sha256 -or -not $secondSource.dirty -or $secondSource.tracked_diff.size_bytes -eq 0) {
        throw 'changed source content did not change the captured source identity'
    }
    $trackedDiff = [System.IO.File]::ReadAllText($secondSource.tracked_diff.path, [System.Text.Encoding]::UTF8)
    if ($trackedDiff -notlike "*$trackedSourceName*" -or $trackedDiff -notlike "*$stagedSourceName*" -or $trackedDiff -notlike "*+second $pi$snow*" -or $trackedDiff -notlike "*+beta $lambda$snow*") {
        throw 'source provenance did not preserve both index and working-tree changes'
    }
    $expectedTrackedDiff = Join-Path $scratch 'expected-source.patch'
    & $git -C $sourceRepository -c core.quotepath=false diff --no-ext-diff --binary "--output=$expectedTrackedDiff" HEAD -- .
    if ($LASTEXITCODE -ne 0 -or $secondSource.tracked_diff.sha256 -ne (Get-GhidraHarnessHash -Path $expectedTrackedDiff)) {
        throw 'source provenance did not retain the exact Git patch bytes'
    }
    $untrackedManifest = @([System.IO.File]::ReadAllText($secondSource.untracked_manifest.path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json)
    if ($untrackedManifest.Count -ne 1 -or $untrackedManifest[0].path -ne $unicodeRelativePath -or $untrackedManifest[0].sha256 -ne (Get-GhidraHarnessHash -Path $untrackedSource)) {
        throw 'source provenance did not preserve the untracked source path and hash'
    }
    $thirdSourceLogs = Join-Path $scratch 'source-logs-third'
    New-Item -ItemType Directory -Path $thirdSourceLogs | Out-Null
    $thirdSource = Get-GhidraHarnessSourceProvenance -RepositoryRoot $sourceRepository -LogDirectory $thirdSourceLogs -TimeoutSeconds 10
    if ($thirdSource.identity_sha256 -ne $secondSource.identity_sha256) { throw 'unchanged source content produced a nondeterministic identity' }
    $failedSourceLogs = Join-Path $scratch 'source-logs-failed'
    New-Item -ItemType Directory -Path $failedSourceLogs | Out-Null
    Assert-Throws -Action { Get-GhidraHarnessSourceProvenance -RepositoryRoot $scratch -LogDirectory $failedSourceLogs -TimeoutSeconds 10 } -Contains 'git source revision capture exited'

    $exportRoot = Join-Path $scratch 'export'
    New-Item -ItemType Directory -Path $exportRoot | Out-Null
    $sentinel = Join-Path $exportRoot 'prior-output.txt'
    [System.IO.File]::WriteAllText($sentinel, 'preserve')
    $prepared = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $exportRoot -Name 'fixture'
    $secondPrepared = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $exportRoot -Name 'fixture'
    if ($prepared.path -eq $secondPrepared.path -or -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) { throw 'output directories were not uniquely and safely allocated' }
    [System.IO.File]::WriteAllText((Join-Path $prepared.path 'one.unpacked.exe'), 'one')
    $artifact = Get-GhidraHarnessExportArtifact -ExportDirectory $prepared.path
    if (-not $artifact.sha256) { throw 'selected export artifact lacks a hash' }
    [System.IO.File]::WriteAllText((Join-Path $prepared.path 'two.unpacked.exe'), 'two')
    Assert-Throws -Action { Get-GhidraHarnessExportArtifact -ExportDirectory $prepared.path } -Contains 'expected exactly one rebuilt'
    Assert-Throws -Action { Assert-GhidraHarnessDirectorySize -Path $prepared.path -MaximumBytes 1 } -Contains 'exceeds its 1 byte ceiling'
    Assert-Throws -Action { Remove-GhidraHarnessOutputDirectory -Path $scratch -OwnerRoot $exportRoot } -Contains 'not a strict descendant'
    Remove-GhidraHarnessOutputDirectory -Path $secondPrepared.path -OwnerRoot $exportRoot
    if (Test-Path -LiteralPath $secondPrepared.path) { throw 'owned output directory cleanup left its target behind' }

    $publicationOutput = Join-Path $scratch 'publication-output'
    $publicationEvidence = Join-Path $scratch 'publication-evidence'
    New-Item -ItemType Directory -Path $publicationOutput | Out-Null
    New-Item -ItemType Directory -Path $publicationEvidence | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $publicationEvidence 'evidence.log'), 'evidence')
    $firstPublication = Publish-GhidraHarnessResults -OutputDirectory $publicationOutput -Json '{"generation":1}' -Markdown 'generation 1' -EvidenceDirectories @($publicationEvidence)
    $selectedBeforeFailure = [System.IO.File]::ReadAllBytes($firstPublication.pointer)
    $snapshotCountBeforeFailure = @(Get-ChildItem -LiteralPath (Join-Path $publicationOutput 'snapshots') -Directory | Where-Object { $_.Name -notlike 'stage-*' }).Count
    $pointerLock = [System.IO.File]::Open($firstPublication.pointer, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
    try {
        Assert-Throws -Action { Publish-GhidraHarnessResults -OutputDirectory $publicationOutput -Json '{"generation":2}' -Markdown 'generation 2' -EvidenceDirectories @($publicationEvidence) } -Contains 'Replace'
    } finally {
        $pointerLock.Dispose()
    }
    if ([System.BitConverter]::ToString([System.IO.File]::ReadAllBytes($firstPublication.pointer)) -ne [System.BitConverter]::ToString($selectedBeforeFailure)) { throw 'failed publication changed the selected generation' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $publicationOutput 'snapshots') -Directory | Where-Object { $_.Name -notlike 'stage-*' }).Count -ne $snapshotCountBeforeFailure) { throw 'failed publication left an orphan snapshot' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $publicationOutput 'snapshots') -Directory -Filter 'stage-*').Count -ne 0) { throw 'failed publication left an orphan staging directory' }

    $recorder = Join-Path $scratch 'record-arguments.ps1'
    [System.IO.File]::WriteAllText($recorder, "[System.IO.File]::WriteAllLines(`$env:GHIDRA_TEST_OUTPUT, [string[]]@(`$env:GHIDRA_TEST_FIRST, `$env:GHIDRA_TEST_SECOND, `$env:GHIDRA_TEST_THIRD, `$env:GHIDRA_TEST_FOURTH), [System.Text.UTF8Encoding]::new(`$false))`r`n", [System.Text.UTF8Encoding]::new($false))
    $batchDirectory = Join-Path $pathWithSpace 'batch & (roundtrip)'
    New-Item -ItemType Directory -Path $batchDirectory | Out-Null
    $roundTrip = Join-Path $batchDirectory 'record arguments.cmd'
    [System.IO.File]::WriteAllText($roundTrip, "@echo off`r`nset `"GHIDRA_TEST_OUTPUT=%~1`"`r`nset `"GHIDRA_TEST_FIRST=%~2`"`r`nset `"GHIDRA_TEST_SECOND=%~3`"`r`nset `"GHIDRA_TEST_THIRD=%~4`"`r`nset `"GHIDRA_TEST_FOURTH=%~5`"`r`n`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -NonInteractive -File `"$recorder`"`r`n", [System.Text.UTF8Encoding]::new($false))
    $argumentOutput = Join-Path $pathWithSpace 'arguments & values.txt'
    $expectedArguments = [string[]]@('space value', 'ampersand & value', '(parentheses)', 'trailing\')
    $roundTripOutcome = Invoke-GhidraHarnessProcess -FilePath $roundTrip -ArgumentList ([string[]]@($argumentOutput) + $expectedArguments) -LogPath (Join-Path $scratch 'roundtrip.log') -TimeoutSeconds 10
    if ($roundTripOutcome.exit_code -ne 0) { throw "batch argument recorder exited $($roundTripOutcome.exit_code)" }
    $actualArguments = [System.IO.File]::ReadAllLines($argumentOutput)
    if (($actualArguments -join "`n") -ne ($expectedArguments -join "`n")) { throw "batch arguments changed in transit: $($actualArguments -join '|')" }
    $unsupportedMarker = Join-Path $scratch 'unsupported-started.txt'
    Assert-Throws -Action { Invoke-GhidraHarnessProcess -FilePath $roundTrip -ArgumentList @($unsupportedMarker, '100%', 'ok', 'ok', 'ok') -LogPath (Join-Path $scratch 'percent.log') -TimeoutSeconds 10 } -Contains 'cannot contain quotes, percent signs, exclamation marks'
    Assert-Throws -Action { Invoke-GhidraHarnessProcess -FilePath $roundTrip -ArgumentList @($unsupportedMarker, 'bang!', 'ok', 'ok', 'ok') -LogPath (Join-Path $scratch 'bang.log') -TimeoutSeconds 10 } -Contains 'cannot contain quotes, percent signs, exclamation marks'
    if (Test-Path -LiteralPath $unsupportedMarker) { throw 'unsupported batch arguments started the child process' }

    $childScript = Join-Path $scratch 'ready-child.ps1'
    [System.IO.File]::WriteAllText($childScript, "param([string]`$PidPath)`r`n[Console]::Out.WriteLine('analyzer progress')`r`n[Console]::Error.WriteLine('analyzer diagnostic')`r`n[System.IO.File]::WriteAllText(`$PidPath, [string]`$PID)`r`nStart-Sleep -Seconds 30`r`n", [System.Text.UTF8Encoding]::new($false))
    $childPidPath = Join-Path $scratch 'ready-child.pid'
    $hang = New-StandIn -Name 'hang' -Body "`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -NonInteractive -File `"$childScript`" `"%~1`""
    Assert-Throws -Action { Invoke-GhidraHarnessProcess -FilePath $hang -ArgumentList @($childPidPath) -LogPath (Join-Path $scratch 'hang.log') -TimeoutSeconds 2 } -Contains 'timed out'
    $timeoutLog = [System.IO.File]::ReadAllText((Join-Path $scratch 'hang.log'))
    if ($timeoutLog -notlike '*analyzer progress*' -or $timeoutLog -notlike '*analyzer diagnostic*' -or $timeoutLog -notlike '*timeout after 2 seconds*') {
        throw 'timeout discarded analyzer output'
    }
    if (-not (Test-Path -LiteralPath $childPidPath -PathType Leaf)) { throw 'timeout test did not establish a ready child process' }
    $childPid = [int](Get-Content -Raw -LiteralPath $childPidPath)
    $child = Get-Process -Id $childPid -ErrorAction SilentlyContinue
    if ($child) {
        if (-not $child.WaitForExit(5000)) { throw "timeout left owned child pid $childPid running" }
        throw "owned child pid $childPid survived process-tree cleanup"
    }

    $fakeCorpus = Join-Path $scratch 'corpus'
    $fixturePaths = [string[]]@(
        'native/packers/upx/hello.packed.nrv2b.exe'
        'native/packers/aspack/Clockres.packed.aspack.exe'
        'native/packers/aspack/AccessEnum.packed.aspack.exe'
        'native/packers/pecompact/Clockres.packed.pecompact.exe'
        'native/packers/pecompact/AccessEnum.packed.pecompact.exe'
        'native/packers/mew/Clockres.packed.mew.exe'
        'native/packers/mew/AccessEnum.packed.mew.exe'
        'native/packers/mew/Autologon.packed.mew.exe'
        'native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe'
    )
    foreach ($relativePath in $fixturePaths) {
        $fixturePath = Join-Path $fakeCorpus $relativePath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fixturePath) | Out-Null
        [System.IO.File]::WriteAllBytes($fixturePath, [byte[]](77, 90))
    }

    $fakeDisrobeScript = Join-Path $scratch 'fake-disrobe.ps1'
    [System.IO.File]::WriteAllText($fakeDisrobeScript, @'
if ($args.Count -eq 1 -and $args[0] -eq '--version') {
    Write-Output 'disrobe 0.0.0-stand-in'
    exit 0
}
if ($args.Count -ne 7 -or $args[0] -ne 'native' -or $args[1] -ne 'export' -or $args[2] -ne '--format' -or $args[3] -ne 'ghidra' -or $args[5] -ne '--out') {
    exit 23
}
New-Item -ItemType Directory -Force -Path $args[6] | Out-Null
[System.IO.File]::WriteAllBytes((Join-Path $args[6] 'fixture.unpacked.exe'), [byte[]](77, 90, 1))
'@, [System.Text.UTF8Encoding]::new($false))
    $fakeDisrobe = New-StandIn -Name 'fake-disrobe' -Body "`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -NonInteractive -File `"$fakeDisrobeScript`" %*"

    $fakeGhidra = Join-Path $scratch 'fake Ghidra & (stand-in)'
    $fakeGhidraSupport = Join-Path $fakeGhidra 'support'
    $fakeGhidraApplication = Join-Path $fakeGhidra 'Ghidra'
    New-Item -ItemType Directory -Force -Path $fakeGhidraSupport | Out-Null
    New-Item -ItemType Directory -Force -Path $fakeGhidraApplication | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $fakeGhidraApplication 'application.properties'), "application.version=0.0-stand-in`n", [System.Text.UTF8Encoding]::new($false))
    $fakeAnalyzerScript = Join-Path $scratch 'fake-analyze-headless.ps1'
    [System.IO.File]::WriteAllText($fakeAnalyzerScript, @'
if ($env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER) {
    [System.IO.File]::AppendAllText($env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER, "$($args[1])`n")
}
if ($args.Count -ne 11 -or $args[2] -ne '-import' -or $args[4] -ne '-postScript' -or $args[7] -ne '-scriptPath' -or $args[9] -ne '-deleteProject' -or $args[10] -ne '-overwrite') {
    exit 29
}
if ($env:DISROBE_GHIDRA_TEST_FAIL_UNPACKED -eq $args[1] -and $args[3] -like '*.unpacked.exe') {
    exit 17
}
$javaHome = $env:DISROBE_GHIDRA_TEST_JAVA_HOME.Replace('\', '\\')
$runtime = '"runtime":{"ghidra_version":"0.0-stand-in","java_home":"' + $javaHome + '","java_version":"25.0.4","java_vendor":"Eclipse Adoptium","java_vm_name":"OpenJDK 64-Bit Server VM"},'
$unpack = '{' + $runtime + '"program":"fixture","language":"x86:LE:64:default","image_base":"00400000","functions":1,"thunks":0,"instructions":1,"defined_strings":0,"resolved_imports":0,"executable_bytes":1,"decompile_attempts":1,"decompiled_ok":1}'
$cleaner = '{' + $runtime + '"program":"fixture","language":"x86:LE:64:default","image_base":"00400000","functions":1,"thunks":0,"instructions":1,"instruction_bytes":1,"defined_data_bytes":0,"defined_bytes":1,"defined_strings":0,"undefined_in_exec":0,"executable_block_bytes":1,"total_block_bytes":1}'
$json = if ($args[5] -eq 'DisrobeMetrics.java') { $unpack } elseif ($args[5] -eq 'GhidraReport.java') { $cleaner } else { exit 31 }
[System.IO.File]::WriteAllText($args[6], $json, [System.Text.UTF8Encoding]::new($false))
'@, [System.Text.UTF8Encoding]::new($false))
    $fakeAnalyze = Join-Path $fakeGhidraSupport 'analyzeHeadless.bat'
    [System.IO.File]::WriteAllText($fakeAnalyze, "@echo off`r`n`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -NonInteractive -File `"$fakeAnalyzerScript`" %*`r`n", [System.Text.UTF8Encoding]::new($false))

    $fakeJavaHome = Join-Path $scratch 'fake-java-home'
    $fakeJavaBin = Join-Path $fakeJavaHome 'bin'
    New-Item -ItemType Directory -Path $fakeJavaBin | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $fakeJavaBin 'java.exe'), 'stand-in java', [System.Text.UTF8Encoding]::new($false))
    $env:DISROBE_GHIDRA_TEST_JAVA_HOME = $fakeJavaHome
    $fakeArchive = Join-Path $scratch 'ghidra-stand-in.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($fakeGhidra, $fakeArchive, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $fakeArchiveItem = Get-Item -LiteralPath $fakeArchive
    $fakeToolchainManifest = Join-Path $scratch 'ghidra-toolchain.json'
    [System.IO.File]::WriteAllText($fakeToolchainManifest, ([pscustomobject]@{
        schema = 'disrobe.bench.ghidra-toolchain/v1'
        ghidra = [pscustomobject]@{
            version = '0.0-stand-in'
            archive = $fakeArchiveItem.Name
            archive_size_bytes = $fakeArchiveItem.Length
            archive_sha256 = Get-GhidraHarnessHash -Path $fakeArchive
            release_url = 'https://example.invalid/ghidra-stand-in.zip'
            home_directory = $fakeGhidra.Substring((Split-Path -Parent $fakeGhidra).Length + 1)
        }
    } | ConvertTo-Json -Depth 3), [System.Text.UTF8Encoding]::new($false))
    $verifiedToolchain = Assert-GhidraHarnessToolchain -ManifestPath $fakeToolchainManifest -ArchivePath $fakeArchive -GhidraHome $fakeGhidra
    if (-not $verifiedToolchain.installation.verified_against_archive -or $verifiedToolchain.archive.sha256 -ne (Get-GhidraHarnessHash -Path $fakeArchive)) {
        throw 'toolchain verification did not bind the installation to its archive'
    }
    $badManifest = Join-Path $scratch 'bad-ghidra-toolchain.json'
    $badPin = Get-Content -Raw -LiteralPath $fakeToolchainManifest | ConvertFrom-Json
    $badPin.ghidra.archive_sha256 = '0' * 64
    [System.IO.File]::WriteAllText($badManifest, ($badPin | ConvertTo-Json -Depth 3), [System.Text.UTF8Encoding]::new($false))
    Assert-Throws -Action { Assert-GhidraHarnessToolchain -ManifestPath $badManifest -ArchivePath $fakeArchive -GhidraHome $fakeGhidra } -Contains 'does not match pinned'

    $provenanceLog = Join-Path $scratch 'provenance-logs'
    New-Item -ItemType Directory -Path $provenanceLog | Out-Null
    $firstRuntime = [pscustomobject]@{ runtime = [pscustomobject]@{ ghidra_version = '0.0-stand-in'; java_home = $fakeJavaHome; java_version = '25.0.4'; java_vendor = 'Eclipse Adoptium'; java_vm_name = 'OpenJDK 64-Bit Server VM' } }
    $secondRuntime = [pscustomobject]@{ runtime = [pscustomobject]@{ ghidra_version = '0.0-stand-in'; java_home = $fakeJavaHome; java_version = '25.0.5'; java_vendor = 'Eclipse Adoptium'; java_vm_name = 'OpenJDK 64-Bit Server VM' } }
    Assert-Throws -Action {
        Get-GhidraHarnessProvenance -RepositoryRoot (Split-Path -Parent $PSScriptRoot) -Disrobe $fakeDisrobe -Analyzer $fakeAnalyze -ScriptPath $PSCommandPath -PostScriptPath (Join-Path $PSScriptRoot 'ghidra-unpack\DisrobeMetrics.java') -LogDirectory $provenanceLog -Toolchain $verifiedToolchain -Reports @($firstRuntime, $secondRuntime) -ExportCommand 'export' -HeadlessCommand 'analyze' -TimeoutSeconds 10
    } -Contains "reports disagree on runtime field 'java_version'"
    $wrongGhidraRuntime = [pscustomobject]@{ runtime = [pscustomobject]@{ ghidra_version = '0.0-other'; java_home = $fakeJavaHome; java_version = '25.0.4'; java_vendor = 'Eclipse Adoptium'; java_vm_name = 'OpenJDK 64-Bit Server VM' } }
    Assert-Throws -Action {
        Get-GhidraHarnessProvenance -RepositoryRoot (Split-Path -Parent $PSScriptRoot) -Disrobe $fakeDisrobe -Analyzer $fakeAnalyze -ScriptPath $PSCommandPath -PostScriptPath (Join-Path $PSScriptRoot 'ghidra-unpack\DisrobeMetrics.java') -LogDirectory $provenanceLog -Toolchain $verifiedToolchain -Reports @($wrongGhidraRuntime) -ExportCommand 'export' -HeadlessCommand 'analyze' -TimeoutSeconds 10
    } -Contains "running Ghidra version '0.0-other' does not match pinned '0.0-stand-in'"

    $entrypoints = @(
        [pscustomobject]@{ path = Join-Path $PSScriptRoot 'ghidra-unpack\ghidra-unpack-benchmark.ps1'; count = 6; name = 'unpack' }
        [pscustomobject]@{ path = Join-Path $PSScriptRoot 'ghidra-cleaner-input\run.ps1'; count = 9; name = 'cleaner' }
    )
    foreach ($entrypoint in $entrypoints) {
        $entryOut = Join-Path $scratch "$($entrypoint.name)-results"
        $entryScratch = Join-Path $scratch "$($entrypoint.name)-scratch"
        New-Item -ItemType Directory -Path $entryOut | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $entryOut 'results.json'), 'legacy json', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $entryOut 'results.md'), 'legacy markdown', [System.Text.UTF8Encoding]::new($false))
        & $entrypoint.path -Disrobe $fakeDisrobe -GhidraHome $fakeGhidra -GhidraArchive $fakeArchive -ToolchainManifest $fakeToolchainManifest -Corpus $fakeCorpus -OutDir $entryOut -Scratch $entryScratch -TimeoutSeconds 10 | Out-Null
        $entryPointer = Get-Content -Raw -LiteralPath (Join-Path $entryOut 'current.json') | ConvertFrom-Json
        $entryResultPath = Join-Path $entryOut $entryPointer.results_json
        $entrySnapshotPath = Split-Path -Parent $entryResultPath
        $entryResult = Get-Content -Raw -LiteralPath $entryResultPath | ConvertFrom-Json
        $entryMarkdown = [System.IO.File]::ReadAllText((Join-Path $entryOut $entryPointer.results_markdown))
        $entryManifestPath = Join-Path $entryOut $entryPointer.manifest
        if ($entryPointer.manifest_sha256 -ne (Get-GhidraHarnessHash -Path $entryManifestPath)) { throw "$($entrypoint.name) entrypoint selected a manifest with the wrong hash" }
        $expectedIds = if ($entrypoint.name -eq 'unpack') {
            @('aspack_accessenum', 'aspack_clockres', 'kkrunchy_classic', 'pecompact_accessenum', 'pecompact_clockres', 'upx_hello')
        } else {
            @('aspack_accessenum', 'aspack_clockres', 'kkrunchy_classic', 'mew_accessenum', 'mew_autologon', 'mew_clockres', 'pecompact_accessenum', 'pecompact_clockres', 'upx_hello')
        }
        $actualIds = @($entryResult.samples | ForEach-Object { $_.id } | Sort-Object)
        if (@($entryResult.samples).Count -ne $entrypoint.count -or ($actualIds -join ',') -ne ($expectedIds -join ',')) { throw "$($entrypoint.name) entrypoint changed its fixed fixture roster" }
        if (@($entryResult.samples | Where-Object { -not $_.export_ok -or $null -eq $_.unpacked }).Count -ne 0) { throw "$($entrypoint.name) entrypoint omitted a successful stand-in measurement" }
        if ($entryResult.measurement_status -ne 'newly_measured_verified' -or -not $entryResult.measurement_verification.supports_verified_measurement) { throw "$($entrypoint.name) entrypoint did not preserve verified provenance" }
        if (-not $entryResult.provenance.tools.ghidra_selected_jvm.verified -or $entryResult.provenance.tools.ghidra_selected_jvm.version -ne '25.0.4') { throw "$($entrypoint.name) entrypoint did not record the selected JVM" }
        if (-not $entryResult.provenance.harness.ghidra_distribution.installation.verified_against_archive -or $entryResult.provenance.harness.ghidra_distribution.archive.sha256 -ne (Get-GhidraHarnessHash -Path $fakeArchive)) { throw "$($entrypoint.name) entrypoint did not preserve verified distribution evidence" }
        if ($entryResult.provenance.host.cpu.physical_cores -le 0 -or $entryResult.provenance.host.cpu.logical_processors -le 0 -or $entryResult.provenance.host.physical_memory_bytes -le 0) { throw "$($entrypoint.name) entrypoint did not record measurement host hardware" }
        if ($entryMarkdown -notlike '*Toolchain: Ghidra 0.0-stand-in*source*identity SHA-256*fixtures measured at*' -or $entryMarkdown -like '*Measurement status:*' -or $entryMarkdown -like '*legacy root results*') { throw "$($entrypoint.name) entrypoint did not publish useful run provenance" }
        $rawEvidencePath = Join-Path $entrySnapshotPath $entryResult.raw_evidence.directory
        if (-not (Test-Path -LiteralPath $rawEvidencePath -PathType Container) -or @($entryResult.raw_evidence.files).Count -eq 0) { throw "$($entrypoint.name) entrypoint did not preserve raw evidence" }
        foreach ($measuredSample in $entryResult.samples) {
            if (-not $measuredSample.export_directory.cleaned_after_run) { throw "$($entrypoint.name) entrypoint retained an unqualified temporary path" }
            foreach ($property in @('export_outcome', 'packed_outcome', 'unpacked_outcome')) {
                $outcome = $measuredSample.$property
                if ($null -ne $outcome -and -not (Test-Path -LiteralPath (Join-Path $entrySnapshotPath $outcome.log) -PathType Leaf)) { throw "$($entrypoint.name) entrypoint lost a referenced process log" }
            }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $entrySnapshotPath $entryResult.provenance.tools.disrobe.version_outcome.log) -PathType Leaf)) { throw "$($entrypoint.name) entrypoint lost its version log" }
        if (-not (Test-Path -LiteralPath (Join-Path $entrySnapshotPath $entryResult.provenance.source.tracked_diff.path) -PathType Leaf) -or -not (Test-Path -LiteralPath (Join-Path $entrySnapshotPath $entryResult.provenance.source.untracked_manifest.path) -PathType Leaf)) { throw "$($entrypoint.name) entrypoint lost its source provenance evidence" }
        if ([System.IO.File]::ReadAllText((Join-Path $entryOut 'results.json')) -ne 'legacy json' -or [System.IO.File]::ReadAllText((Join-Path $entryOut 'results.md')) -ne 'legacy markdown') { throw "$($entrypoint.name) entrypoint changed legacy root results" }
        if (@(Get-ChildItem -LiteralPath $entryScratch -Force).Count -ne 0) { throw "$($entrypoint.name) entrypoint retained its successful temporary run" }

        $failedOut = Join-Path $scratch "$($entrypoint.name)-failed-results"
        New-Item -ItemType Directory -Force -Path $failedOut | Out-Null
        $historicalPath = Join-Path $failedOut 'results.json'
        $historicalMarkdownPath = Join-Path $failedOut 'results.md'
        [System.IO.File]::WriteAllText($historicalPath, 'historical', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($historicalMarkdownPath, 'historical markdown', [System.Text.UTF8Encoding]::new($false))
        $failedScratch = Join-Path $scratch "$($entrypoint.name)-failed-scratch"
        $env:DISROBE_GHIDRA_TEST_FAIL_UNPACKED = 'aspack_clockres_unpacked'
        try {
            Assert-Throws -Action { & $entrypoint.path -Disrobe $fakeDisrobe -GhidraHome $fakeGhidra -GhidraArchive $fakeArchive -ToolchainManifest $fakeToolchainManifest -Corpus $fakeCorpus -OutDir $failedOut -Scratch $failedScratch -TimeoutSeconds 10 } -Contains 'analyzer failed with exit code 17'
        } finally {
            Remove-Item Env:DISROBE_GHIDRA_TEST_FAIL_UNPACKED -ErrorAction SilentlyContinue
        }
        if ([System.IO.File]::ReadAllText($historicalPath) -ne 'historical') { throw "$($entrypoint.name) entrypoint rewrote historical results after a measurement failure" }
        if ([System.IO.File]::ReadAllText($historicalMarkdownPath) -ne 'historical markdown') { throw "$($entrypoint.name) entrypoint rewrote historical Markdown after a measurement failure" }
        $failedScratchRuns = @(Get-ChildItem -LiteralPath $failedScratch -Directory)
        if ($failedScratchRuns.Count -ne 1) { throw "$($entrypoint.name) entrypoint did not retain exactly one failed temporary run" }
        if (-not (Test-Path -LiteralPath (Join-Path $failedScratchRuns[0].FullName 'resume.json') -PathType Leaf)) { throw "$($entrypoint.name) entrypoint did not retain a usable failed resume checkpoint" }
        if (-not (Test-Path -LiteralPath (Join-Path $failedScratchRuns[0].FullName 'logs/aspack_clockres_unpacked.log') -PathType Leaf)) { throw "$($entrypoint.name) entrypoint did not retain failed-run diagnostics" }
        $failureRuns = @(Get-ChildItem -LiteralPath (Join-Path $failedOut 'failures') -Directory)
        if ($failureRuns.Count -ne 1) { throw "$($entrypoint.name) entrypoint did not retain one failed run" }
        $failedAnalyzerLog = Join-Path $failureRuns[0].FullName 'logs/aspack_clockres_unpacked.log'
        if (-not (Test-Path -LiteralPath $failedAnalyzerLog -PathType Leaf)) { throw "$($entrypoint.name) entrypoint discarded the failing analyzer log" }

        $invalidDisrobe = Join-Path $scratch 'invalid-disrobe.exe'
        [System.IO.File]::WriteAllText($invalidDisrobe, 'not an executable', [System.Text.UTF8Encoding]::new($false))
        $processFailureOut = Join-Path $scratch "$($entrypoint.name)-process-failure-results"
        $processFailureScratch = Join-Path $scratch "$($entrypoint.name)-process-failure-scratch"
        New-Item -ItemType Directory -Force -Path $processFailureOut | Out-Null
        $processFailureJson = Join-Path $processFailureOut 'results.json'
        $processFailureMarkdown = Join-Path $processFailureOut 'results.md'
        [System.IO.File]::WriteAllText($processFailureJson, 'historical', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($processFailureMarkdown, 'historical markdown', [System.Text.UTF8Encoding]::new($false))
        $analyzerMarker = Join-Path $scratch "$($entrypoint.name)-unexpected-analyzer.txt"
        $env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER = $analyzerMarker
        try {
            Assert-Throws -Action { & $entrypoint.path -Disrobe $invalidDisrobe -GhidraHome $fakeGhidra -GhidraArchive $fakeArchive -ToolchainManifest $fakeToolchainManifest -Corpus $fakeCorpus -OutDir $processFailureOut -Scratch $processFailureScratch -TimeoutSeconds 10 } -Contains 'Start'
        } finally {
            Remove-Item Env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $analyzerMarker) { throw "$($entrypoint.name) entrypoint launched analysis after an export process-control failure" }
        if ([System.IO.File]::ReadAllText($processFailureJson) -ne 'historical' -or [System.IO.File]::ReadAllText($processFailureMarkdown) -ne 'historical markdown') { throw "$($entrypoint.name) entrypoint rewrote historical results after a process-control failure" }
        $processFailureRuns = @(Get-ChildItem -LiteralPath $processFailureScratch -Directory)
        if ($processFailureRuns.Count -ne 1 -or -not (Test-Path -LiteralPath (Join-Path $processFailureRuns[0].FullName 'resume.json') -PathType Leaf)) { throw "$($entrypoint.name) entrypoint did not retain its process-control failure checkpoint" }

        $resumePath = Join-Path $failedScratchRuns[0].FullName 'resume.json'
        $resumeState = Get-Content -Raw -LiteralPath $resumePath | ConvertFrom-Json
        if (@($resumeState.rows).Count -ne 1 -or $resumeState.rows[0].id -ne 'upx_hello') { throw "$($entrypoint.name) resume regression requires one completed measurement" }
        $completedRow = $resumeState.rows[0]
        $completedRow.packed.functions = 99
        $completedRow.unpacked.functions = 100
        [System.IO.File]::WriteAllText($resumePath, ($resumeState | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
        foreach ($side in @('packed', 'unpacked')) {
            if ((Get-GhidraHarnessHash -Path $completedRow."${side}_report_path") -ne $completedRow."${side}_report_sha256") { throw 'changing cached metrics changed raw report evidence' }
        }
        $resumeMarker = Join-Path $scratch "$($entrypoint.name)-resume-analyzer.txt"
        $env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER = $resumeMarker
        try {
            & $entrypoint.path -Disrobe $fakeDisrobe -GhidraHome $fakeGhidra -GhidraArchive $fakeArchive -ToolchainManifest $fakeToolchainManifest -Corpus $fakeCorpus -OutDir $failedOut -Scratch $failedScratch -ResumeRunDirectory $failedScratchRuns[0].FullName -TimeoutSeconds 10 | Out-Null
        } finally {
            Remove-Item Env:DISROBE_GHIDRA_TEST_ANALYZER_MARKER -ErrorAction SilentlyContinue
        }
        $resumePointer = Get-Content -Raw -LiteralPath (Join-Path $failedOut 'current.json') | ConvertFrom-Json
        $resumedResultPath = Join-Path $failedOut $resumePointer.results_json
        $resumedResult = Get-Content -Raw -LiteralPath $resumedResultPath | ConvertFrom-Json
        $resumedRows = @($resumedResult.samples | Where-Object { $_.id -eq 'upx_hello' })
        if ($resumedRows.Count -ne 1 -or $resumedRows[0].packed.functions -ne 1 -or $resumedRows[0].unpacked.functions -ne 1) { throw "$($entrypoint.name) resume published changed cached counts instead of raw report metrics" }
        $resumedLaunches = @(Get-Content -LiteralPath $resumeMarker)
        if ($resumedLaunches.Count -ne (($entrypoint.count - 1) * 2) -or @($resumedLaunches | Where-Object { $_ -like 'upx_hello_*' }).Count -ne 0) { throw "$($entrypoint.name) resume remeasured a completed fixture" }
        $resumedEvidence = Join-Path (Split-Path -Parent $resumedResultPath) $resumedResult.raw_evidence.directory
        if (@(Get-ChildItem -LiteralPath $resumedEvidence -Recurse -File -Filter 'aspack_clockres_packed*.json').Count -ne 2) { throw "$($entrypoint.name) resume overwrote a previous attempt report" }
    }

    [System.IO.File]::AppendAllText($fakeAnalyze, "remapped`r`n", [System.Text.UTF8Encoding]::new($false))
    Assert-Throws -Action { Assert-GhidraHarnessToolchain -ManifestPath $fakeToolchainManifest -ArchivePath $fakeArchive -GhidraHome $fakeGhidra } -Contains 'differs from the pinned archive'

    Write-Host 'ghidra harness tests passed'
} finally {
    Remove-Item Env:DISROBE_GHIDRA_TEST_JAVA_HOME -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
