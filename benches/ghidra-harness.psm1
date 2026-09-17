Set-StrictMode -Version Latest

function Get-GhidraHarnessHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required file is missing: $Path"
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-GhidraHarnessStreamHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-GhidraHarnessTextHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $stream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($Text))
    try {
        return Get-GhidraHarnessStreamHash -Stream $stream
    } finally {
        $stream.Dispose()
    }
}

function Assert-GhidraHarnessToolchain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$GhidraHome
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Ghidra toolchain manifest is missing: $ManifestPath"
    }
    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force
    if ($manifestItem.Length -gt 1MB) {
        throw "Ghidra toolchain manifest exceeds its 1048576 byte ceiling: $ManifestPath"
    }
    try {
        $manifest = Get-Content -Raw -LiteralPath $manifestItem.FullName | ConvertFrom-Json
    } catch {
        throw "Ghidra toolchain manifest is not valid JSON at ${ManifestPath}: $($_.Exception.Message)"
    }
    if ($null -eq $manifest -or $manifest -is [array] -or $manifest.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        throw "Ghidra toolchain manifest must be a JSON object: $ManifestPath"
    }
    if ($manifest.schema -ne 'disrobe.bench.ghidra-toolchain/v1') {
        throw "Ghidra toolchain manifest has an unsupported schema: $ManifestPath"
    }
    if ($null -eq $manifest.ghidra -or $manifest.ghidra.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        throw "Ghidra toolchain manifest must contain a Ghidra object: $ManifestPath"
    }
    $pin = $manifest.ghidra
    foreach ($field in @('version', 'archive', 'archive_sha256', 'release_url', 'home_directory')) {
        if ($pin.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($pin.$field)) {
            throw "Ghidra toolchain field '$field' must be a non-empty string: $ManifestPath"
        }
    }
    if ($pin.archive_size_bytes -isnot [int64] -and $pin.archive_size_bytes -isnot [int32]) {
        throw "Ghidra toolchain field 'archive_size_bytes' must be an integer: $ManifestPath"
    }
    if ($pin.archive_size_bytes -le 0) {
        throw "Ghidra toolchain field 'archive_size_bytes' must be positive: $ManifestPath"
    }
    if ($pin.archive_sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Ghidra toolchain field 'archive_sha256' must be a SHA-256 digest: $ManifestPath"
    }
    $releaseUri = $null
    if (-not [System.Uri]::TryCreate($pin.release_url, [System.UriKind]::Absolute, [ref]$releaseUri) -or $releaseUri.Scheme -ne 'https') {
        throw "Ghidra toolchain field 'release_url' must be an HTTPS URL: $ManifestPath"
    }
    if ([System.IO.Path]::GetFileName($pin.archive) -ne $pin.archive -or [System.IO.Path]::GetFileName($pin.home_directory) -ne $pin.home_directory) {
        throw "Ghidra toolchain archive and home_directory must be leaf names: $ManifestPath"
    }

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "pinned Ghidra archive is missing: $ArchivePath"
    }
    $archiveItem = Get-Item -LiteralPath $ArchivePath -Force
    if ($archiveItem.Name -ne $pin.archive) {
        throw "Ghidra archive name '$($archiveItem.Name)' does not match pinned '$($pin.archive)'"
    }
    if ($archiveItem.Length -ne $pin.archive_size_bytes) {
        throw "Ghidra archive size $($archiveItem.Length) does not match pinned $($pin.archive_size_bytes)"
    }
    $archiveHash = Get-GhidraHarnessHash -Path $archiveItem.FullName
    if ($archiveHash -ne $pin.archive_sha256.ToLowerInvariant()) {
        throw "Ghidra archive SHA-256 $archiveHash does not match pinned $($pin.archive_sha256.ToLowerInvariant())"
    }

    if (-not (Test-Path -LiteralPath $GhidraHome -PathType Container)) {
        throw "Ghidra home is missing: $GhidraHome"
    }
    $homeItem = Get-Item -LiteralPath $GhidraHome -Force
    if (($homeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Ghidra home cannot be a reparse point: $GhidraHome"
    }
    if ($homeItem.Name -ne $pin.home_directory) {
        throw "Ghidra home name '$($homeItem.Name)' does not match pinned '$($pin.home_directory)'"
    }
    $applicationProperties = Join-Path $homeItem.FullName 'Ghidra/application.properties'
    if (-not (Test-Path -LiteralPath $applicationProperties -PathType Leaf)) {
        throw "Ghidra application properties are missing: $applicationProperties"
    }
    $versionLine = Select-String -LiteralPath $applicationProperties -Pattern '^application\.version=' | Select-Object -First 1
    if ($null -eq $versionLine) {
        throw "Ghidra application properties do not declare application.version: $applicationProperties"
    }
    $installedVersion = ($versionLine.Line -split '=', 2)[1].Trim()
    if ($installedVersion -ne $pin.version) {
        throw "installed Ghidra version '$installedVersion' does not match pinned '$($pin.version)'"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($archiveItem.FullName)
    $expectedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $contentRecords = New-Object System.Collections.Generic.List[string]
    [long]$contentBytes = 0
    $homePrefix = $pin.home_directory + '/'
    $homePathPrefix = $homeItem.FullName.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    try {
        foreach ($entry in $archive.Entries) {
            $entryPath = $entry.FullName.Replace('\', '/')
            if (-not $entryPath.StartsWith($homePrefix, [System.StringComparison]::Ordinal)) {
                throw "Ghidra archive entry is outside pinned home '$($pin.home_directory)': $entryPath"
            }
            $relativePath = $entryPath.Substring($homePrefix.Length)
            if ([string]::IsNullOrEmpty($relativePath) -or $relativePath.EndsWith('/')) {
                continue
            }
            $installedPath = [System.IO.Path]::GetFullPath((Join-Path $homeItem.FullName $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)))
            if (-not $installedPath.StartsWith($homePathPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Ghidra archive entry escapes its pinned home: $entryPath"
            }
            if (-not $expectedFiles.Add($relativePath)) {
                throw "Ghidra archive contains a duplicate file entry: $entryPath"
            }
            if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
                throw "installed Ghidra file is missing: $relativePath"
            }
            $installedItem = Get-Item -LiteralPath $installedPath -Force
            if (($installedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "installed Ghidra file cannot be a reparse point: $relativePath"
            }
            if ($installedItem.Length -ne $entry.Length) {
                throw "installed Ghidra file size differs from the pinned archive: $relativePath"
            }
            $entryStream = $entry.Open()
            try {
                $entryHash = Get-GhidraHarnessStreamHash -Stream $entryStream
            } finally {
                $entryStream.Dispose()
            }
            $installedHash = Get-GhidraHarnessHash -Path $installedItem.FullName
            if ($installedHash -ne $entryHash) {
                throw "installed Ghidra file differs from the pinned archive: $relativePath"
            }
            $contentBytes += $entry.Length
            $contentRecords.Add("$relativePath`t$($entry.Length)`t$entryHash")
        }
    } finally {
        $archive.Dispose()
    }
    if ($expectedFiles.Count -eq 0) {
        throw 'pinned Ghidra archive contains no files'
    }

    $pending = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $pending.Push($homeItem)
    [int]$installedFileCount = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "installed Ghidra content cannot contain a reparse point: $($entry.FullName)"
            }
            if ($entry -is [System.IO.DirectoryInfo]) {
                $pending.Push($entry)
                continue
            }
            $installedFileCount++
            $relativePath = $entry.FullName.Substring($homePathPrefix.Length).Replace('\', '/')
            if (-not $expectedFiles.Contains($relativePath)) {
                throw "installed Ghidra contains a file absent from the pinned archive: $relativePath"
            }
        }
    }
    if ($installedFileCount -ne $expectedFiles.Count) {
        throw "installed Ghidra file count $installedFileCount does not match pinned archive count $($expectedFiles.Count)"
    }
    $contentRecords.Sort([System.StringComparer]::Ordinal)
    $contentHash = Get-GhidraHarnessTextHash -Text ($contentRecords -join "`n")

    return [pscustomobject]@{
        version = $pin.version
        manifest = [pscustomobject]@{ path = $manifestItem.FullName; sha256 = Get-GhidraHarnessHash -Path $manifestItem.FullName; schema = $manifest.schema }
        archive = [pscustomobject]@{ path = $archiveItem.FullName; name = $archiveItem.Name; size_bytes = $archiveItem.Length; sha256 = $archiveHash; release_url = $pin.release_url }
        installation = [pscustomobject]@{
            home = $homeItem.FullName
            verified_against_archive = $true
            file_count = $installedFileCount
            content_bytes = $contentBytes
            content_manifest_sha256 = $contentHash
            application_properties = [pscustomobject]@{ path = $applicationProperties; sha256 = Get-GhidraHarnessHash -Path $applicationProperties }
        }
    }
}

function Assert-GhidraHarnessRoster {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Corpus,
        [Parameter(Mandatory)][object[]]$Samples
    )

    $missing = New-Object System.Collections.Generic.List[string]
    $resolved = New-Object System.Collections.Generic.List[object]
    foreach ($sample in $Samples) {
        $path = Join-Path $Corpus $sample.rel
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $missing.Add("$($sample.id): $path")
            continue
        }
        $resolved.Add([pscustomobject]@{ sample = $sample; path = $path; sha256 = Get-GhidraHarnessHash -Path $path })
    }
    if ($missing.Count -gt 0) {
        throw "required benchmark fixtures are missing: $($missing -join '; ')"
    }
    return $resolved
}

function Write-GhidraHarnessResumeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('unpack', 'cleaner')][string]$Schema,
        [Parameter(Mandatory)][object[]]$Roster,
        [Parameter(Mandatory)][object]$Identity,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows
    )

    $state = [pscustomobject]@{
        schema = "disrobe.bench.resume/$Schema/v1"
        identity = $Identity
        roster = @($Roster | ForEach-Object { [pscustomobject]@{ id = $_.sample.id; fixture = $_.sample.rel; sha256 = $_.sha256 } })
        rows = @($Rows)
    }
    [System.IO.File]::WriteAllText($Path, ($state | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
}

function Read-GhidraHarnessResumeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('unpack', 'cleaner')][string]$Schema,
        [Parameter(Mandatory)][object[]]$Roster,
        [Parameter(Mandatory)][object]$Identity
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "resume state is missing: $Path"
    }
    $state = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($state.schema -ne "disrobe.bench.resume/$Schema/v1") {
        throw "resume state schema does not match $Schema"
    }
    if (($state.identity | ConvertTo-Json -Compress -Depth 10) -ne ($Identity | ConvertTo-Json -Compress -Depth 10)) {
        throw 'resume state measurement identity does not match current inputs'
    }
    $savedRoster = @($state.roster)
    if ($savedRoster.Count -ne $Roster.Count) {
        throw 'resume state roster count does not match current fixtures'
    }
    for ($index = 0; $index -lt $Roster.Count; $index++) {
        $expected = $Roster[$index]
        $actual = $savedRoster[$index]
        if ($actual.id -ne $expected.sample.id -or $actual.fixture -ne $expected.sample.rel -or $actual.sha256 -ne $expected.sha256) {
            throw "resume state fixture '$($expected.sample.id)' no longer matches its recorded input"
        }
    }
    return @($state.rows)
}

function Assert-GhidraHarnessResumeDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OwnerRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $rootItem = Get-Item -LiteralPath $OwnerRoot -ErrorAction Stop
    $targetItem = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or -not $targetItem.PSIsContainer) {
        throw 'resume directory and owner root must be directories'
    }
    if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint -or $targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'resume directory cannot use a reparse point'
    }
    $root = $rootItem.FullName.TrimEnd('\')
    $target = $targetItem.FullName.TrimEnd('\')
    if ($target -eq $root -or -not $target.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "resume directory '$target' is outside owner root '$root'"
    }
    return $target
}

function Initialize-GhidraHarnessOutputDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OwnerRoot,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')][string]$Name
    )

    if (-not (Test-Path -LiteralPath $OwnerRoot -PathType Container)) {
        throw "output owner root is not a directory: $OwnerRoot"
    }
    $rootItem = Get-Item -LiteralPath $OwnerRoot -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "output owner root cannot be a reparse point: $OwnerRoot"
    }
    $path = Join-Path $rootItem.FullName "$Name-$([Guid]::NewGuid().ToString('N'))"
    $directory = New-Item -ItemType Directory -Path $path
    return [pscustomobject]@{ path = $directory.FullName; owner_root = $rootItem.FullName; name = $Name }
}

function Assert-GhidraHarnessDirectorySize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$MaximumBytes
    )

    if ($MaximumBytes -le 0) {
        throw 'directory size ceiling must be greater than zero bytes'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "owned directory is missing: $Path"
    }
    $root = Get-Item -LiteralPath $Path -Force
    if (($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "owned directory cannot be a reparse point: $Path"
    }
    $pending = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $pending.Push($root)
    [long]$size = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "owned directory contains a reparse point: $($entry.FullName)"
            }
            if ($entry -is [System.IO.DirectoryInfo]) {
                $pending.Push($entry)
            } else {
                if ($entry.Length -gt ($MaximumBytes - $size)) {
                    throw "owned directory exceeds its $MaximumBytes byte ceiling: $Path"
                }
                $size += $entry.Length
            }
        }
    }
    return $size
}

function Remove-GhidraHarnessOutputDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerRoot
    )

    if (-not (Test-Path -LiteralPath $OwnerRoot -PathType Container)) {
        throw "cleanup owner root is not a directory: $OwnerRoot"
    }
    $rootItem = Get-Item -LiteralPath $OwnerRoot -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "cleanup owner root cannot be a reparse point: $OwnerRoot"
    }
    $root = $rootItem.FullName.TrimEnd([char[]]@('\', '/'))
    $target = [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\', '/'))
    $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
    if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "cleanup target is not a strict descendant of its owner root: $Path"
    }
    if (-not (Test-Path -LiteralPath $target)) {
        return
    }
    $targetItem = Get-Item -LiteralPath $target -Force
    if (($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "cleanup target cannot be a reparse point: $target"
    }
    $pending = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $directories = New-Object System.Collections.Generic.List[System.IO.DirectoryInfo]
    $pending.Push($targetItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $directories.Add($directory)
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                    [System.IO.Directory]::Delete($entry.FullName, $false)
                } else {
                    [System.IO.File]::Delete($entry.FullName)
                }
            } elseif ($entry -is [System.IO.DirectoryInfo]) {
                $pending.Push($entry)
            } else {
                $entry.IsReadOnly = $false
                $entry.Delete()
            }
        }
    }
    foreach ($directory in ($directories | Sort-Object { $_.FullName.Length } -Descending)) {
        $directory.Delete($false)
    }
    if (Test-Path -LiteralPath $target) {
        throw "owned output directory was not removed: $target"
    }
}

function Publish-GhidraHarnessResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$Markdown,
        [Parameter(Mandatory)][string[]]$EvidenceDirectories
    )

    $snapshotsRoot = Join-Path $OutputDirectory 'snapshots'
    if (-not (Test-Path -LiteralPath $snapshotsRoot)) {
        New-Item -ItemType Directory -Path $snapshotsRoot | Out-Null
    }
    $snapshotsRootItem = Get-Item -LiteralPath $snapshotsRoot -Force
    if ($snapshotsRootItem -isnot [System.IO.DirectoryInfo] -or ($snapshotsRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "snapshot root must be a regular directory: $snapshotsRoot"
    }
    $snapshotId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [Guid]::NewGuid().ToString('N')
    $snapshotPath = Join-Path $snapshotsRootItem.FullName $snapshotId
    $stage = Initialize-GhidraHarnessOutputDirectory -OwnerRoot $snapshotsRootItem.FullName -Name 'stage'
    $pointerPath = Join-Path $OutputDirectory 'current.json'
    $pointerTemporaryPath = Join-Path $OutputDirectory "current-$snapshotId.tmp"
    $committed = $false
    try {
        $stageJson = Join-Path $stage.path 'results.json'
        $stageMarkdown = Join-Path $stage.path 'results.md'
        $stageEvidence = Join-Path $stage.path 'raw-evidence'
        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($stageJson, $Json, $encoding)
        [System.IO.File]::WriteAllText($stageMarkdown, $Markdown, $encoding)
        New-Item -ItemType Directory -Path $stageEvidence | Out-Null
        $evidenceNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($directory in $EvidenceDirectories) {
            Assert-GhidraHarnessDirectorySize -Path $directory -MaximumBytes ([long]::MaxValue) | Out-Null
            $name = Split-Path -Leaf $directory
            if (-not $evidenceNames.Add($name)) {
                throw "raw evidence directory name is duplicated: $name"
            }
            Copy-Item -LiteralPath $directory -Destination $stageEvidence -Recurse
        }
        $manifestFiles = @(Get-ChildItem -LiteralPath $stage.path -Recurse -File | Sort-Object FullName | ForEach-Object {
            [pscustomobject]@{ path = $_.FullName.Substring($stage.path.Length + 1).Replace('\', '/'); sha256 = Get-GhidraHarnessHash -Path $_.FullName; size_bytes = $_.Length }
        })
        $manifestPath = Join-Path $stage.path 'manifest.json'
        $manifest = [pscustomobject]@{ schema = 'disrobe.bench.snapshot/v1'; snapshot = $snapshotId; files = $manifestFiles }
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), $encoding)
        [System.IO.Directory]::Move($stage.path, $snapshotPath)

        $snapshotRelativePath = "snapshots/$snapshotId"
        $pointer = [pscustomobject]@{
            schema = 'disrobe.bench.current/v1'
            snapshot = $snapshotRelativePath
            manifest = "$snapshotRelativePath/manifest.json"
            manifest_sha256 = Get-GhidraHarnessHash -Path (Join-Path $snapshotPath 'manifest.json')
            results_json = "$snapshotRelativePath/results.json"
            results_markdown = "$snapshotRelativePath/results.md"
        }
        [System.IO.File]::WriteAllText($pointerTemporaryPath, ($pointer | ConvertTo-Json -Depth 3), $encoding)
        if (Test-Path -LiteralPath $pointerPath) {
            $pointerItem = Get-Item -LiteralPath $pointerPath -Force
            if ($pointerItem -isnot [System.IO.FileInfo] -or ($pointerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "current result pointer must be a regular file: $pointerPath"
            }
            [System.IO.File]::Replace($pointerTemporaryPath, $pointerPath, $null)
        } else {
            [System.IO.File]::Move($pointerTemporaryPath, $pointerPath)
        }
        $committed = $true
        return [pscustomobject]@{
            pointer = $pointerPath
            directory = $snapshotPath
            json = Join-Path $snapshotPath 'results.json'
            markdown = Join-Path $snapshotPath 'results.md'
            manifest = Join-Path $snapshotPath 'manifest.json'
        }
    } finally {
        if (Test-Path -LiteralPath $pointerTemporaryPath -PathType Leaf) { [System.IO.File]::Delete($pointerTemporaryPath) }
        if (Test-Path -LiteralPath $stage.path -PathType Container) { Remove-GhidraHarnessOutputDirectory -Path $stage.path -OwnerRoot $snapshotsRootItem.FullName }
        if (-not $committed -and (Test-Path -LiteralPath $snapshotPath -PathType Container)) { Remove-GhidraHarnessOutputDirectory -Path $snapshotPath -OwnerRoot $snapshotsRootItem.FullName }
    }
}

function Get-GhidraHarnessExportArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExportDirectory)

    $artifacts = @(Get-ChildItem -LiteralPath $ExportDirectory -File -Filter '*.unpacked.exe' | Sort-Object FullName)
    if ($artifacts.Count -ne 1) {
        throw "expected exactly one rebuilt *.unpacked.exe under $ExportDirectory; found $($artifacts.Count)"
    }
    return [pscustomobject]@{ path = $artifacts[0].FullName; sha256 = Get-GhidraHarnessHash -Path $artifacts[0].FullName }
}

function ConvertTo-GhidraHarnessArgument {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function ConvertTo-GhidraHarnessBatchArgument {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)

    if ($Value.Contains('"') -or $Value.Contains('%') -or $Value.Contains('!') -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw 'Windows batch arguments cannot contain quotes, percent signs, exclamation marks, or line breaks'
    }
    return $Value
}

function Stop-GhidraHarnessProcessTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$FilePath
    )

    $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    if (-not (Test-Path -LiteralPath $taskKill -PathType Leaf)) {
        throw "taskkill is unavailable; cannot terminate owned process tree for $FilePath"
    }
    $killStart = [System.Diagnostics.ProcessStartInfo]::new()
    $killStart.FileName = $taskKill
    $killStart.Arguments = "/F /T /PID $($Process.Id)"
    $killStart.UseShellExecute = $false
    $killStart.CreateNoWindow = $true
    $kill = [System.Diagnostics.Process]::new()
    $kill.StartInfo = $killStart
    try {
        if (-not $kill.Start()) {
            throw "failed to start process-tree cleanup for pid $($Process.Id)"
        }
        if (-not $kill.WaitForExit(5000)) {
            $kill.Kill()
            if (-not $kill.WaitForExit(1000)) {
                throw "process-tree cleanup command could not be stopped for pid $($Process.Id)"
            }
            throw "process-tree cleanup timed out for pid $($Process.Id)"
        }
        if ($kill.ExitCode -ne 0) {
            throw "process-tree cleanup failed with exit code $($kill.ExitCode) for pid $($Process.Id)"
        }
    } finally {
        $kill.Dispose()
    }
    if (-not $Process.WaitForExit(5000)) {
        throw "owned process tree did not terminate within five seconds (pid $($Process.Id))"
    }
}

function Invoke-GhidraHarnessProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [string]$StructuredOutputPath,
        [long]$MaximumStructuredOutputBytes = 0
    )

    if ($TimeoutSeconds -le 0) {
        throw 'timeout must be greater than zero seconds'
    }
    $captureStructuredOutput = -not [string]::IsNullOrWhiteSpace($StructuredOutputPath)
    if ($captureStructuredOutput) {
        if ($MaximumStructuredOutputBytes -le 0) {
            throw 'structured process output requires a positive byte ceiling'
        }
        $structuredOutputFullPath = [System.IO.Path]::GetFullPath($StructuredOutputPath)
        if ([string]::Equals($structuredOutputFullPath, [System.IO.Path]::GetFullPath($LogPath), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'structured process output and diagnostic log must use different paths'
        }
        $structuredOutputParent = Get-Item -LiteralPath ([System.IO.Path]::GetDirectoryName($structuredOutputFullPath)) -Force
        if ($structuredOutputParent -isnot [System.IO.DirectoryInfo] -or ($structuredOutputParent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "structured process output parent must be a non-reparse directory: $($structuredOutputParent.FullName)"
        }
        if ((Test-Path -LiteralPath $structuredOutputFullPath) -and ((Get-Item -LiteralPath $structuredOutputFullPath -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "structured process output cannot be a reparse point: $structuredOutputFullPath"
        }
    }
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    if ([System.IO.Path]::GetExtension($FilePath) -in @('.bat', '.cmd')) {
        if ($FilePath.Contains('"') -or $FilePath.Contains('%') -or $FilePath.Contains('!') -or $FilePath.Contains("`r") -or $FilePath.Contains("`n")) {
            throw "invalid Windows batch script path: $FilePath"
        }
        $start.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
        $batchVariable = 'DISROBE_GHIDRA_HARNESS_BATCH'
        $start.EnvironmentVariables[$batchVariable] = $FilePath
        $argumentReferences = New-Object System.Collections.Generic.List[string]
        for ($index = 0; $index -lt $ArgumentList.Count; $index++) {
            $value = ConvertTo-GhidraHarnessBatchArgument -Value $ArgumentList[$index]
            $name = "DISROBE_GHIDRA_HARNESS_ARG_$index"
            $start.EnvironmentVariables[$name] = $value
            $argumentReferences.Add('"%' + $name + '%"')
        }
        $command = '"%' + $batchVariable + '%" ' + ($argumentReferences -join ' ')
        $start.Arguments = "/d /q /v:off /s /c `"$command`""
    } else {
        $start.FileName = $FilePath
        $start.Arguments = @($ArgumentList | ForEach-Object { ConvertTo-GhidraHarnessArgument -Value $_ }) -join ' '
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "failed to start trusted analyzer: $FilePath"
        }
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($captureStructuredOutput) {
            try {
                $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
                $writer = [System.IO.File]::Open($structuredOutputFullPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                $buffer = New-Object byte[] 4096
                $timedOut = $false
                $tooLarge = $false
                try {
                    while ($true) {
                        $remainingMilliseconds = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                        if ($remainingMilliseconds -le 0) {
                            $timedOut = $true
                            break
                        }
                        $read = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
                        if (-not $read.Wait($remainingMilliseconds)) {
                            $timedOut = $true
                            break
                        }
                        $readCount = $read.GetAwaiter().GetResult()
                        if ($readCount -eq 0) {
                            break
                        }
                        $writer.Write($buffer, 0, $readCount)
                        $writer.Flush()
                        if ($writer.Length -gt $MaximumStructuredOutputBytes) {
                            $tooLarge = $true
                            break
                        }
                    }
                } finally {
                    $writer.Dispose()
                }
                if ($timedOut -or $tooLarge) {
                    if ($timedOut -or -not $process.WaitForExit(1000)) {
                        Stop-GhidraHarnessProcessTree -Process $process -FilePath $FilePath
                    }
                    $diagnostics = $stderr.GetAwaiter().GetResult()
                    [System.IO.File]::Delete($structuredOutputFullPath)
                    if ($tooLarge) {
                        [System.IO.File]::WriteAllText($LogPath, $diagnostics + "`nstructured output exceeded $MaximumStructuredOutputBytes bytes`n", [System.Text.UTF8Encoding]::new($false))
                        throw "trusted analyzer structured output exceeds its $MaximumStructuredOutputBytes byte ceiling (see $LogPath)"
                    }
                    [System.IO.File]::WriteAllText($LogPath, $diagnostics + "`ntimeout after $TimeoutSeconds seconds`n", [System.Text.UTF8Encoding]::new($false))
                    throw "trusted analyzer timed out after $TimeoutSeconds seconds (see $LogPath)"
                }
                $remainingMilliseconds = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                if ($remainingMilliseconds -le 0 -or -not $process.WaitForExit($remainingMilliseconds)) {
                    Stop-GhidraHarnessProcessTree -Process $process -FilePath $FilePath
                    $diagnostics = $stderr.GetAwaiter().GetResult()
                    [System.IO.File]::Delete($structuredOutputFullPath)
                    [System.IO.File]::WriteAllText($LogPath, $diagnostics + "`ntimeout after $TimeoutSeconds seconds`n", [System.Text.UTF8Encoding]::new($false))
                    throw "trusted analyzer timed out after $TimeoutSeconds seconds (see $LogPath)"
                }
                $diagnostics = $stderr.GetAwaiter().GetResult()
                [System.IO.File]::WriteAllText($LogPath, $diagnostics, [System.Text.UTF8Encoding]::new($false))
                return [pscustomobject]@{
                    pid = $process.Id
                    exit_code = $process.ExitCode
                    log = $LogPath
                    log_sha256 = Get-GhidraHarnessHash -Path $LogPath
                    structured_output = $structuredOutputFullPath
                    structured_output_sha256 = Get-GhidraHarnessHash -Path $structuredOutputFullPath
                }
            } catch {
                $captureFailure = $_
                try {
                    if (-not $process.HasExited) {
                        Stop-GhidraHarnessProcessTree -Process $process -FilePath $FilePath
                    }
                } finally {
                    [System.IO.File]::Delete($structuredOutputFullPath)
                }
                throw $captureFailure
            }
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-GhidraHarnessProcessTree -Process $process -FilePath $FilePath
            $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
            [System.IO.File]::WriteAllText($LogPath, $output + "`ntimeout after $TimeoutSeconds seconds`n", [System.Text.UTF8Encoding]::new($false))
            throw "trusted analyzer timed out after $TimeoutSeconds seconds (see $LogPath)"
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($LogPath, $output, [System.Text.UTF8Encoding]::new($false))
        return [pscustomobject]@{ pid = $process.Id; exit_code = $process.ExitCode; log = $LogPath; log_sha256 = Get-GhidraHarnessHash -Path $LogPath }
    } finally {
        $process.Dispose()
    }
}

function Read-GhidraHarnessReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('unpack', 'cleaner')][string]$Schema
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "analyzer did not produce a report: $Path"
    }
    try {
        $report = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    } catch {
        throw "analyzer report is not valid JSON at ${Path}: $($_.Exception.Message)"
    }
    if ($null -eq $report -or $report -is [array] -or $report.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        throw "analyzer report must be a JSON object at $Path"
    }
    if ($null -eq $report.PSObject.Properties['runtime'] -or $null -eq $report.runtime -or $report.runtime.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        throw "analyzer report field 'runtime' must be a JSON object at $Path"
    }
    foreach ($field in @('ghidra_version', 'java_home', 'java_version', 'java_vendor', 'java_vm_name')) {
        if ($null -eq $report.runtime.PSObject.Properties[$field]) {
            throw "analyzer report runtime is missing required field '$field' at $Path"
        }
        if ($report.runtime.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($report.runtime.$field)) {
            throw "analyzer report runtime field '$field' must be a non-empty string at $Path"
        }
    }
    if (-not [System.IO.Path]::IsPathRooted($report.runtime.java_home)) {
        throw "analyzer report runtime field 'java_home' must be an absolute path at $Path"
    }
    $fields = if ($Schema -eq 'unpack') {
        @('program', 'language', 'image_base', 'functions', 'thunks', 'instructions', 'defined_strings', 'resolved_imports', 'executable_bytes', 'decompile_attempts', 'decompiled_ok')
    } else {
        @('program', 'language', 'image_base', 'functions', 'thunks', 'instructions', 'instruction_bytes', 'defined_data_bytes', 'defined_bytes', 'defined_strings', 'undefined_in_exec', 'executable_block_bytes', 'total_block_bytes')
    }
    foreach ($field in $fields) {
        if ($null -eq $report.PSObject.Properties[$field]) {
            throw "analyzer report is missing required field '$field' at $Path"
        }
    }
    foreach ($field in @('program', 'language', 'image_base')) {
        if ($report.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($report.$field)) {
            throw "analyzer report field '$field' must be a non-empty string at $Path"
        }
    }
    if ($report.image_base -notmatch '^(?:0[xX])?[0-9A-Fa-f]+$') {
        throw "analyzer report field 'image_base' must be a hexadecimal address at $Path"
    }
    foreach ($field in $fields | Where-Object { $_ -notin @('program', 'language', 'image_base') }) {
        $value = $report.$field
        if ($value -isnot [int64] -and $value -isnot [int32]) {
            throw "analyzer report field '$field' must be an integer at $Path"
        }
        if ($value -lt 0) {
            throw "analyzer report field '$field' must be nonnegative at $Path"
        }
    }
    if ($Schema -eq 'unpack') {
        if ($report.thunks -gt $report.functions -or $report.decompile_attempts -gt $report.functions -or $report.decompiled_ok -gt $report.decompile_attempts) {
            throw "analyzer unpack report has inconsistent function or decompilation counts at $Path"
        }
    } elseif ($report.defined_bytes -ne ($report.instruction_bytes + $report.defined_data_bytes) -or $report.executable_block_bytes -gt $report.total_block_bytes) {
        throw "analyzer cleaner report has inconsistent byte counts at $Path"
    }
    return $report
}

function Invoke-GhidraHarnessMeasurement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][ValidateSet('unpack', 'cleaner')][string]$Schema,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    if (Test-Path -LiteralPath $ReportPath) {
        throw "report path must not already exist: $ReportPath"
    }
    $outcome = Invoke-GhidraHarnessProcess -FilePath $FilePath -ArgumentList $ArgumentList -LogPath $LogPath -TimeoutSeconds $TimeoutSeconds
    if ($outcome.exit_code -ne 0) {
        throw "analyzer failed with exit code $($outcome.exit_code) (see $LogPath)"
    }
    $report = Read-GhidraHarnessReport -Path $ReportPath -Schema $Schema
    return [pscustomobject]@{ report = $report; outcome = $outcome; report_path = $ReportPath; report_sha256 = Get-GhidraHarnessHash -Path $ReportPath }
}

function Get-GhidraHarnessSourceProvenance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $maximumDiffBytes = 32MB
    $maximumPathListBytes = 4MB
    $maximumUntrackedFiles = 4096
    $maximumUntrackedFileBytes = 256MB
    $maximumUntrackedBytes = 1GB
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if (-not $git) {
        throw 'git.exe is required to capture benchmark source provenance'
    }
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        throw "source provenance log directory is missing: $LogDirectory"
    }
    $revisionLog = Join-Path $LogDirectory 'git-revision.log'
    $revisionPath = Join-Path $LogDirectory 'git-revision.txt'
    $diffPath = Join-Path $LogDirectory 'git-diff-head.patch'
    $diffLog = Join-Path $LogDirectory 'git-diff-head.log'
    $untrackedPathList = Join-Path $LogDirectory 'git-untracked-paths.bin'
    $untrackedLog = Join-Path $LogDirectory 'git-untracked-paths.log'
    $revisionOutcome = Invoke-GhidraHarnessProcess -FilePath $git.Source -ArgumentList @('-C', $RepositoryRoot, 'rev-parse', 'HEAD') -LogPath $revisionLog -TimeoutSeconds $TimeoutSeconds -StructuredOutputPath $revisionPath -MaximumStructuredOutputBytes 128
    $diffOutcome = Invoke-GhidraHarnessProcess -FilePath $git.Source -ArgumentList @('-C', $RepositoryRoot, '-c', 'core.quotepath=false', 'diff', '--no-ext-diff', '--binary', "--output=$diffPath", 'HEAD', '--', '.') -LogPath $diffLog -TimeoutSeconds $TimeoutSeconds
    $untrackedOutcome = Invoke-GhidraHarnessProcess -FilePath $git.Source -ArgumentList @('-C', $RepositoryRoot, 'ls-files', '--others', '--exclude-standard', '-z', '--', '.') -LogPath $untrackedLog -TimeoutSeconds $TimeoutSeconds -StructuredOutputPath $untrackedPathList -MaximumStructuredOutputBytes $maximumPathListBytes
    foreach ($capture in @(
        [pscustomobject]@{ name = 'revision'; outcome = $revisionOutcome }
        [pscustomobject]@{ name = 'diff'; outcome = $diffOutcome }
        [pscustomobject]@{ name = 'untracked paths'; outcome = $untrackedOutcome }
    )) {
        if ($capture.outcome.exit_code -ne 0) {
            throw "git source $($capture.name) capture exited $($capture.outcome.exit_code) (see $($capture.outcome.log))"
        }
    }
    $revision = ([System.IO.File]::ReadAllText($revisionPath, [System.Text.Encoding]::UTF8)).Trim()
    if ($revision -notmatch '^[0-9a-fA-F]{40,64}$') {
        throw "git source revision capture did not produce an object ID: $revisionLog"
    }
    $diffItem = Get-Item -LiteralPath $diffPath
    if ($diffItem.Length -gt $maximumDiffBytes) {
        [System.IO.File]::Delete($diffPath)
        throw "git source diff exceeds its $maximumDiffBytes byte ceiling: $diffPath"
    }
    $pathListItem = Get-Item -LiteralPath $untrackedPathList
    if ($pathListItem.Length -gt $maximumPathListBytes) {
        throw "git untracked path list exceeds its $maximumPathListBytes byte ceiling: $untrackedPathList"
    }

    $rootItem = Get-Item -LiteralPath $RepositoryRoot -Force
    if ($rootItem -isnot [System.IO.DirectoryInfo] -or ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "source repository root must be a non-reparse directory: $RepositoryRoot"
    }
    $rootPrefix = $rootItem.FullName.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    $rawPaths = [System.IO.File]::ReadAllText($untrackedPathList, [System.Text.Encoding]::UTF8)
    [string[]]$untrackedPaths = @($rawPaths.Split([char[]]@([char]0), [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($untrackedPaths.Count -gt $maximumUntrackedFiles) {
        throw "git source capture found $($untrackedPaths.Count) untracked files; the ceiling is $maximumUntrackedFiles"
    }
    [System.Array]::Sort($untrackedPaths, [System.StringComparer]::Ordinal)
    $records = New-Object System.Collections.Generic.List[object]
    [long]$untrackedBytes = 0
    foreach ($relativePath in $untrackedPaths) {
        $normalizedPath = $relativePath.Replace('\', '/')
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $rootItem.FullName $normalizedPath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)))
        if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "untracked source path escapes the repository root: $normalizedPath"
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "untracked source file disappeared during capture: $normalizedPath"
        }
        $item = Get-Item -LiteralPath $fullPath -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "untracked source file cannot be a reparse point: $normalizedPath"
        }
        if ($item.Length -gt $maximumUntrackedFileBytes) {
            throw "untracked source file exceeds its $maximumUntrackedFileBytes byte ceiling: $normalizedPath"
        }
        if ($item.Length -gt ($maximumUntrackedBytes - $untrackedBytes)) {
            throw "untracked source files exceed their $maximumUntrackedBytes byte ceiling"
        }
        $untrackedBytes += $item.Length
        $records.Add([pscustomobject]@{ path = $normalizedPath; size_bytes = $item.Length; sha256 = Get-GhidraHarnessHash -Path $item.FullName })
    }
    $manifestPath = Join-Path $LogDirectory 'git-untracked-manifest.json'
    $manifestJson = ConvertTo-Json -InputObject ($records.ToArray()) -Depth 3
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson + "`n", [System.Text.UTF8Encoding]::new($false))
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 4MB) {
        throw "git untracked manifest exceeds its 4194304 byte ceiling: $manifestPath"
    }
    $diffHash = Get-GhidraHarnessHash -Path $diffPath
    $manifestHash = Get-GhidraHarnessHash -Path $manifestPath
    [System.IO.File]::Delete($untrackedPathList)
    $identityHash = Get-GhidraHarnessTextHash -Text "$revision`n$diffHash`n$manifestHash"
    return [pscustomobject]@{
        revision = $revision.ToLowerInvariant()
        dirty = [bool]$rawPaths -or $diffItem.Length -gt 0
        identity_sha256 = $identityHash
        tracked_diff = [pscustomobject]@{ path = $diffPath; size_bytes = $diffItem.Length; sha256 = $diffHash }
        untracked_manifest = [pscustomobject]@{ path = $manifestPath; file_count = $records.Count; content_bytes = $untrackedBytes; sha256 = $manifestHash }
    }
}

function Get-GhidraHarnessProvenance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Disrobe,
        [Parameter(Mandatory)][string]$Analyzer,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$PostScriptPath,
        [Parameter(Mandatory)][string]$LogDirectory,
        [Parameter(Mandatory)][object]$Toolchain,
        [Parameter(Mandatory)][object[]]$Reports,
        [Parameter(Mandatory)][string]$ExportCommand,
        [Parameter(Mandatory)][string]$HeadlessCommand,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $source = Get-GhidraHarnessSourceProvenance -RepositoryRoot $RepositoryRoot -LogDirectory $LogDirectory -TimeoutSeconds $TimeoutSeconds
    $versionLog = Join-Path $LogDirectory 'disrobe-version.log'
    $versionOutcome = Invoke-GhidraHarnessProcess -FilePath $Disrobe -ArgumentList @('--version') -LogPath $versionLog -TimeoutSeconds $TimeoutSeconds
    if ($versionOutcome.exit_code -ne 0) {
        throw "disrobe --version exited $($versionOutcome.exit_code) (see $versionLog)"
    }
    $disrobeVersion = Get-Content -LiteralPath $versionLog | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($disrobeVersion)) {
        throw "disrobe --version produced no version string (see $versionLog)"
    }

    if ($Reports.Count -eq 0) {
        throw 'benchmark provenance requires at least one analyzer report'
    }
    $runtime = $Reports[0].runtime
    foreach ($report in $Reports) {
        foreach ($field in @('ghidra_version', 'java_home', 'java_version', 'java_vendor', 'java_vm_name')) {
            if (-not [string]::Equals($report.runtime.$field, $runtime.$field, [System.StringComparison]::Ordinal)) {
                throw "analyzer reports disagree on runtime field '$field'"
            }
        }
    }
    if ($runtime.ghidra_version -ne $Toolchain.version) {
        throw "running Ghidra version '$($runtime.ghidra_version)' does not match pinned '$($Toolchain.version)'"
    }
    $javaExecutable = Join-Path $runtime.java_home 'bin/java.exe'
    if (-not (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) {
        $javaExecutable = Join-Path $runtime.java_home 'bin/java'
    }
    if (-not (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) {
        throw "running JVM reported a java.home without a Java executable: $($runtime.java_home)"
    }
    $javaItem = Get-Item -LiteralPath $javaExecutable -Force
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    } catch {
        throw "failed to capture measurement host hardware: $($_.Exception.Message)"
    }
    if ($processors.Count -eq 0 -or $computerSystem.TotalPhysicalMemory -le 0) {
        throw 'measurement host hardware capture returned incomplete data'
    }
    [int]$physicalCores = ($processors | Measure-Object -Property NumberOfCores -Sum).Sum
    [int]$logicalProcessors = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $cpuModel = (@($processors | ForEach-Object { $_.Name.Trim() } | Sort-Object -Unique) -join '; ')
    if ($physicalCores -le 0 -or $logicalProcessors -le 0 -or [string]::IsNullOrWhiteSpace($cpuModel)) {
        throw 'measurement host CPU capture returned incomplete data'
    }
    $verification = [pscustomobject]@{
        status = 'verified'
        supports_verified_measurement = $true
        reasons = @()
    }
    return [pscustomobject]@{
        utc = [DateTime]::UtcNow.ToString('o')
        source = $source
        host = [pscustomobject]@{
            name = $env:COMPUTERNAME
            os = [Environment]::OSVersion.VersionString
            powershell = $PSVersionTable.PSVersion.ToString()
            cpu = [pscustomobject]@{ model = $cpuModel; packages = $processors.Count; physical_cores = $physicalCores; logical_processors = $logicalProcessors }
            physical_memory_bytes = [long]$computerSystem.TotalPhysicalMemory
        }
        tools = [pscustomobject]@{
            disrobe = [pscustomobject]@{ path = $Disrobe; sha256 = Get-GhidraHarnessHash -Path $Disrobe; version = $disrobeVersion.Trim(); version_outcome = $versionOutcome }
            analyze_headless = [pscustomobject]@{ path = $Analyzer; sha256 = Get-GhidraHarnessHash -Path $Analyzer; version = $runtime.ghidra_version }
            ghidra_selected_jvm = [pscustomobject]@{
                verified = $true
                home = $runtime.java_home
                executable = $javaItem.FullName
                executable_sha256 = Get-GhidraHarnessHash -Path $javaItem.FullName
                version = $runtime.java_version
                vendor = $runtime.java_vendor
                vm_name = $runtime.java_vm_name
                launch_environment_java_home = $env:JAVA_HOME
            }
        }
        harness = [pscustomobject]@{
            script = [pscustomobject]@{ path = $ScriptPath; sha256 = Get-GhidraHarnessHash -Path $ScriptPath }
            module = [pscustomobject]@{ path = $PSCommandPath; sha256 = Get-GhidraHarnessHash -Path $PSCommandPath }
            post_script = [pscustomobject]@{ path = $PostScriptPath; sha256 = Get-GhidraHarnessHash -Path $PostScriptPath }
            export_command = $ExportCommand
            headless_command = $HeadlessCommand
            timeout_seconds = $TimeoutSeconds
            ghidra_distribution = $Toolchain
        }
        verification = $verification
    }
}

Export-ModuleMember -Function Get-GhidraHarnessHash, Assert-GhidraHarnessToolchain, Assert-GhidraHarnessRoster, Write-GhidraHarnessResumeState, Read-GhidraHarnessResumeState, Assert-GhidraHarnessResumeDirectory, Initialize-GhidraHarnessOutputDirectory, Assert-GhidraHarnessDirectorySize, Remove-GhidraHarnessOutputDirectory, Publish-GhidraHarnessResults, Get-GhidraHarnessExportArtifact, Invoke-GhidraHarnessProcess, Read-GhidraHarnessReport, Invoke-GhidraHarnessMeasurement, Get-GhidraHarnessSourceProvenance, Get-GhidraHarnessProvenance
