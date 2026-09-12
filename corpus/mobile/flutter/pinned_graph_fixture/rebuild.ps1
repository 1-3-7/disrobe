param(
    [string]$Flutter = "flutter",
    [string]$Cargo = "cargo",
    [string]$Workspace = (Join-Path ([System.IO.Path]::GetTempPath()) ("pinned-dart-graph-flutter-" + [System.Guid]::NewGuid().ToString("N")))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (Test-Path -LiteralPath $Workspace) {
    throw "Workspace already exists: $Workspace"
}

$fixtureRoot = $PSScriptRoot
$oraclePath = Join-Path $fixtureRoot "oracle.json"
$oracle = Get-Content -LiteralPath $oraclePath -Raw | ConvertFrom-Json
$version = (& $Flutter --version --machine | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) {
    throw "Flutter version query failed"
}
if ($version.frameworkRevision -ne $oracle.flutter_framework_revision) {
    throw "Flutter framework revision does not match oracle.json"
}
if ($version.flutterVersion -ne $oracle.flutter_version) {
    throw "Flutter version does not match oracle.json"
}
if ($version.channel -ne $oracle.flutter_channel) {
    throw "Flutter channel does not match oracle.json"
}
if ($version.engineRevision -ne $oracle.flutter_engine_revision) {
    throw "Flutter engine revision does not match oracle.json"
}
if ($version.dartSdkVersion -ne $oracle.dart_version) {
    throw "Dart version does not match oracle.json"
}

& $Flutter create --empty --platforms android --org dev.disrobe --project-name disrobe_dart_fixture $Workspace
if ($LASTEXITCODE -ne 0) {
    throw "Flutter project creation failed"
}

Copy-Item -LiteralPath (Join-Path $fixtureRoot "pubspec.yaml") -Destination (Join-Path $Workspace "pubspec.yaml") -Force
$outputRoot = Join-Path $Workspace "recovered-fixtures"
New-Item -ItemType Directory -Path $outputRoot | Out-Null

function Export-Libapp {
    param(
        [object]$Build,
        [string[]]$Arguments
    )

    Copy-Item -LiteralPath (Join-Path $fixtureRoot $Build.source) -Destination (Join-Path $Workspace "lib/main.dart") -Force
    Push-Location $Workspace
    try {
        & $Flutter @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter build failed: $($Build.name)"
        }
    } finally {
        Pop-Location
    }

    $apkPath = Join-Path $Workspace "build/app/outputs/flutter-apk/app-release.apk"
    $destination = Join-Path $outputRoot $Build.artifact
    $archive = [System.IO.Compression.ZipFile]::OpenRead($apkPath)
    try {
        $entry = $archive.GetEntry("lib/arm64-v8a/libapp.so")
        if ($null -eq $entry) {
            throw "arm64 libapp.so is absent from the release APK"
        }
        $inputStream = $entry.Open()
        $outputStream = [System.IO.File]::Create($destination)
        try {
            $inputStream.CopyTo($outputStream)
        } finally {
            $outputStream.Dispose()
            $inputStream.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

$sourceBuild = $oracle.builds | Where-Object { $_.name -eq "source" }
$renamedBuild = $oracle.builds | Where-Object { $_.name -eq "renamed" }
$obfuscatedBuild = $oracle.builds | Where-Object { $_.name -eq "obfuscated" }

Export-Libapp -Build $sourceBuild -Arguments @("build", "apk", "--release")
Export-Libapp -Build $renamedBuild -Arguments @("build", "apk", "--release")
Export-Libapp -Build $obfuscatedBuild -Arguments @("build", "apk", "--release", "--obfuscate", "--split-debug-info=build/symbols")

foreach ($build in $oracle.builds) {
    $artifactPath = Join-Path $outputRoot $build.artifact
    $actual = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $build.sha256) {
        throw "Artifact hash mismatch: $($build.artifact)"
    }
}

function Get-DeclaredTotal {
    param(
        [object[]]$Clusters,
        [string]$Layout
    )

    $total = 0
    foreach ($cluster in $Clusters) {
        if ($cluster.kind -eq $Layout) {
            $total += $cluster.object_count
        }
    }
    return $total
}

function Assert-Count {
    param(
        [string]$Artifact,
        [string]$Field,
        [int]$Actual,
        [int]$Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Artifact reports $Field = $Actual, oracle.json records $Expected"
    }
}

$repoRoot = (Resolve-Path (Join-Path $fixtureRoot "../../../..")).Path
$inventoryDir = Join-Path $Workspace "recovered-inventory"
New-Item -ItemType Directory -Path $inventoryDir | Out-Null
foreach ($build in $oracle.builds) {
    $artifactPath = Join-Path $outputRoot $build.artifact
    $inventoryPath = Join-Path $inventoryDir "$($build.name).json"
    & $Cargo run --quiet --manifest-path (Join-Path $repoRoot "Cargo.toml") -p disrobe-cli --bin disrobe -- `
        flutter inventory --names $build.names --out $inventoryPath $artifactPath
    if ($LASTEXITCODE -ne 0) {
        throw "Recovery failed: $($build.artifact)"
    }
    $report = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json

    $vmClusters = $report.vm_snapshot.clusters
    $isolateClusters = $report.isolate_snapshot.clusters
    if ($null -eq $vmClusters -or $null -eq $isolateClusters) {
        throw "$($build.artifact) recovered without cluster headers, so its counts cannot be re-derived"
    }

    $declaredLayouts = [ordered]@{
        "library"     = "libraries"
        "class"       = "classes"
        "patch-class" = "patch_classes"
        "function"    = "functions"
        "field"       = "fields"
    }
    foreach ($layout in $declaredLayouts.Keys) {
        $key = $declaredLayouts[$layout]
        Assert-Count -Artifact $build.artifact -Field "declared.vm.$key" `
            -Actual (Get-DeclaredTotal -Clusters $vmClusters -Layout $layout) -Expected $build.declared.vm.$key
        Assert-Count -Artifact $build.artifact -Field "declared.isolate.$key" `
            -Actual (Get-DeclaredTotal -Clusters $isolateClusters -Layout $layout) -Expected $build.declared.isolate.$key
    }

    Assert-Count -Artifact $build.artifact -Field "libraries" -Actual $report.inventory.counts.libraries -Expected $build.libraries
    Assert-Count -Artifact $build.artifact -Field "classes" -Actual $report.inventory.counts.classes -Expected $build.classes
    Assert-Count -Artifact $build.artifact -Field "methods" -Actual $report.inventory.counts.methods -Expected $build.methods
    Assert-Count -Artifact $build.artifact -Field "fields" -Actual $report.inventory.counts.fields -Expected $build.fields

    foreach ($key in @("unattributed_classes", "unattributed_methods", "unattributed_fields", "synthesized_libraries")) {
        Assert-Count -Artifact $build.artifact -Field "attribution_residue.$key" `
            -Actual $report.inventory.residue.$key -Expected $build.attribution_residue.$key
    }
}

Write-Output $outputRoot
