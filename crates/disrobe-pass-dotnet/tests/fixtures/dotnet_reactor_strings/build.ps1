$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$expectedSdk = '9.0.314'
$actualSdk = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSdk -ne $expectedSdk) {
    throw "dotnet SDK $expectedSdk required, found $actualSdk"
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$work = [IO.Path]::GetFullPath((Join-Path $tempRoot "disrobe-reactor-string-fixture-$([Guid]::NewGuid().ToString('N'))"))
if (-not $work.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary work path escaped the system temporary directory'
}

try {
    $packerProject = Join-Path $work 'packer'
    $hostProject = Join-Path $work 'host'
    New-Item -ItemType Directory -Path $packerProject | Out-Null
    New-Item -ItemType Directory -Path $hostProject | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'Packer.csproj') -Destination $packerProject
    Copy-Item -LiteralPath (Join-Path $root 'Packer.cs') -Destination $packerProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStrings.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStringsAmbiguous.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStringsMixedInstance.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStringsCatch.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStringsDiscarded.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'ReactorStringsPostSetReverse.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'Host.cs') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'expected.json') -Destination $hostProject

    $packerOutput = Join-Path $work 'packer-output'
    $packerPathMap = "-p:PathMap=$packerProject=/_/packer"
    & dotnet build (Join-Path $packerProject 'Packer.csproj') -c Release --nologo -o $packerOutput $packerPathMap
    if ($LASTEXITCODE -ne 0) {
        throw 'packer build failed'
    }
    & dotnet (Join-Path $packerOutput 'ReactorStringsCompat.Packer.dll') `
        (Join-Path $hostProject 'expected.json') `
        (Join-Path $hostProject 'strings.bin') `
        (Join-Path $hostProject 'decoy.bin') `
        (Join-Path $hostProject 'Offsets.g.cs') `
        (Join-Path $hostProject 'expected.canonical.json')
    if ($LASTEXITCODE -ne 0) {
        throw 'resource pack failed'
    }

    $expectedOutput = [IO.File]::ReadAllText((Join-Path $hostProject 'expected.canonical.json'))
    $variants = @(
        [PSCustomObject]@{ Project = 'ReactorStrings.csproj'; Assembly = 'ReactorStringsCompat'; Label = 'fixture' },
        [PSCustomObject]@{ Project = 'ReactorStringsAmbiguous.csproj'; Assembly = 'ReactorStringsAmbiguous'; Label = 'ambiguous fixture' },
        [PSCustomObject]@{ Project = 'ReactorStringsMixedInstance.csproj'; Assembly = 'ReactorStringsMixedInstance'; Label = 'mixed-instance fixture' },
        [PSCustomObject]@{ Project = 'ReactorStringsCatch.csproj'; Assembly = 'ReactorStringsCatch'; Label = 'catch-path fixture' },
        [PSCustomObject]@{ Project = 'ReactorStringsDiscarded.csproj'; Assembly = 'ReactorStringsDiscarded'; Label = 'discarded-decoy fixture' },
        [PSCustomObject]@{ Project = 'ReactorStringsPostSetReverse.csproj'; Assembly = 'ReactorStringsPostSetReverse'; Label = 'post-set-reverse fixture' }
    )
    $destinations = @()
    $primaryOutputs = @{}
    $hostPathMap = "-p:PathMap=$hostProject=/_/host"
    foreach ($variant in $variants) {
        $output = Join-Path $work "$($variant.Assembly)-output"
        & dotnet build (Join-Path $hostProject $variant.Project) -c Release --nologo -o $output $hostPathMap
        if ($LASTEXITCODE -ne 0) {
            throw "$($variant.Label) build failed"
        }
        $dll = Join-Path $output "$($variant.Assembly).dll"
        $runtimeConfig = Join-Path $output "$($variant.Assembly).runtimeconfig.json"
        $runtimeText = [IO.File]::ReadAllText($runtimeConfig).Replace("`r`n", "`n").TrimEnd([char[]]@("`r", "`n")) + "`n"
        [IO.File]::WriteAllText($runtimeConfig, $runtimeText, [Text.UTF8Encoding]::new($false))
        $runtimeOutput = (& dotnet $dll 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "$($variant.Label) runtime failed"
        }
        if ($runtimeOutput -cne $expectedOutput) {
            throw "$($variant.Label) runtime output mismatch"
        }
        $destinations += [PSCustomObject]@{ Source = $dll; Destination = (Join-Path $root "$($variant.Assembly).dll") }
        $destinations += [PSCustomObject]@{ Source = $runtimeConfig; Destination = (Join-Path $root "$($variant.Assembly).runtimeconfig.json") }
        $primaryOutputs[$variant.Assembly] = [PSCustomObject]@{ Dll = $dll; RuntimeConfig = $runtimeConfig }
        Write-Output "$($variant.Label) runtime strings: 7"
    }

    $verifyHostProject = Join-Path $work 'host-verify'
    New-Item -ItemType Directory -Path $verifyHostProject | Out-Null
    foreach ($name in @(
        'ReactorStrings.csproj',
        'ReactorStringsAmbiguous.csproj',
        'ReactorStringsMixedInstance.csproj',
        'ReactorStringsCatch.csproj',
        'ReactorStringsDiscarded.csproj',
        'ReactorStringsPostSetReverse.csproj',
        'Host.cs',
        'expected.json'
    )) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $verifyHostProject
    }
    foreach ($name in @('strings.bin', 'decoy.bin', 'Offsets.g.cs')) {
        Copy-Item -LiteralPath (Join-Path $hostProject $name) -Destination $verifyHostProject
    }
    $verifyPathMap = "-p:PathMap=$verifyHostProject=/_/host"
    $verifiedFiles = 0
    foreach ($variant in $variants) {
        $verifyOutput = Join-Path $work "$($variant.Assembly)-verify-output"
        & dotnet build (Join-Path $verifyHostProject $variant.Project) -c Release --nologo -o $verifyOutput $verifyPathMap
        if ($LASTEXITCODE -ne 0) {
            throw "$($variant.Label) independent build failed"
        }
        $verifyDll = Join-Path $verifyOutput "$($variant.Assembly).dll"
        $verifyRuntimeConfig = Join-Path $verifyOutput "$($variant.Assembly).runtimeconfig.json"
        $verifyRuntimeText = [IO.File]::ReadAllText($verifyRuntimeConfig).Replace("`r`n", "`n").TrimEnd([char[]]@("`r", "`n")) + "`n"
        [IO.File]::WriteAllText($verifyRuntimeConfig, $verifyRuntimeText, [Text.UTF8Encoding]::new($false))
        $primary = $primaryOutputs[$variant.Assembly]
        foreach ($pair in @(
            [PSCustomObject]@{ First = $primary.Dll; Second = $verifyDll },
            [PSCustomObject]@{ First = $primary.RuntimeConfig; Second = $verifyRuntimeConfig }
        )) {
            $firstInfo = Get-Item -LiteralPath $pair.First
            $secondInfo = Get-Item -LiteralPath $pair.Second
            $firstHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair.First).Hash
            $secondHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair.Second).Hash
            if ($firstInfo.Length -ne $secondInfo.Length -or $firstHash -cne $secondHash) {
                throw "$($variant.Label) independent build differs"
            }
            $verifiedFiles++
        }
    }
    Write-Output "independent build files: $verifiedFiles/$verifiedFiles unchanged"

    $manifestText = [IO.File]::ReadAllText((Join-Path $root 'MANIFEST.toml'))
    $manifestEntries = @{}
    $blocks = [Regex]::Split($manifestText, '(?m)^\[\[fixture\]\]\s*$')
    foreach ($block in $blocks) {
        $nameMatch = [Regex]::Match($block, '(?m)^name = "([^"]+)"$')
        $sizeMatch = [Regex]::Match($block, '(?m)^size = ([0-9]+)$')
        $hashMatch = [Regex]::Match($block, '(?m)^sha256 = "([0-9a-f]{64})"$')
        if ($nameMatch.Success -and $sizeMatch.Success -and $hashMatch.Success) {
            $manifestEntries[$nameMatch.Groups[1].Value] = [PSCustomObject]@{
                Size = [Int64]::Parse($sizeMatch.Groups[1].Value)
                Hash = $hashMatch.Groups[1].Value
            }
        }
    }
    if ($manifestEntries.Count -ne 13) {
        throw "manifest contains $($manifestEntries.Count) fixture records instead of 13"
    }
    $manifestSources = @([PSCustomObject]@{
        Source = (Join-Path $root 'expected.json')
        Destination = (Join-Path $root 'expected.json')
    }) + $destinations
    $manifestMismatches = @()
    foreach ($entry in $manifestSources) {
        $name = Split-Path -Leaf $entry.Destination
        $expected = $manifestEntries[$name]
        if ($null -eq $expected) {
            throw "manifest entry absent for $name"
        }
        $actualInfo = Get-Item -LiteralPath $entry.Source
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Source).Hash.ToLowerInvariant()
        if ($actualInfo.Length -ne $expected.Size -or $actualHash -cne $expected.Hash) {
            $manifestMismatches += "${name}: size $($actualInfo.Length), sha256 $actualHash"
        }
    }
    if ($manifestMismatches.Count -ne 0) {
        throw "manifest entries differ: $($manifestMismatches -join '; ')"
    }
    Write-Output "manifest fixture records: $($manifestEntries.Count)/$($manifestEntries.Count) verified"

    $publishId = [Guid]::NewGuid().ToString('N')
    $publications = @()
    foreach ($entry in $destinations) {
        $stage = "$($entry.Destination).$publishId.stage"
        $backup = "$($entry.Destination).$publishId.backup"
        Copy-Item -LiteralPath $entry.Source -Destination $stage
        $publications += [PSCustomObject]@{
            Stage = $stage
            Backup = $backup
            Destination = $entry.Destination
            Existed = (Test-Path -LiteralPath $entry.Destination)
        }
    }
    $applied = @()
    try {
        foreach ($publication in $publications) {
            if ($publication.Existed) {
                [IO.File]::Replace(
                    $publication.Stage,
                    $publication.Destination,
                    $publication.Backup,
                    $true
                )
            }
            else {
                [IO.File]::Move($publication.Stage, $publication.Destination)
            }
            $applied += $publication
        }
    }
    catch {
        $publishError = $_
        [Array]::Reverse($applied)
        foreach ($publication in $applied) {
            if ($publication.Existed -and (Test-Path -LiteralPath $publication.Backup)) {
                [IO.File]::Copy($publication.Backup, $publication.Destination, $true)
            }
            elseif (-not $publication.Existed -and (Test-Path -LiteralPath $publication.Destination)) {
                Remove-Item -LiteralPath $publication.Destination -Force
            }
        }
        foreach ($publication in $publications) {
            if (Test-Path -LiteralPath $publication.Stage) {
                Remove-Item -LiteralPath $publication.Stage -Force
            }
            if (Test-Path -LiteralPath $publication.Backup) {
                Remove-Item -LiteralPath $publication.Backup -Force
            }
        }
        throw $publishError
    }
    foreach ($publication in $publications) {
        if (Test-Path -LiteralPath $publication.Stage) {
            Remove-Item -LiteralPath $publication.Stage -Force
        }
        if (Test-Path -LiteralPath $publication.Backup) {
            Remove-Item -LiteralPath $publication.Backup -Force
        }
    }
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
