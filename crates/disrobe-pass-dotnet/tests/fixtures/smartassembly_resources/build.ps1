$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$expectedSdk = '9.0.314'
$actualSdk = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSdk -ne $expectedSdk) {
    throw "dotnet SDK $expectedSdk required, found $actualSdk"
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$work = [IO.Path]::GetFullPath((Join-Path $tempRoot "disrobe-smartassembly-resource-fixture-$([Guid]::NewGuid().ToString('N'))"))
if (-not $work.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary work path escaped the system temporary directory'
}

try {
    $payloadProject = Join-Path $work 'payload'
    $packerProject = Join-Path $work 'packer'
    $hostProject = Join-Path $work 'host'
    foreach ($directory in @($payloadProject, $packerProject, $hostProject)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $root 'Payload.csproj') -Destination $payloadProject
    Copy-Item -LiteralPath (Join-Path $root 'Payload.cs') -Destination $payloadProject
    Copy-Item -LiteralPath (Join-Path $root 'Packer.csproj') -Destination $packerProject
    Copy-Item -LiteralPath (Join-Path $root 'Packer.cs') -Destination $packerProject
    Copy-Item -LiteralPath (Join-Path $root 'Host.csproj') -Destination $hostProject
    Copy-Item -LiteralPath (Join-Path $root 'Host.cs') -Destination $hostProject

    $payloadOutput = Join-Path $work 'payload-output'
    & dotnet build (Join-Path $payloadProject 'Payload.csproj') -c Release --nologo -o $payloadOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'payload build failed'
    }
    $packerOutput = Join-Path $work 'packer-output'
    & dotnet build (Join-Path $packerProject 'Packer.csproj') -c Release --nologo -o $packerOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'packer build failed'
    }
    $payloadDll = Join-Path $payloadOutput 'SmartAssemblyCompat.Payload.dll'
    & dotnet (Join-Path $packerOutput 'SmartAssemblyCompat.Packer.dll') $payloadDll (Join-Path $hostProject 'payload.saz') 257
    if ($LASTEXITCODE -ne 0) {
        throw 'resource pack failed'
    }
    [IO.File]::WriteAllBytes((Join-Path $hostProject 'keyed.saz'), [byte[]](0x7B, 0x7A, 0x7D, 0x03, 0x00, 0x00, 0x00, 0x00))
    [IO.File]::WriteAllBytes((Join-Path $hostProject 'rejected.saz'), [byte[]](0x7B, 0x7A, 0x7D, 0x01, 0x00, 0x10, 0x00, 0x00))

    $hostOutput = Join-Path $work 'host-output'
    & dotnet build (Join-Path $hostProject 'Host.csproj') -c Release --nologo -o $hostOutput
    if ($LASTEXITCODE -ne 0) {
        throw 'host build failed'
    }
    $hostDll = Join-Path $hostOutput 'SmartAssemblyCompat.dll'
    $runtimeConfig = Join-Path $hostOutput 'SmartAssemblyCompat.runtimeconfig.json'
    $runtimeText = [IO.File]::ReadAllText($runtimeConfig).Replace("`r`n", "`n").TrimEnd([char[]]@("`r", "`n")) + "`n"
    [IO.File]::WriteAllText($runtimeConfig, $runtimeText, [Text.UTF8Encoding]::new($false))
    $runtimeOutput = (& dotnet $hostDll 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'fixture runtime failed'
    }
    if ($runtimeOutput -cne 'smartassembly-resource-ground-truth-v1') {
        throw "fixture runtime output mismatch: $runtimeOutput"
    }

    $lockPath = Join-Path $root '.smartassembly-resource-fixture.lock'
    $lockDeadline = [DateTime]::UtcNow.AddMinutes(2)
    $publishLock = $null
    while ($null -eq $publishLock) {
        try {
            $publishLock = [IO.FileStream]::new(
                $lockPath,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None,
                1,
                [IO.FileOptions]::DeleteOnClose
            )
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $lockDeadline) {
                throw 'fixture publication lock timed out'
            }
            Start-Sleep -Milliseconds 100
        }
    }
    try {
        $publishId = [Guid]::NewGuid().ToString('N')
        $destinations = @(
            [PSCustomObject]@{
                Source = $payloadDll
                Destination = (Join-Path $root 'Payload.clean.dll')
            },
            [PSCustomObject]@{
                Source = $hostDll
                Destination = (Join-Path $root 'SmartAssemblyCompat.dll')
            },
            [PSCustomObject]@{
                Source = $runtimeConfig
                Destination = (Join-Path $root 'SmartAssemblyCompat.runtimeconfig.json')
            }
        )
        $publicationSettled = $false
        foreach ($entry in $destinations) {
            $entry | Add-Member -NotePropertyName Stage -NotePropertyValue "$($entry.Destination).$publishId.stage"
            $entry | Add-Member -NotePropertyName Backup -NotePropertyValue "$($entry.Destination).$publishId.backup"
            $entry | Add-Member -NotePropertyName HadDestination -NotePropertyValue (Test-Path -LiteralPath $entry.Destination)
            $entry | Add-Member -NotePropertyName Published -NotePropertyValue $false
        }
        try {
            foreach ($entry in $destinations) {
                Copy-Item -LiteralPath $entry.Source -Destination $entry.Stage
            }
            foreach ($entry in $destinations) {
                if ($entry.HadDestination) {
                    [IO.File]::Replace($entry.Stage, $entry.Destination, $entry.Backup, $true)
                }
                else {
                    [IO.File]::Move($entry.Stage, $entry.Destination)
                }
                $entry.Published = $true
            }
            $publicationSettled = $true
        }
        catch {
            $publishError = $_
            $rollbackFailures = [Collections.Generic.List[string]]::new()
            for ($index = $destinations.Count - 1; $index -ge 0; $index--) {
                $entry = $destinations[$index]
                if (-not $entry.Published) {
                    continue
                }
                try {
                    if ($entry.HadDestination) {
                        [IO.File]::Replace($entry.Backup, $entry.Destination, $null, $true)
                    }
                    elseif (Test-Path -LiteralPath $entry.Destination) {
                        Remove-Item -LiteralPath $entry.Destination -Force
                    }
                }
                catch {
                    $rollbackFailures.Add("$($entry.Destination): $_")
                }
            }
            if ($rollbackFailures.Count -ne 0) {
                throw "fixture publish failed and rollback failed: $publishError; $($rollbackFailures -join '; ')"
            }
            $publicationSettled = $true
            throw $publishError
        }
        finally {
            foreach ($entry in $destinations) {
                if (Test-Path -LiteralPath $entry.Stage) {
                    Remove-Item -LiteralPath $entry.Stage -Force
                }
                if ($publicationSettled -and (Test-Path -LiteralPath $entry.Backup)) {
                    Remove-Item -LiteralPath $entry.Backup -Force
                }
            }
        }
    }
    finally {
        $publishLock.Dispose()
    }
    Write-Output "fixture runtime: $runtimeOutput"
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
