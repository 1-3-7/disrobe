#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[string] $FixtureRoot = $PSScriptRoot
[string] $Ilasm = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\ilasm.exe'
[string] $Source = Join-Path $FixtureRoot 'MethodImplShapes.il'
[string] $Assembly = Join-Path $FixtureRoot 'MethodImplShapes.dll'
[string] $Reference = Join-Path $FixtureRoot 'MethodImplShapes.metadata.txt'
[string] $ReferenceProject = Join-Path $FixtureRoot 'metadata_reference\metadata_reference.csproj'

if (-not (Test-Path -LiteralPath $Ilasm)) {
    throw "ilasm 4.8 is required at $Ilasm"
}

& $Ilasm '-nologo' '-dll' "-output=$Assembly" $Source
if ($LASTEXITCODE -ne 0) {
    throw "ilasm failed with exit code $LASTEXITCODE"
}

& dotnet run --project $ReferenceProject -- $Assembly | Set-Content -LiteralPath $Reference -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    throw "the metadata reference reader failed with exit code $LASTEXITCODE"
}

foreach ($Artifact in @('bin', 'obj')) {
    [string] $Path = Join-Path $FixtureRoot "metadata_reference\$Artifact"
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false
    }
}

Get-FileHash -LiteralPath $Assembly, $Source, $Reference -Algorithm SHA256 |
    Select-Object -Property Hash, Path
