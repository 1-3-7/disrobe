#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string] $HermesToolchain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[string] $here = $PSScriptRoot
[string] $hermesc = Join-Path $HermesToolchain 'hermesc.exe'
[string] $hermes = Join-Path $HermesToolchain 'hermes.exe'
[string] $hbcdump = Join-Path $HermesToolchain 'hbcdump.exe'

foreach ($tool in @($hermesc, $hermes, $hbcdump)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "missing $tool"
    }
}

foreach ($name in @('longtail', 'shapes')) {
    [string] $source = "./$name." + 'js'
    [string] $bytecode = "./$name.hbc"

    Start-Process -FilePath $hermesc -WorkingDirectory $here -Wait -NoNewWindow `
        -ArgumentList @('-emit-binary', '-out', $bytecode, $source)

    Start-Process -FilePath $hermes -WorkingDirectory $here -Wait -NoNewWindow `
        -ArgumentList @($source) `
        -RedirectStandardOutput (Join-Path $here "$name.hermes-stdout.txt")

    Start-Process -FilePath $hbcdump -WorkingDirectory $here -Wait -NoNewWindow `
        -ArgumentList @('-objdump-disassemble', '-c', 'disassemble;quit', $bytecode) `
        -RedirectStandardOutput (Join-Path $here "$name.hbcdump.txt")

    [string] $digest = (Get-FileHash -LiteralPath (Join-Path $here "$name.hbc") -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output "$name.hbc sha256=$digest"
}
