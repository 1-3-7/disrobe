[CmdletBinding()]
param(
    [Parameter()]
    [string] $Clangxx = 'clang++'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[string] $fixtureDirectory = $PSScriptRoot
[string] $source = Join-Path $fixtureDirectory 'itanium_lsda_low_opt.cpp'
[string] $output = Join-Path $fixtureDirectory 'itanium_lsda_low_opt.elf'
[string[]] $arguments = @(
    '--target=x86_64-unknown-linux-gnu'
    '-std=c++17'
    '-O0'
    '-fexceptions'
    '-fPIC'
    '-shared'
    '-nostdlib'
    '-fuse-ld=lld'
    '-Wl,-e,recover_try'
    '-Wl,--unresolved-symbols=ignore-all'
    '-Wl,--build-id=none'
    '-o'
    $output
    $source
)

& $Clangxx @arguments
if ($LASTEXITCODE -ne 0) {
    throw "clang++ exited with status $LASTEXITCODE"
}
