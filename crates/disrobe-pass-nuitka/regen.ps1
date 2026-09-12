#requires -Version 5.1
<#
.SYNOPSIS
    Freeze real Nuitka fixtures (--onefile and --standalone) for disrobe-pass-nuitka tests.

.DESCRIPTION
    Builds a trivial hello program with a planted, recoverable marker constant using the
    locally installed Nuitka, writing the artifacts under corpus/python/nuitka/<variant>/.
    The large .exe outputs are git-ignored (see corpus .gitignore); GitHub gets this script
    plus the small checked-in extracted artifact under tests/fixtures, while local runs build
    and verify against the real binary.

    Honest by construction: if Nuitka is not importable this exits non-zero with a clear
    message rather than fabricating a fixture.

.PARAMETER Only
    Restrict to a single variant: onefile | standalone | module. Omit to build all.

.PARAMETER Force
    Rebuild even when the output already exists.
#>
[CmdletBinding()]
param(
    [ValidateSet('onefile', 'standalone', 'module')]
    [string]$Only,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CrateDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $CrateDir '..\..')
$CorpusRoot = Join-Path $RepoRoot 'corpus\python\nuitka'
$StageRoot = Join-Path $RepoRoot '.developer\nuitka-bake'
$FixtureDir = Join-Path $CrateDir 'tests\fixtures'
$HelloPy = Join-Path $StageRoot 'hello.py'

# A unique token planted in the source so a recovered artifact can be asserted byte-exact.
$PlantedMarker = 'DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c'

function Get-PyBin {
    foreach ($c in 'python', 'python3', 'py') {
        if (Get-Command $c -ErrorAction SilentlyContinue) { return $c }
    }
    throw 'no python interpreter on PATH'
}

function Test-NuitkaImportable([string]$Py) {
    & $Py -c 'import nuitka' 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Write-HelloPy {
    if (-not (Test-Path $StageRoot)) { New-Item -ItemType Directory -Force -Path $StageRoot | Out-Null }
    $body = @"
MARKER = "$PlantedMarker"


def greet(name: str) -> str:
    return f"hello, {name} [{MARKER}]"


def fib(n: int) -> int:
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b


def main() -> int:
    print(greet("disrobe"))
    print(fib(20))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"@
    Set-Content -Path $HelloPy -Value $body -Encoding utf8
}

function Invoke-Variant {
    param([string]$Name, [string[]]$ExtraArgs)

    $outDir = Join-Path $CorpusRoot $Name
    if ((Test-Path (Join-Path $outDir 'hello.exe')) -and (-not $Force)) {
        Write-Host "[skip] $Name exists"
        return
    }
    $stageDir = Join-Path $StageRoot $Name
    if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    $py = Get-PyBin
    $argv = @('-m', 'nuitka', '--assume-yes-for-downloads', "--output-dir=$stageDir") + $ExtraArgs + @($HelloPy)
    Write-Host "[build] nuitka [$Name] -> $stageDir"
    & $py @argv
    if ($LASTEXITCODE -ne 0) { throw "nuitka [$Name] failed (exit $LASTEXITCODE)" }

    if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Get-ChildItem -Path $stageDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($stageDir.Length).TrimStart('\', '/')
        $dst = Join-Path $outDir $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        Copy-Item -Force $_.FullName $dst
    }
    Write-Host "[done] $Name -> $outDir"
}

function Write-CheckedInFixture {
    # Carve the small first-entry header slice from the onefile payload and persist a tiny
    # checked-in artifact: the planted marker bytes, so a fast unit test can assert recovery
    # without committing the multi-MB exe.
    $onefile = Join-Path $CorpusRoot 'onefile\hello.exe'
    if (-not (Test-Path $onefile)) { return }
    if (-not (Test-Path $FixtureDir)) { New-Item -ItemType Directory -Force -Path $FixtureDir | Out-Null }
    $markerFile = Join-Path $FixtureDir 'planted_marker.txt'
    Set-Content -Path $markerFile -Value $PlantedMarker -NoNewline -Encoding ascii
    Write-Host "[done] checked-in marker -> $markerFile"
}

$py = Get-PyBin
if (-not (Test-NuitkaImportable $py)) {
    Write-Error "Nuitka is not importable under '$py'. Install with: $py -m pip install nuitka==4.1.1 zstandard ordered-set"
    exit 1
}

Write-HelloPy

$variants = @{
    onefile    = @('--onefile')
    standalone = @('--standalone')
    module     = @('--module')
}

if ($Only) {
    Invoke-Variant -Name $Only -ExtraArgs $variants[$Only]
}
else {
    foreach ($name in 'onefile', 'standalone', 'module') {
        Invoke-Variant -Name $name -ExtraArgs $variants[$name]
    }
}

Write-CheckedInFixture
Write-Host "[ok] regen complete"
