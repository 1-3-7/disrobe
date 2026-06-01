param(
    [switch]$DryRun,
    [string]$OutRoot = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "../..") | Select-Object -ExpandProperty Path
if ([string]::IsNullOrEmpty($OutRoot)) {
    $OutRoot = Join-Path $RepoRoot "corpus/python/pyarmor"
}
$VenvRoot = Join-Path $RepoRoot ".developer/venv"

function Write-Plan($msg) { Write-Host "[plan] $msg" }
function Write-Run($msg)  { Write-Host "[run]  $msg" }
function Write-Skip($msg) { Write-Host "[skip] $msg" }
function Write-Ok($msg)   { Write-Host "[ok]   $msg" }
function Has-Cmd($name)   { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

function New-PyVenv {
    param([string]$Path, [string]$PyarmorVersion)
    if (Test-Path $Path) {
        Write-Skip "venv already exists: $Path"
        return
    }
    if (-not (Has-Cmd python)) {
        throw "python not on PATH; cannot build pyarmor venv"
    }
    Write-Run "creating venv $Path with pyarmor==$PyarmorVersion"
    if ($DryRun) { return }
    & python -m venv $Path
    $pip = Join-Path $Path "Scripts/pip.exe"
    if (-not (Test-Path $pip)) { $pip = Join-Path $Path "bin/pip" }
    & $pip install --upgrade pip | Out-Null
    & $pip install "pyarmor==$PyarmorVersion" | Out-Null
}

function Bake-V7Super {
    $venv = Join-Path $VenvRoot "pyarmor-7.7.4"
    $out = Join-Path $OutRoot "v7-super"
    Write-Plan "v7-super -> $out"
    if ($DryRun) { return }
    New-PyVenv -Path $venv -PyarmorVersion "7.7.4"
    $pyarmor = Join-Path $venv "Scripts/pyarmor.exe"
    if (-not (Test-Path $pyarmor)) { $pyarmor = Join-Path $venv "bin/pyarmor" }
    if (-not (Test-Path $pyarmor)) {
        Write-Skip "pyarmor-7.7.4 venv missing pyarmor entrypoint; skipping v7-super bake"
        return
    }
    $stage = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "disrobe-bake-v7-super") | Select-Object -ExpandProperty FullName
    $src = Join-Path $stage "hello_v7_super.py"
    Set-Content -Path $src -Value 'def greet(name: str) -> str:`n    return f"hello {name}"`n`nif __name__ == "__main__":`n    print(greet("world"))`n' -Encoding utf8
    Push-Location $stage
    try {
        & $pyarmor obfuscate --advanced 2 --output $out $src
        Write-Ok "v7-super baked into $out"
    } finally {
        Pop-Location
    }
}

function Bake-V9Bcc {
    $venv = Join-Path $VenvRoot "pyarmor-9.0.0"
    $out = Join-Path $OutRoot "v9-bcc"
    Write-Plan "v9-bcc -> $out"
    if ($DryRun) { return }
    New-PyVenv -Path $venv -PyarmorVersion "9.0.0"
    $pyarmor = Join-Path $venv "Scripts/pyarmor.exe"
    if (-not (Test-Path $pyarmor)) { $pyarmor = Join-Path $venv "bin/pyarmor" }
    if (-not (Test-Path $pyarmor)) {
        Write-Skip "pyarmor-9.0.0 venv missing pyarmor entrypoint; skipping v9-bcc bake"
        return
    }
    $stage = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "disrobe-bake-v9-bcc") | Select-Object -ExpandProperty FullName
    $src = Join-Path $stage "hello_v9_bcc.py"
    Set-Content -Path $src -Value 'def fib(n: int) -> int:`n    if n < 2:`n        return n`n    return fib(n - 1) + fib(n - 2)`n`nif __name__ == "__main__":`n    print(fib(10))`n' -Encoding utf8
    Push-Location $stage
    try {
        & $pyarmor cfg bcc_mode=1
        & $pyarmor gen --enable-bcc --output $out $src
        Write-Ok "v9-bcc baked into $out"
    } finally {
        Pop-Location
    }
}

function Stage-Runtimes {
    $rtRoot = Join-Path $OutRoot "_pytransform-runtimes"
    Write-Plan "stage _pytransform runtimes -> $rtRoot"
    if ($DryRun) { return }
    New-Item -ItemType Directory -Force -Path $rtRoot | Out-Null
    foreach ($pair in @(@("pyarmor-7.7.4", "v7"), @("pyarmor-9.0.0", "v9"))) {
        $venv = Join-Path $VenvRoot $pair[0]
        $tag = $pair[1]
        if (-not (Test-Path $venv)) { continue }
        $sitePkgs = @()
        if ($IsWindows -or $env:OS -eq "Windows_NT") {
            $sitePkgs = Get-ChildItem -Recurse -Path (Join-Path $venv "Lib") -Filter "_pytransform*" -ErrorAction SilentlyContinue
        } else {
            $sitePkgs = Get-ChildItem -Recurse -Path (Join-Path $venv "lib") -Filter "_pytransform*" -ErrorAction SilentlyContinue
        }
        foreach ($f in $sitePkgs) {
            $dst = Join-Path $rtRoot "${tag}_$($f.Name)"
            Copy-Item -Force -Path $f.FullName -Destination $dst
            Write-Ok "staged $($f.FullName) -> $dst"
        }
    }
}

if (-not (Test-Path $OutRoot)) { New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null }
Write-Plan "OutRoot=$OutRoot"
Bake-V7Super
Bake-V9Bcc
Stage-Runtimes
Write-Ok "pyarmor bake complete"
