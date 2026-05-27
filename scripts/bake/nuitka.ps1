param(
    [switch]$DryRun,
    [switch]$Force,
    [string]$NuitkaVersion = '4.1.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir '..\..')
$CorpusRoot = Join-Path $RepoRoot 'corpus\python\nuitka'
$VenvDir = Join-Path $RepoRoot '.developer\nuitka-venv'
$BuildRoot = Join-Path $RepoRoot '.developer\nuitka-bake'
$HelloPy = Join-Path $BuildRoot 'hello.py'

function Write-Plan([string]$m) { Write-Host "[plan] $m" }
function Write-Step([string]$m) { Write-Host "[step] $m" }
function Write-Skip([string]$m) { Write-Host "[skip] $m" }
function Write-Done([string]$m) { Write-Host "[done] $m" }
function Has-Cmd([string]$n) { $null -ne (Get-Command $n -ErrorAction SilentlyContinue) }

function Get-PyBin {
    if (Has-Cmd python) { return 'python' }
    if (Has-Cmd python3) { return 'python3' }
    if (Has-Cmd py) { return 'py' }
    return $null
}

function Ensure-Venv {
    $py = Get-PyBin
    if (-not $py) { throw 'python not on PATH' }
    if (Test-Path $VenvDir) {
        if (-not $Force) { Write-Skip "venv exists: $VenvDir"; return }
        Remove-Item -Recurse -Force $VenvDir
    }
    Write-Step "creating venv -> $VenvDir"
    Invoke-Native -Exe $py -ArgList @('-m','venv','--without-pip',$VenvDir) -Label 'venv create'
    $vpy = Get-VenvPy
    Invoke-Native -Exe $vpy -ArgList @('-m','ensurepip','--upgrade') -Label 'ensurepip'
}

function Get-VenvPy {
    $cand = Join-Path $VenvDir 'Scripts\python.exe'
    if (Test-Path $cand) { return $cand }
    $cand = Join-Path $VenvDir 'bin\python'
    if (Test-Path $cand) { return $cand }
    throw "no venv python at $VenvDir"
}

function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { return '"' + ($a -replace '"','\"') + '"' }
    return $a
}

function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList, [string]$Label)
    $quoted = New-Object System.Collections.Generic.List[string]
    foreach ($a in $ArgList) { $quoted.Add((Quote-Arg $a)) }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($quoted -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $p.StandardOutput.ReadToEndAsync()
    $stderrTask = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($p.ExitCode -ne 0) {
        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr }
        throw "$Label failed with exit $($p.ExitCode)"
    }
    if ($stdout) { Write-Host $stdout }
}

function Test-Importable([string]$Module) {
    $vpy = Get-VenvPy
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $vpy
    $psi.Arguments = "-c `"import $Module`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardOutput.ReadToEnd() | Out-Null
    $p.StandardError.ReadToEnd() | Out-Null
    $p.WaitForExit()
    return ($p.ExitCode -eq 0)
}

function Ensure-Nuitka {
    $vpy = Get-VenvPy
    if ((Test-Importable 'nuitka') -and (Test-Importable 'zstandard') -and (Test-Importable 'ordered_set') -and (-not $Force)) {
        Write-Skip 'nuitka + zstandard + ordered-set already installed'
        return
    }
    Write-Step "installing nuitka==$NuitkaVersion + zstandard + ordered-set"
    Invoke-Native -Exe $vpy -ArgList @('-m','pip','install','--no-input','--upgrade','pip') -Label 'pip upgrade'
    Invoke-Native -Exe $vpy -ArgList @('-m','pip','install','--no-input',"nuitka==$NuitkaVersion",'zstandard','ordered-set') -Label 'nuitka install'
}

function Write-HelloPy {
    if (-not (Test-Path $BuildRoot)) { New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null }
    $body = @'
def greet(name: str) -> str:
    return f"hello, {name}"

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
'@
    Set-Content -Path $HelloPy -Value $body -Encoding utf8
}

function Invoke-Variant {
    param(
        [string]$Name,
        [string[]]$ExtraArgs
    )
    $outDir = Join-Path $CorpusRoot $Name
    $stageDir = Join-Path $BuildRoot $Name
    if ((Test-Path $outDir) -and (-not $Force)) {
        Write-Skip "variant exists: $outDir"
        return
    }
    if (-not (Test-Path $stageDir)) { New-Item -ItemType Directory -Force -Path $stageDir | Out-Null }
    if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
    $vpy = Get-VenvPy
    $argsAll = @('-m', 'nuitka', '--assume-yes-for-downloads', "--output-dir=$stageDir") + $ExtraArgs + @($HelloPy)
    Write-Step "nuitka [$Name] -> $stageDir"
    Invoke-Native -Exe $vpy -ArgList $argsAll -Label "nuitka [$Name]"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Get-ChildItem -Path $stageDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($stageDir.Length).TrimStart('\','/')
        $dst = Join-Path $outDir $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
        Copy-Item -Force $_.FullName $dst
    }
    Write-Done "variant baked: $outDir"
}

function Plan {
    Write-Plan "venv: $VenvDir (nuitka==$NuitkaVersion)"
    Write-Plan "hello.py: $HelloPy"
    Write-Plan "out root: $CorpusRoot"
    foreach ($v in 'onefile','standalone','module','static-libpython','plugin-anti-bloat','console-disable') {
        Write-Plan "variant: $v -> $CorpusRoot\$v"
    }
}

if ($DryRun) { Plan; exit 0 }

Ensure-Venv
Ensure-Nuitka
Write-HelloPy

function Try-Variant {
    param([string]$Name, [string[]]$ExtraArgs)
    try { Invoke-Variant -Name $Name -ExtraArgs $ExtraArgs }
    catch { Write-Skip "$Name unavailable on this host: $($_.Exception.Message)" }
}

Try-Variant -Name 'onefile' -ExtraArgs @('--onefile')
Try-Variant -Name 'standalone' -ExtraArgs @('--standalone')
Try-Variant -Name 'module' -ExtraArgs @('--module')
Try-Variant -Name 'static-libpython' -ExtraArgs @('--standalone','--static-libpython=yes')
Try-Variant -Name 'plugin-anti-bloat' -ExtraArgs @('--standalone','--enable-plugin=anti-bloat')
$onWindows = $env:OS -eq 'Windows_NT'
if ($onWindows) {
    Try-Variant -Name 'console-disable' -ExtraArgs @('--standalone','--windows-console-mode=disable')
} else {
    Write-Skip 'console-disable: Windows-only variant'
}

Write-Done "all variants baked under $CorpusRoot"
