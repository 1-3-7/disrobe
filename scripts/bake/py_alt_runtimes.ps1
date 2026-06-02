#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$CorpusRoot = Join-Path $RepoRoot 'corpus\python\alt_runtimes'

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Log-Plan { param([string]$Msg) Write-Host "[plan]    $Msg" }
function Log-Run  { param([string]$Msg) Write-Host "[run]     $Msg" }
function Log-Skip { param([string]$Msg) Write-Host "[skip]    $Msg" -ForegroundColor Yellow }
function Log-Done { param([string]$Msg) Write-Host "[done]    $Msg" -ForegroundColor Green }

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function Write-Source {
    param([string]$Path, [string]$Content)
    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8 -NoNewline
}

function Bake-PyPy {
    $OutDir = Join-Path $CorpusRoot 'pypy'
    Ensure-Dir $OutDir
    $HelloPy = @"
def greet(name):
    return f"hello, {name}"


print(greet("pypy"))
"@
    Write-Source (Join-Path $OutDir 'hello.py') $HelloPy
    Log-Plan "pypy: compile hello.py with pypy3 -> hello.pypy3.pyc"
    if ($DryRun) { return }
    if (Test-Command 'pypy3') {
        Log-Run "pypy: compiling"
        Push-Location $OutDir
        try {
            & pypy3 -c "import py_compile; py_compile.compile('hello.py', 'hello.pypy3.pyc')"
            Log-Done "pypy: $OutDir\hello.pypy3.pyc"
        } finally { Pop-Location }
    } else {
        Log-Skip "pypy: pypy3 not on PATH (install via scoop install pypy3 / chocolatey)"
    }
}

function Bake-MicroPythonBytecode {
    $OutDir = Join-Path $CorpusRoot 'micropython'
    Ensure-Dir $OutDir
    $HelloPy = @"
def add(a, b):
    return a + b


print(add(1, 2))
"@
    Write-Source (Join-Path $OutDir 'hello.py') $HelloPy
    Log-Plan "micropython: mpy-cross hello.py -> hello.mpy"
    if ($DryRun) { return }
    if (Test-Command 'mpy-cross') {
        Log-Run "micropython: mpy-cross"
        Push-Location $OutDir
        try {
            & mpy-cross hello.py -o hello.mpy
            Log-Done "micropython: $OutDir\hello.mpy"
        } finally { Pop-Location }
    } elseif (Test-Command 'docker') {
        Log-Run "micropython: docker run micropython/unix mpy-cross"
        try {
            & docker run --rm -v "${OutDir}:/src" -w /src micropython/unix mpy-cross hello.py -o hello.mpy
        } catch {
            Log-Skip "micropython: docker image missing"
        }
    } else {
        Log-Skip "micropython: neither mpy-cross nor docker available"
    }
}

function Bake-MicroPythonNative {
    $OutDir = Join-Path $CorpusRoot 'micropython'
    Ensure-Dir $OutDir
    Log-Plan "micropython-native: mpy-cross -X emit=native hello.py -> hello.native.mpy"
    if ($DryRun) { return }
    if (Test-Command 'mpy-cross') {
        Log-Run "micropython-native: mpy-cross emit=native"
        Push-Location $OutDir
        try {
            & mpy-cross -X emit=native hello.py -o hello.native.mpy
        } catch {
            Log-Skip "micropython-native: emit=native failed (arch unsupported on host)"
        } finally { Pop-Location }
    } else {
        Log-Skip "micropython-native: mpy-cross not available"
    }
}

function Bake-Jython {
    $OutDir = Join-Path $CorpusRoot 'jython'
    Ensure-Dir $OutDir
    $HelloPy = @"
def greet():
    return 'hi from jython'


if __name__ == '__main__':
    print(greet())
"@
    Write-Source (Join-Path $OutDir 'hello.py') $HelloPy
    Log-Plan "jython: compile hello.py -> hello`$py.class"
    if ($DryRun) { return }
    if (Test-Command 'jython') {
        Log-Run "jython: compile"
        Push-Location $OutDir
        try {
            & jython -c "from compileall import compile_file; compile_file('hello.py')"
            Log-Done "jython: $OutDir\hello`$py.class"
        } finally { Pop-Location }
    } elseif (Test-Command 'docker') {
        Log-Run "jython: docker run jython:2.7"
        try {
            & docker run --rm -v "${OutDir}:/src" -w /src jython:2.7 jython -c "from compileall import compile_file; compile_file('hello.py')"
        } catch {
            Log-Skip "jython: docker image missing"
        }
    } else {
        Log-Skip "jython: neither jython nor docker available"
    }
}

function Bake-IronPython {
    $OutDir = Join-Path $CorpusRoot 'ironpython'
    Ensure-Dir $OutDir
    $HelloPy = @"
def greet():
    return 'hi from ironpython'


if __name__ == '__main__':
    print(greet())
"@
    Write-Source (Join-Path $OutDir 'hello.py') $HelloPy
    Log-Plan "ironpython: ipy hello.py -> hello.dll"
    if ($DryRun) { return }
    if (Test-Command 'ipy') {
        Log-Run "ironpython: ipy compile"
        Push-Location $OutDir
        try {
            & ipy -c "import clr; clr.CompileModules('hello.dll', 'hello.py')"
        } catch {
            Log-Skip "ironpython: compile failed"
        } finally { Pop-Location }
    } else {
        Log-Skip "ironpython: ipy not on PATH (install IronPython release)"
    }
}

function Bake-Brython {
    $OutDir = Join-Path $CorpusRoot 'brython'
    Ensure-Dir $OutDir
    $HelloPy = @"
def greet():
    return 'hi from brython'


print(greet())
"@
    Write-Source (Join-Path $OutDir 'hello.py') $HelloPy
    $BrythonJs = @"
;(function() {
    var `$B = __BRYTHON__;
    `$B.imported['hello'] = (function() {
        var `$locals_hello = {};
        `$locals_hello.greet = function() { return 'hi from brython'; };
        `$B.modules['hello'] = `$locals_hello;
        return `$locals_hello;
    })();
})();
"@
    Write-Source (Join-Path $OutDir 'hello.brython.js') $BrythonJs
    Log-Plan "brython: emit synthetic hello.brython.js (npx brython-cli optional)"
    if ($DryRun) { return }
    if (Test-Command 'npx') {
        Log-Run "brython: npx brython-cli (best effort)"
        Push-Location $OutDir
        try {
            & npx --yes brython-cli@latest --modules hello.py 2>$null | Out-Null
        } catch {
            Log-Skip "brython: brython-cli not available (using hand-shaped fixture)"
        } finally { Pop-Location }
    } else {
        Log-Skip "brython: npx not available (using hand-shaped fixture)"
    }
    Log-Done "brython: $OutDir\hello.brython.js"
}

Ensure-Dir $CorpusRoot
Bake-PyPy
Bake-MicroPythonBytecode
Bake-MicroPythonNative
Bake-Jython
Bake-IronPython
Bake-Brython
Write-Host ""
Write-Host "[summary] alt-runtime fixtures baked under $CorpusRoot"
