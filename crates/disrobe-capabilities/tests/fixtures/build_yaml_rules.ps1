#requires -Version 5.1
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"

$link = "/NODEFAULTLIB /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /FIXED:NO"

$targets = @(
    @{ src = "yaml_scope.c";   out = "yaml_scope.exe";   libs = "kernel32.lib"; opt = "/Od" },
    @{ src = "yaml_strings.c"; out = "yaml_strings.exe"; libs = "kernel32.lib"; opt = "/Od" }
)

foreach ($t in $targets) {
    $cmd = "`"$vcvars`" >nul 2>&1 && cd /d `"$here`" && cl /nologo $($t.opt) /GS- $($t.src) /link $link /OUT:$($t.out) $($t.libs)"
    cmd /c $cmd
    if (-not (Test-Path (Join-Path $here $t.out))) {
        throw "build failed for $($t.src)"
    }
    Remove-Item (Join-Path $here ([IO.Path]::ChangeExtension($t.src, "obj"))) -ErrorAction SilentlyContinue
    Write-Host ("built {0} ({1} bytes)" -f $t.out, (Get-Item (Join-Path $here $t.out)).Length)
}
