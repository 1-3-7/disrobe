#requires -Version 5.1
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"

$link = "/NODEFAULTLIB /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /FIXED:NO"

$targets = @(
    @{ src = "writefile.c";  out = "writefile.exe";  libs = "kernel32.lib";            opt = "/O2" },
    @{ src = "connect.c";    out = "connect.exe";    libs = "ws2_32.lib kernel32.lib"; opt = "/O2" },
    @{ src = "xordecrypt.c"; out = "xordecrypt.exe"; libs = "kernel32.lib";            opt = "/Od" },
    @{ src = "clean.c";      out = "clean.exe";      libs = "kernel32.lib";            opt = "/O2" }
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
