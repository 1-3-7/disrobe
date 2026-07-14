param(
    [string]$ClPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe",
    [string]$VcRoot = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207",
    [string]$SdkLibRoot = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0",
    [string]$SdkIncludeRoot = "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:LIB = "$VcRoot\lib\x64;$SdkLibRoot\um\x64;$SdkLibRoot\ucrt\x64"
$env:INCLUDE = "$VcRoot\include;$SdkIncludeRoot\ucrt;$SdkIncludeRoot\shared;$SdkIncludeRoot\um"

Push-Location $here
& $ClPath /Zi /nologo /std:c++17 /GS- /c pdb_cxx_recovery.cpp /Fo:pdb_cxx_recovery.obj
& $ClPath /Zi /nologo pdb_cxx_recovery.obj /Fe:pdb_cxx_recovery.exe /link /NODEFAULTLIB /ENTRY:EntryPoint /SUBSYSTEM:CONSOLE kernel32.lib
Remove-Item pdb_cxx_recovery.obj, pdb_cxx_recovery.exe, pdb_cxx_recovery.ilk -ErrorAction SilentlyContinue
Pop-Location
