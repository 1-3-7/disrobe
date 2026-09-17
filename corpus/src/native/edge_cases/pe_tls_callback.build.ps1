$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Here '..\..\..\generated\native'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
cl.exe /nologo /O2 /Fe:"$Out\pe_tls_callback.exe" "$Here\pe_tls_callback.c" /link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib
