[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('vscode', 'ida', 'ghidra', 'binja')]
    [string]$Editor,

    [string]$IDADir = '',
    [string]$GhidraScripts = '',
    [string]$BinjaPlugins = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Install-VSCode {
    $Target = Join-Path $env:USERPROFILE '.vscode\extensions\disrobe-vscode'
    Write-Host "installing disrobe VS Code extension to $Target"
    if (Test-Path $Target) {
        Remove-Item -Recurse -Force $Target
    }
    Copy-Item -Recurse (Join-Path $ScriptDir 'vscode') $Target
    Write-Host "done: extension installed at $Target"
    Write-Host "reload VS Code or run: code --install-extension `"$Target`" to activate"
}

function Install-IDA {
    $Dir = if ($IDADir) { $IDADir } else {
        $CandidateAppData = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins'
        $CandidateLocal   = Join-Path $env:LOCALAPPDATA 'Hex-Rays\IDA Pro\plugins'
        if (Test-Path $CandidateAppData) { $CandidateAppData }
        elseif (Test-Path $CandidateLocal) { $CandidateLocal }
        else { $CandidateAppData }
    }
    $Dst = Join-Path $Dir 'disrobe_ida.py'
    Write-Host "installing disrobe IDA plugin to $Dst"
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item (Join-Path $ScriptDir 'ida\disrobe_ida.py') $Dst -Force
    Write-Host "done: plugin copied to $Dst"
    Write-Host "restart IDA Pro to load the plugin"
}

function Install-Ghidra {
    $Dir = if ($GhidraScripts) { $GhidraScripts } else {
        Join-Path $env:USERPROFILE 'ghidra_scripts'
    }
    $Dst = Join-Path $Dir 'DisrobeAnalyzer.java'
    Write-Host "installing disrobe Ghidra script to $Dst"
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item (Join-Path $ScriptDir 'ghidra\DisrobeAnalyzer.java') $Dst -Force
    Write-Host "done: script copied to $Dst"
    Write-Host "in Ghidra: Window > Script Manager, refresh the list, then run DisrobeAnalyzer"
}

function Install-Binja {
    $Dir = if ($BinjaPlugins) { $BinjaPlugins } else {
        Join-Path $env:APPDATA 'Binary Ninja\plugins'
    }
    $Dst = Join-Path $Dir 'disrobe'
    Write-Host "installing disrobe Binary Ninja plugin to $Dst"
    if (Test-Path $Dst) { Remove-Item -Recurse -Force $Dst }
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force $Dir | Out-Null }
    Copy-Item -Recurse (Join-Path $ScriptDir 'binja') $Dst
    Write-Host "done: plugin copied to $Dst"
    Write-Host "restart Binary Ninja to load the plugin"
}

switch ($Editor) {
    'vscode' { Install-VSCode }
    'ida'    { Install-IDA }
    'ghidra' { Install-Ghidra }
    'binja'  { Install-Binja }
}
