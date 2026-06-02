param(
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$Out = Join-Path $RepoRoot 'corpus/v8'
$HelloSrc = 'process.stdout.write("hello " + (42 + 0));'

if (-not (Test-Path $Out)) {
    if ($DryRun) {
        Write-Host "[plan] mkdir $Out"
    } else {
        New-Item -ItemType Directory -Force -Path $Out | Out-Null
    }
}

$Versions = @('18', '20', '22', '24')
foreach ($v in $Versions) {
    $OutDir = Join-Path $Out "node-$v"
    if (-not (Test-Path $OutDir)) {
        if ($DryRun) {
            Write-Host "[plan] mkdir $OutDir"
        } else {
            New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        }
    }
    $HelloPath = Join-Path $OutDir "hello-$v.js"
    $JscPath = Join-Path $OutDir "hello-$v.jsc"
    if ($DryRun) {
        Write-Host "[plan] write $HelloPath"
        Write-Host "[plan] npx -y -p node@$v -p bytenode bytenode --compile $HelloPath"
    } else {
        Set-Content -Path $HelloPath -Value $HelloSrc -Encoding utf8
        $env:NODE_NO_WARNINGS = '1'
        $proc = Start-Process -FilePath 'npx' -ArgumentList @(
            '-y', '-p', "node@$v", '-p', 'bytenode',
            'bytenode', '--compile', $HelloPath
        ) -NoNewWindow -Wait -PassThru -ErrorAction Continue
        if ($null -ne $proc -and $proc.ExitCode -eq 0 -and (Test-Path $JscPath)) {
            Write-Host "[ok]   baked $JscPath"
        } else {
            Write-Host "[skip] node $v unavailable or bytenode failed (npx exit $($proc.ExitCode))"
        }
    }
}
