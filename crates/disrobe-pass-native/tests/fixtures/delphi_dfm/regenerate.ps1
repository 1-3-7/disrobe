param(
    [Parameter(Mandatory = $true)]
    [string] $FpcBin
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) 'disrobe-dfmconv'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$units = Join-Path (Split-Path -Parent $FpcBin) 'units'
if (-not (Test-Path $units)) {
    $units = Join-Path (Split-Path -Parent (Split-Path -Parent $FpcBin)) 'units'
}
$rtl = Get-ChildItem -Path $units -Filter 'rtl' -Recurse -Directory | Select-Object -First 1
if ($null -eq $rtl) { throw "no rtl unit directory found under $units" }

Copy-Item (Join-Path $here 'dfmconv.pas') $work -Force
& (Join-Path $FpcBin 'fpc.exe') "-FD$FpcBin" "-Fu$($rtl.FullName)" "-FE$work" (Join-Path $work 'dfmconv.pas')
if ($LASTEXITCODE -ne 0) { throw 'dfmconv failed to build' }

$converter = Join-Path $work 'dfmconv.exe'
foreach ($source in Get-ChildItem -Path $here -Filter '*.src.txt') {
    $case = $source.Name -replace '\.src\.txt$', ''
    $binary = Join-Path $here "$case.dfm"
    $reference = Join-Path $here "$case.ref.txt"
    & $converter t2b $source.FullName $binary
    if ($LASTEXITCODE -ne 0) { throw "text to binary failed for $case" }
    & $converter b2t $binary $reference
    if ($LASTEXITCODE -ne 0) { throw "binary to text failed for $case" }
    Write-Output "regenerated $case"
}
