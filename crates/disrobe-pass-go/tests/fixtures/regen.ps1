#requires -version 5.1
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'src'
$mainGo = Join-Path $src 'main.go'

if (-not (Test-Path $mainGo)) {
    throw "source not found: $mainGo"
}

foreach ($tool in @('go', 'garble')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "missing toolchain dependency: $tool (install with: winget install GoLang.Go; go install mvdan.cc/garble@latest)"
    }
}

$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'

Push-Location $src
try {
    & go build -trimpath -o (Join-Path $here 'hello_normal.exe') .
    if ($LASTEXITCODE -ne 0) { throw "go build (normal) failed" }

    & go build -trimpath -ldflags '-s -w' -o (Join-Path $here 'hello_stripped.exe') .
    if ($LASTEXITCODE -ne 0) { throw "go build (stripped) failed" }

    & garble -literals -tiny build -o (Join-Path $here 'hello_garble.exe') .
    if ($LASTEXITCODE -ne 0) { throw "garble build failed" }
} finally {
    Pop-Location
}

Write-Host "regenerated:"
Get-ChildItem -Path $here -Filter '*.exe' | ForEach-Object {
    Write-Host ("  {0,-22} {1,10} bytes" -f $_.Name, $_.Length)
}
