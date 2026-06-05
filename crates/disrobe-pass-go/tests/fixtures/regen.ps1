#requires -version 5.1
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $here 'src'
$mainGo = Join-Path $src 'main.go'

if (-not (Test-Path $mainGo)) {
    throw "source not found: $mainGo"
}

if (-not (Get-Command 'go' -ErrorAction SilentlyContinue)) {
    throw "missing toolchain dependency: go (install with: winget install GoLang.Go)"
}
$haveGarble = [bool](Get-Command 'garble' -ErrorAction SilentlyContinue)
if (-not $haveGarble) {
    Write-Warning "garble not on PATH; hello_garble.exe will be left as-is (install: go install mvdan.cc/garble@latest)"
}

$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
# src/main.go and genericsrc/main.go are single-file main packages with no go.mod;
# GOPATH/module-aware mode would fail inside the parent git repo, so build them as
# standalone packages.
$env:GO111MODULE = 'auto'

Push-Location $src
try {
    & go build -trimpath -o (Join-Path $here 'hello_normal.exe') .
    if ($LASTEXITCODE -ne 0) { throw "go build (normal) failed" }

    & go build -trimpath -ldflags '-s -w' -o (Join-Path $here 'hello_stripped.exe') .
    if ($LASTEXITCODE -ne 0) { throw "go build (stripped) failed" }

    if ($haveGarble) {
        & garble -literals -tiny build -o (Join-Path $here 'hello_garble.exe') .
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "garble build failed (often a garble<->Go version mismatch); leaving existing hello_garble.exe"
        }
    }
} finally {
    Pop-Location
}

$embedSrc = Join-Path $here 'embedsrc'
if (Test-Path (Join-Path $embedSrc 'main.go')) {
    Push-Location $embedSrc
    try {
        & go build -trimpath -o (Join-Path $here 'hello_embed.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (embed) failed" }
    } finally {
        Pop-Location
    }
}

$genericSrc = Join-Path $here 'genericsrc'
if (Test-Path (Join-Path $genericSrc 'main.go')) {
    Push-Location $genericSrc
    try {
        & go build -trimpath -o (Join-Path $here 'hello_generics.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (generics) failed" }

        & go build -trimpath -ldflags '-s -w' -o (Join-Path $here 'hello_generics_stripped.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (generics stripped) failed" }
    } finally {
        Pop-Location
    }
}

# Synthetic magic-stomp fixture: copy hello_normal and overwrite the 4 pclntab magic
# bytes with a garble-style random value, leaving the rest of the header intact. This
# reproduces the magic-stomp case the signature scan must recover (static byte patch,
# the sample is never executed).
$normalExe = Join-Path $here 'hello_normal.exe'
if (Test-Path $normalExe) {
    $bytes = [System.IO.File]::ReadAllBytes($normalExe)
    $pcMagics = @(
        @(0xfb, 0xff, 0xff, 0xff),
        @(0xfa, 0xff, 0xff, 0xff),
        @(0xf0, 0xff, 0xff, 0xff),
        @(0xf1, 0xff, 0xff, 0xff)
    )
    $off = -1
    for ($i = 0; ($i + 16) -le $bytes.Length; $i++) {
        foreach ($m in $pcMagics) {
            if ($bytes[$i] -eq $m[0] -and $bytes[$i + 1] -eq $m[1] -and
                $bytes[$i + 2] -eq $m[2] -and $bytes[$i + 3] -eq $m[3] -and
                $bytes[$i + 4] -eq 0 -and $bytes[$i + 5] -eq 0 -and
                ($bytes[$i + 6] -in 1, 2, 4) -and ($bytes[$i + 7] -in 4, 8)) {
                $off = $i
                break
            }
        }
        if ($off -ge 0) { break }
    }
    if ($off -ge 0) {
        $bytes[$off] = 0xde; $bytes[$off + 1] = 0xad
        $bytes[$off + 2] = 0xbe; $bytes[$off + 3] = 0x5f
        [System.IO.File]::WriteAllBytes((Join-Path $here 'hello_magic_stomped.exe'), $bytes)
    } else {
        Write-Warning 'pclntab magic not found in hello_normal.exe; skipped hello_magic_stomped.exe'
    }
}

Write-Host "regenerated:"
Get-ChildItem -Path $here -Filter '*.exe' | ForEach-Object {
    Write-Host ("  {0,-22} {1,10} bytes" -f $_.Name, $_.Length)
}
