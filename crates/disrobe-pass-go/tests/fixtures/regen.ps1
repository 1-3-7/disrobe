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

    $env:GOARCH = '386'
    & go build -trimpath -o (Join-Path $here 'hello_386.exe') .
    if ($LASTEXITCODE -ne 0) { throw "go build (386) failed" }
    $env:GOARCH = 'amd64'

    if ($haveGarble) {
        & garble -literals build -o (Join-Path $here 'hello_garble.exe') .
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

$depSrc = Join-Path $here 'depsrc'
if (Test-Path (Join-Path $depSrc 'main.go')) {
    Push-Location $depSrc
    try {
        $env:GO111MODULE = 'on'
        $env:GOFLAGS = '-mod=mod'
        & go build -trimpath -o (Join-Path $here 'hello_deps.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (deps) failed" }
        $env:GOFLAGS = ''
        $env:GO111MODULE = 'auto'
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

$benchSrc = Join-Path $here 'benchsrc'
if (Test-Path (Join-Path $benchSrc 'main.go')) {
    Push-Location $benchSrc
    try {
        & go build -trimpath -o (Join-Path $here 'bench_generics.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (bench) failed" }

        & go build -trimpath -ldflags '-s -w' -o (Join-Path $here 'bench_generics_stripped.exe') .
        if ($LASTEXITCODE -ne 0) { throw "go build (bench stripped) failed" }

        $rawNm = & go tool nm (Join-Path $here 'bench_generics.exe')
        if ($LASTEXITCODE -ne 0) { throw "go tool nm (bench windows/amd64) failed" }
        $textSyms = $rawNm | Where-Object {
            $cols = ($_ -split '\s+') | Where-Object { $_ -ne '' }
            $cols.Count -ge 3 -and ($cols[$cols.Count - 2] -eq 'T' -or $cols[$cols.Count - 2] -eq 't')
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllLines((Join-Path $here 'bench_generics.nm.txt'), $textSyms, $utf8NoBom)
        $benchVm = & go version -m (Join-Path $here 'bench_generics.exe')
        if ($LASTEXITCODE -ne 0) { throw "go version -m (bench windows/amd64) failed" }
        [System.IO.File]::WriteAllLines((Join-Path $here 'bench_generics.govm.txt'), $benchVm, $utf8NoBom)

        # Cross-compile the same generics benchmark for the dominant real-world/malware Go
        # surface: linux ELF (amd64+arm64) and darwin Mach-O (amd64+arm64). `go tool nm` reads
        # any object format regardless of host OS, so it grades all four here. Pure-Go, so no C
        # cross-toolchain is required.
        $crossTargets = @(
            @{ os = 'linux';  arch = 'amd64'; out = 'bench_generics_linux_amd64' },
            @{ os = 'linux';  arch = 'arm64'; out = 'bench_generics_linux_arm64' },
            @{ os = 'darwin'; arch = 'amd64'; out = 'bench_generics_darwin_amd64' },
            @{ os = 'darwin'; arch = 'arm64'; out = 'bench_generics_darwin_arm64' }
        )
        $savedOs = $env:GOOS
        $savedArch = $env:GOARCH
        foreach ($t in $crossTargets) {
            $env:GOOS = $t.os
            $env:GOARCH = $t.arch
            $binPath = Join-Path $here $t.out
            & go build -trimpath -o $binPath .
            if ($LASTEXITCODE -ne 0) { throw ("go build (cross {0}/{1}) failed" -f $t.os, $t.arch) }
            $rawCross = & go tool nm $binPath
            if ($LASTEXITCODE -ne 0) { throw ("go tool nm (cross {0}/{1}) failed" -f $t.os, $t.arch) }
            $crossSyms = $rawCross | Where-Object {
                $cols = ($_ -split '\s+') | Where-Object { $_ -ne '' }
                $cols.Count -ge 3 -and ($cols[$cols.Count - 2] -eq 'T' -or $cols[$cols.Count - 2] -eq 't')
            }
            [System.IO.File]::WriteAllLines(($binPath + '.nm.txt'), $crossSyms, $utf8NoBom)
            $crossEq = $rawCross | Where-Object { ($_ -split '\s+') | Where-Object { $_ -like 'type:.eq.*' } }
            [System.IO.File]::WriteAllLines(($binPath + '.nm_eq.txt'), $crossEq, $utf8NoBom)
            $crossItab = $rawCross | Where-Object { ($_ -split '\s+') | Where-Object { $_ -like 'go:itab.*' } }
            [System.IO.File]::WriteAllLines(($binPath + '.nm_itab.txt'), $crossItab, $utf8NoBom)
            $crossVm = & go version -m $binPath
            if ($LASTEXITCODE -ne 0) { throw ("go version -m (cross {0}/{1}) failed" -f $t.os, $t.arch) }
            [System.IO.File]::WriteAllLines(($binPath + '.govm.txt'), $crossVm, $utf8NoBom)
        }
        $env:GOOS = $savedOs
        $env:GOARCH = $savedArch
    } finally {
        Pop-Location
    }
}

$go124Src = Join-Path $here 'go124src'
if (Test-Path (Join-Path $go124Src 'main.go')) {
    Push-Location $go124Src
    try {
        $env:GO111MODULE = 'on'
        $env:GOTOOLCHAIN = 'go1.24.0'
        $go124Bin = Join-Path $here 'hello_go124_windows_amd64'
        & go build -trimpath -o $go124Bin .
        if ($LASTEXITCODE -ne 0) { throw "go build (go124) failed" }
        $env:GOTOOLCHAIN = 'auto'
        $rawNm = & go tool nm $go124Bin
        if ($LASTEXITCODE -ne 0) { throw "go tool nm (go124) failed" }
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $eq = $rawNm | Where-Object { ($_ -split '\s+') | Where-Object { $_ -like 'type:.eq.*' } }
        [System.IO.File]::WriteAllLines(($go124Bin + '.nm_eq.txt'), $eq, $utf8NoBom)
        $itab = $rawNm | Where-Object { ($_ -split '\s+') | Where-Object { $_ -like 'go:itab.*' } }
        [System.IO.File]::WriteAllLines(($go124Bin + '.nm_itab.txt'), $itab, $utf8NoBom)
        $vm = & go version -m $go124Bin
        [System.IO.File]::WriteAllLines(($go124Bin + '.govm.txt'), $vm, $utf8NoBom)
        $env:GO111MODULE = 'auto'
    } finally {
        Pop-Location
    }
}

$garbleSrc = Join-Path $here 'garblesrc'
if ($haveGarble -and (Test-Path (Join-Path $garbleSrc 'main.go'))) {
    Push-Location $garbleSrc
    try {
        $env:GO111MODULE = 'on'
        & garble -seed=base64:Z2FyYmxlbGl0Zml4dHVyZXNlZWQwMQ== -literals build -o (Join-Path $here 'garble_literals_indirect.exe') .
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "garble -literals build (indirect fixture) failed; leaving existing garble_literals_indirect.exe"
        }
        $env:GO111MODULE = 'auto'
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
