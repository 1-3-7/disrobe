param(
    [string]$Rustc = 'rustc',
    [string]$RustLld = '',
    [switch]$PublicationSelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedRelease = '1.96.1'
$ExpectedCommit = '31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd'
$ExpectedHost = 'x86_64-pc-windows-msvc'
$ExpectedLldVersion = 'LLD 22.1.2 (https://github.com/rust-lang/llvm-project.git 1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e)'
$ExpectedLldSha256 = '21d542ef31ee7308dffb79f3e7ebf4ffa0f4a109874c95b8cc78190c36fccbbe'
$ExpectedSdkVersion = '10.0.26100.0'
$ExpectedKernel32Sha256 = '341c7d56125a03b458e4d5093e4c79b33123ccfdfd610fe236937b8e6f3134bb'
$ExpectedFixtureSha256 = '46907ad1d0b0a85a4246aebabed97012f69a5004d91f6bc7214802aea08f34e9'
$KernelCount = 12000
$SaltMultiplier = [uint64]::Parse('9E3779B9', [Globalization.NumberStyles]::HexNumber)
$SaltOffset = [uint64]::Parse('85EBCA6B', [Globalization.NumberStyles]::HexNumber)
$MulMultiplier = [uint64]::Parse('C2B2AE35', [Globalization.NumberStyles]::HexNumber)
$MulOffset = [uint64]::Parse('27D4EB2F', [Globalization.NumberStyles]::HexNumber)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputPath = Join-Path $ScriptDir 'large-benign-x86_64-pc-windows-msvc.exe'

function Publish-ValidatedFixture {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ExpectedSha256
    )

    $SourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($SourceHash -ne $ExpectedSha256) { throw "publication source SHA-256 must be $ExpectedSha256" }
    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) { throw "publication destination must be a file: $Destination" }
        $Backup = "$Destination.$([guid]::NewGuid().ToString('N')).backup"
        try {
            [System.IO.File]::Replace($Source, $Destination, $Backup)
        } finally {
            if (Test-Path -LiteralPath $Backup) { [System.IO.File]::Delete($Backup) }
        }
    } else {
        [System.IO.File]::Move($Source, $Destination)
    }
}

function Test-PublicationScenario {
    param(
        [string]$Root,
        [string]$Name,
        [bool]$DestinationExists
    )

    $Source = Join-Path $Root "$Name-source.bin"
    $Destination = Join-Path $Root "$Name-destination.bin"
    $Candidate = [System.Text.Encoding]::UTF8.GetBytes("$Name candidate")
    [System.IO.File]::WriteAllBytes($Source, $Candidate)
    if ($DestinationExists) { [System.IO.File]::WriteAllBytes($Destination, [System.Text.Encoding]::UTF8.GetBytes("$Name prior")) }
    $PriorDestinationHash = if ($DestinationExists) { (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    try {
        Publish-ValidatedFixture -Source $Source -Destination $Destination -ExpectedSha256 ('0' * 64)
        throw "publication validation accepted an invalid digest for $Name"
    } catch [System.Management.Automation.RuntimeException] {
        if ($_.Exception.Message -notlike 'publication source SHA-256 must be *') { throw }
    }
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "invalid publication consumed source for $Name" }
    if ($DestinationExists -and -not (Test-Path -LiteralPath $Destination -PathType Leaf)) { throw "invalid publication removed destination for $Name" }
    if (-not $DestinationExists -and (Test-Path -LiteralPath $Destination)) { throw "invalid publication created destination for $Name" }
    if ($DestinationExists -and (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $PriorDestinationHash) { throw "invalid publication changed destination for $Name" }
    $CandidateHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    Publish-ValidatedFixture -Source $Source -Destination $Destination -ExpectedSha256 $CandidateHash
    if (Test-Path -LiteralPath $Source) { throw "publication retained source for $Name" }
    $DestinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($DestinationHash -ne $CandidateHash) { throw "publication destination SHA-256 mismatch for $Name" }
}

function Test-Publication {
    $Token = [guid]::NewGuid().ToString('N')
    $TempParent = (Resolve-Path -LiteralPath ([System.IO.Path]::GetTempPath()) -ErrorAction Stop).Path
    $Root = Join-Path $TempParent "fixture-publication-$Token"
    $Prefix = [System.IO.Path]::GetFullPath((Join-Path $TempParent 'fixture-publication-'))
    New-Item -ItemType Directory -Path $Root | Out-Null
    try {
        Test-PublicationScenario -Root $Root -Name 'replace' -DestinationExists $true
        Test-PublicationScenario -Root $Root -Name 'create' -DestinationExists $false
    } finally {
        if (Test-Path -LiteralPath $Root) {
            $ResolvedRoot = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path
            if (!$ResolvedRoot.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'publication test directory escaped owned prefix' }
            [System.IO.Directory]::Delete($ResolvedRoot, $true)
        }
    }
}

if ($PublicationSelfTest) {
    Test-Publication
    exit 0
}

$VersionLines = @(& $Rustc -Vv)
if ($LASTEXITCODE -ne 0) { throw 'rustc -Vv failed' }
$Version = @{}
foreach ($Line in $VersionLines) {
    $Pair = $Line -split ': ', 2
    if ($Pair.Count -eq 2) { $Version[$Pair[0]] = $Pair[1] }
}
if ($Version['release'] -ne $ExpectedRelease) { throw "rustc release must be $ExpectedRelease" }
if ($Version['commit-hash'] -ne $ExpectedCommit) { throw "rustc commit must be $ExpectedCommit" }
if ($Version['host'] -ne $ExpectedHost) { throw "rustc host must be $ExpectedHost" }

$SysrootLines = @(& $Rustc --print sysroot)
if ($LASTEXITCODE -ne 0 -or $SysrootLines.Count -ne 1) { throw 'rustc --print sysroot must return one path' }
$Sysroot = $SysrootLines[0]
$ExpectedRustLld = Join-Path $Sysroot 'lib\rustlib\x86_64-pc-windows-msvc\bin\rust-lld.exe'
if ([string]::IsNullOrEmpty($RustLld)) { $RustLld = $ExpectedRustLld }
$RustLldPath = (Resolve-Path -LiteralPath $RustLld -ErrorAction Stop).Path
if ($RustLldPath -ne (Resolve-Path -LiteralPath $ExpectedRustLld -ErrorAction Stop).Path) { throw 'rust-lld must come from the pinned rustc sysroot' }
$LldVersion = @(& $RustLldPath -flavor link --version)
if ($LASTEXITCODE -ne 0 -or $LldVersion.Count -ne 1 -or $LldVersion[0] -ne $ExpectedLldVersion) { throw "rust-lld version must be $ExpectedLldVersion" }
$LldHash = (Get-FileHash -LiteralPath $RustLldPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($LldHash -ne $ExpectedLldSha256) { throw "rust-lld SHA-256 must be $ExpectedLldSha256" }
$SdkRoot = "C:\Program Files (x86)\Windows Kits\10\Lib\$ExpectedSdkVersion"
$SdkUm = Join-Path $SdkRoot 'um\x64'
$SdkUcrt = Join-Path $SdkRoot 'ucrt\x64'
$Kernel32 = Join-Path $SdkUm 'kernel32.lib'
if (!(Test-Path -LiteralPath $SdkUm -PathType Container) -or !(Test-Path -LiteralPath $SdkUcrt -PathType Container)) { throw "Windows SDK $ExpectedSdkVersion x64 libraries are required" }
$Kernel32Hash = (Get-FileHash -LiteralPath $Kernel32 -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Kernel32Hash -ne $ExpectedKernel32Sha256) { throw "Windows SDK kernel32.lib SHA-256 must be $ExpectedKernel32Sha256" }
$TempParent = (Resolve-Path -LiteralPath ([System.IO.Path]::GetTempPath()) -ErrorAction Stop).Path
$OwnershipToken = [guid]::NewGuid().ToString('N')
$BuildRoot = Join-Path $TempParent "fixture-build-$OwnershipToken"
$BuildPrefix = [System.IO.Path]::GetFullPath((Join-Path $TempParent 'fixture-build-'))
$OwnershipMarker = Join-Path $BuildRoot '.fixture-owner'
$SourcePath = Join-Path $BuildRoot 'large_benign.rs'
$TemporaryOutput = Join-Path $BuildRoot 'large-benign-x86_64-pc-windows-msvc.exe'
$StagedOutput = Join-Path $ScriptDir ".large-benign-x86_64-pc-windows-msvc.$OwnershipToken.tmp"
$OriginalLib = $env:LIB
New-Item -ItemType Directory -Path $BuildRoot | Out-Null
[System.IO.File]::WriteAllText($OwnershipMarker, $OwnershipToken, [System.Text.UTF8Encoding]::new($false))

try {
    $Builder = [System.Text.StringBuilder]::new(33554432)
    [void]$Builder.AppendLine('#![allow(dead_code)]')
    [void]$Builder.AppendLine('type Kernel = fn(u64) -> u64;')
    [void]$Builder.AppendLine('#[inline(never)]')
    [void]$Builder.AppendLine('fn boundary_present(value: u64) -> u64 { value.wrapping_mul(0x9e37_79b9).rotate_left(17) }')
    [void]$Builder.AppendLine('#[inline(never)]')
    [void]$Builder.AppendLine('fn boundary_shape(seed: u64) -> u64 {')
    [void]$Builder.AppendLine('    let (value, underflow) = seed.overflowing_sub(1);')
    [void]$Builder.AppendLine('    if underflow {')
    [void]$Builder.AppendLine('        let mut fallback: u64 = seed;')
    [void]$Builder.AppendLine('        let mut round: u64 = 0;')
    [void]$Builder.AppendLine('        while round < 48 {')
    [void]$Builder.AppendLine('            fallback = fallback.rotate_left((round % 61) as u32).wrapping_add(0x85eb_ca6b) ^ round.wrapping_mul(0x9e37_79b9);')
    [void]$Builder.AppendLine('            round += 1;')
    [void]$Builder.AppendLine('        }')
    [void]$Builder.AppendLine('        return fallback;')
    [void]$Builder.AppendLine('    }')
    [void]$Builder.AppendLine('    boundary_present(value)')
    [void]$Builder.AppendLine('}')
    for ($Index = 0; $Index -lt $KernelCount; $Index++) {
        $Salt = [uint32]((([uint64]$Index * $SaltMultiplier + $SaltOffset) % 4294967296))
        $Mul = [uint32](((([uint64]$Index * $MulMultiplier + $MulOffset) % 4294967296) -bor 1))
        $Modulus = ($Index % 13) + 3
        [void]$Builder.AppendLine("#[inline(never)]")
        [void]$Builder.AppendLine("fn kernel_$Index(seed: u64) -> u64 {")
        switch ($Index % 4) {
            0 {
                [void]$Builder.AppendLine("    let mut acc: u64 = seed ^ 0x$($Salt.ToString('x8'));")
                [void]$Builder.AppendLine('    let mut step: u64 = 0;')
                [void]$Builder.AppendLine('    while step < 24 {')
                [void]$Builder.AppendLine("        acc = acc.rotate_left((step % 61) as u32) ^ acc.wrapping_mul(0x$($Mul.ToString('x8')));")
                [void]$Builder.AppendLine("        if acc % $Modulus == 0 { acc = acc.wrapping_add(step ^ 0x$($Salt.ToString('x8'))); } else if acc & 0x$($Mul.ToString('x8')) != 0 { acc ^= acc >> 7; } else { acc = acc.wrapping_sub(step.wrapping_mul(3)); }")
                [void]$Builder.AppendLine('        step += 1;')
                [void]$Builder.AppendLine('    }')
                [void]$Builder.AppendLine('    acc')
            }
            1 {
                [void]$Builder.AppendLine("    let acc: u64 = seed.wrapping_add(0x$($Mul.ToString('x8')));")
                [void]$Builder.AppendLine('    match acc % 48 {')
                for ($Arm = 0; $Arm -lt 48; $Arm++) {
                    $Factor = [uint32](((($Salt + ([uint64]$Arm * 0x9E37)) % 4294967296) -bor 1))
                    [void]$Builder.AppendLine("        $Arm => acc.wrapping_mul(0x$($Factor.ToString('x8'))) ^ $Arm,")
                }
                [void]$Builder.AppendLine('        _ => acc.swap_bytes(),')
                [void]$Builder.AppendLine('    }')
            }
            2 {
                [void]$Builder.AppendLine('    let mut table: [u32; 64] = [0u32; 64];')
                [void]$Builder.AppendLine('    let mut idx: usize = 0;')
                [void]$Builder.AppendLine('    while idx < 64 {')
                [void]$Builder.AppendLine("        table[idx] = (idx as u32).wrapping_mul(0x$($Salt.ToString('x8'))) ^ 0x$($Mul.ToString('x8'));")
                [void]$Builder.AppendLine('        idx += 1;')
                [void]$Builder.AppendLine('    }')
                [void]$Builder.AppendLine('    let mut acc: u64 = seed;')
                [void]$Builder.AppendLine('    for value in table {')
                [void]$Builder.AppendLine("        if value % $Modulus == 0 { acc ^= u64::from(value); } else { acc = acc.rotate_left(5) ^ u64::from(value); }")
                [void]$Builder.AppendLine('    }')
                [void]$Builder.AppendLine('    acc')
            }
            3 {
                [void]$Builder.AppendLine("    let mut x: f64 = (seed % 10007) as f64 / $Modulus.0;")
                [void]$Builder.AppendLine('    let mut n: u32 = 0;')
                [void]$Builder.AppendLine('    while n < 18 {')
                [void]$Builder.AppendLine('        x = x.mul_add(1.0009, f64::from(n) / 3.0);')
                [void]$Builder.AppendLine('        if x > 1.0e12 { x /= 2.0; } else if x < -1.0e12 { x = -x; }')
                [void]$Builder.AppendLine('        n += 1;')
                [void]$Builder.AppendLine('    }')
                [void]$Builder.AppendLine("    (x.abs() as u64) ^ 0x$($Salt.ToString('x8'))")
            }
        }
        [void]$Builder.AppendLine('}')
    }
    [void]$Builder.AppendLine("static KERNELS: [Kernel; $KernelCount] = [")
    for ($Index = 0; $Index -lt $KernelCount; $Index++) { [void]$Builder.AppendLine("    kernel_$Index,") }
    [void]$Builder.AppendLine('];')
    [void]$Builder.AppendLine('fn main() {')
    [void]$Builder.AppendLine('    let mut total: u64 = std::env::args().count() as u64;')
    [void]$Builder.AppendLine('    total = total.wrapping_add(boundary_shape(total));')
    [void]$Builder.AppendLine('    for kernel in KERNELS { total = total.wrapping_add(kernel(total)); }')
    [void]$Builder.AppendLine('    println!("{}", total);')
    [void]$Builder.AppendLine('}')
    [System.IO.File]::WriteAllText($SourcePath, $Builder.ToString(), [System.Text.UTF8Encoding]::new($false))
    $env:LIB = "$SdkUm;$SdkUcrt"
    & $Rustc '--target' 'x86_64-pc-windows-msvc' '--edition' '2024' '-Copt-level=1' '-Cdebuginfo=0' '-Cstrip=symbols' "-Clinker=$RustLldPath" '-Clinker-flavor=lld-link' '-Clink-arg=/Brepro' '-Clink-arg=/DEBUG:NONE' "--remap-path-prefix=$BuildRoot=." $SourcePath '-o' $TemporaryOutput
    if ($LASTEXITCODE -ne 0) { throw 'rustc fixture build failed' }
    $FixtureHash = (Get-FileHash -LiteralPath $TemporaryOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($FixtureHash -ne $ExpectedFixtureSha256) { throw "fixture SHA-256 must be $ExpectedFixtureSha256, got $FixtureHash" }
    [System.IO.File]::Copy($TemporaryOutput, $StagedOutput, $true)
    $StagedHash = (Get-FileHash -LiteralPath $StagedOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($StagedHash -ne $ExpectedFixtureSha256) { throw "staged fixture SHA-256 must be $ExpectedFixtureSha256" }
    Publish-ValidatedFixture -Source $StagedOutput -Destination $OutputPath -ExpectedSha256 $ExpectedFixtureSha256
    $AllowedNames = @('MANIFEST.toml', 'generate.ps1', 'large-benign-x86_64-pc-windows-msvc.exe')
    $UnexpectedEntries = @(Get-ChildItem -LiteralPath $ScriptDir -Force | Where-Object { $_.Name -notin $AllowedNames })
    if ($UnexpectedEntries.Count -ne 0) { throw "fixture directory contains unexpected entries: $($UnexpectedEntries.Name -join ', ')" }
} finally {
    if (Test-Path -LiteralPath $StagedOutput) { [System.IO.File]::Delete($StagedOutput) }
    $env:LIB = $OriginalLib
    if (Test-Path -LiteralPath $BuildRoot) {
        $ResolvedBuildRoot = (Resolve-Path -LiteralPath $BuildRoot -ErrorAction Stop).Path
        if (!$ResolvedBuildRoot.StartsWith($BuildPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'temporary fixture directory escaped the owned prefix' }
        if ((Get-Content -LiteralPath $OwnershipMarker -Raw) -ne $OwnershipToken) { throw 'temporary fixture directory ownership marker does not match' }
        [System.IO.Directory]::Delete($ResolvedBuildRoot, $true)
    }
}
