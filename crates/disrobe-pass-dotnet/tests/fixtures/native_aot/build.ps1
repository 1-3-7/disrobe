param(
    [string]$Clang = "",
    [string]$ElfLinker = "",
    [string]$MachOLinker = ""
)

function Resolve-LlvmTool {
    param(
        [string]$Requested,
        [string]$Name
    )

    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        return $Requested
    }
    $programFiles = [System.Environment]::GetFolderPath(
        [System.Environment+SpecialFolder]::ProgramFiles
    )
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        $candidate = Join-Path $programFiles "LLVM\bin\$Name.exe"
        if ([System.IO.File]::Exists($candidate)) {
            return $candidate
        }
    }
    return $Name
}

function Test-ByteSequence {
    param(
        [byte[]]$Bytes,
        [byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Bytes.Length -lt $Needle.Length) {
        return $false
    }
    $limit = $Bytes.Length - $Needle.Length
    for ($at = 0; $at -le $limit; $at++) {
        $matches = $true
        for ($index = 0; $index -lt $Needle.Length; $index++) {
            if ($Bytes[$at + $index] -ne $Needle[$index]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            return $true
        }
    }
    return $false
}

$ErrorActionPreference = "Stop"
$Clang = Resolve-LlvmTool $Clang "clang"
$ElfLinker = Resolve-LlvmTool $ElfLinker "ld.lld"
$MachOLinker = Resolve-LlvmTool $MachOLinker "ld64.lld"
$fixtureDirectory = $PSScriptRoot
$temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$temporaryName = "disrobe-native-aot-fixtures-$([System.IO.Path]::GetRandomFileName())"
$temporaryDirectory = [System.IO.Path]::GetFullPath((Join-Path $temporaryRoot $temporaryName))
if (-not $temporaryDirectory.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Fixture temporary directory escaped the system temporary directory"
}
$elfObject = Join-Path $temporaryDirectory "aot_elf_x86_64.o"
$machoObject = Join-Path $temporaryDirectory "aot_macho_x86_64.o"
$temporaryElfOutput = Join-Path $temporaryDirectory "aot_elf_x86_64.elf"
$temporaryMachoOutput = Join-Path $temporaryDirectory "aot_macho_x86_64.macho"
$elfSource = Join-Path $fixtureDirectory "aot_elf_x86_64.s"
$machoSource = Join-Path $fixtureDirectory "aot_macho_x86_64.s"
$elfOutput = Join-Path $fixtureDirectory "aot_elf_x86_64.elf"
$machoOutput = Join-Path $fixtureDirectory "aot_macho_x86_64.macho"

[System.IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null

try {
    & $Clang "--target=x86_64-unknown-linux-gnu" "-c" $elfSource "-o" $elfObject
    if ($LASTEXITCODE -ne 0) {
        throw "ELF fixture assembly failed with exit code $LASTEXITCODE"
    }
    & $ElfLinker "-m" "elf_x86_64" "-pie" "-e" "_start" "--build-id=none" "-o" $temporaryElfOutput $elfObject
    if ($LASTEXITCODE -ne 0) {
        throw "ELF fixture link failed with exit code $LASTEXITCODE"
    }
    & $Clang "--target=x86_64-apple-macosx11.0" "-c" $machoSource "-o" $machoObject
    if ($LASTEXITCODE -ne 0) {
        throw "Mach-O fixture assembly failed with exit code $LASTEXITCODE"
    }
    & $MachOLinker "-arch" "x86_64" "-platform_version" "macos" "11.0" "11.0" "-e" "_start" "-o" $temporaryMachoOutput $machoObject
    if ($LASTEXITCODE -ne 0) {
        throw "Mach-O fixture link failed with exit code $LASTEXITCODE"
    }
    $elfBytes = [System.IO.File]::ReadAllBytes($temporaryElfOutput)
    $machoBytes = [System.IO.File]::ReadAllBytes($temporaryMachoOutput)
    $readyToRun = [byte[]](0x52, 0x54, 0x52, 0x00)
    if (
        $elfBytes.Length -lt 4 -or
        $elfBytes[0] -ne 0x7f -or
        $elfBytes[1] -ne 0x45 -or
        $elfBytes[2] -ne 0x4c -or
        $elfBytes[3] -ne 0x46 -or
        -not (Test-ByteSequence $elfBytes $readyToRun)
    ) {
        throw "ELF fixture output failed validation"
    }
    if (
        $machoBytes.Length -lt 4 -or
        $machoBytes[0] -ne 0xcf -or
        $machoBytes[1] -ne 0xfa -or
        $machoBytes[2] -ne 0xed -or
        $machoBytes[3] -ne 0xfe -or
        -not (Test-ByteSequence $machoBytes $readyToRun)
    ) {
        throw "Mach-O fixture output failed validation"
    }
    [System.IO.File]::Copy($temporaryElfOutput, $elfOutput, $true)
    [System.IO.File]::Copy($temporaryMachoOutput, $machoOutput, $true)
} finally {
    if (
        $temporaryDirectory.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Directory]::Exists($temporaryDirectory)
    ) {
        [System.IO.Directory]::Delete($temporaryDirectory, $true)
    }
}
