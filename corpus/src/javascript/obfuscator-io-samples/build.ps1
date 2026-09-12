$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $root "..\obfuscator-io-high.js"
$presetsDir = Join-Path $root "presets"
$controlsDir = Join-Path $root "controls"

if (-not (Get-Command javascript-obfuscator -ErrorAction SilentlyContinue)) {
    Write-Output "javascript-obfuscator not on PATH; install with: npm install -g javascript-obfuscator"
    exit 0
}

New-Item -ItemType Directory -Force -Path $presetsDir | Out-Null
New-Item -ItemType Directory -Force -Path $controlsDir | Out-Null

if (-not (Test-Path $src)) {
    @"
function greet(name) {
    return "hello, " + name;
}
console.log(greet("world"));
"@ | Out-File -Encoding utf8 $src
}

$presets = @("low", "medium", "high")
foreach ($preset in $presets) {
    $out = Join-Path $presetsDir "$preset.js"
    & javascript-obfuscator $src --output $out --options-preset "$preset-obfuscation"
    Write-Output "preset:$preset -> $out"
}

$controls = [ordered]@{
    booleans                 = @("--transform-object-keys", "false", "--simplify", "false", "--compact", "false")
    controlFlowFlattening    = @("--control-flow-flattening", "true", "--control-flow-flattening-threshold", "1")
    deadCodeInjection        = @("--dead-code-injection", "true", "--dead-code-injection-threshold", "1")
    identifiersHexadecimal   = @("--identifier-names-generator", "hexadecimal", "--rename-globals", "true")
    identifiersMangled       = @("--identifier-names-generator", "mangled", "--rename-globals", "true")
    numbersToExpressions     = @("--numbers-to-expressions", "true")
    objectTransform          = @("--transform-object-keys", "true")
    selfDefending            = @("--self-defending", "true")
    stringArrayBase64        = @("--string-array", "true", "--string-array-encoding", "base64", "--string-array-threshold", "1")
    stringArrayRc4           = @("--string-array", "true", "--string-array-encoding", "rc4", "--string-array-threshold", "1")
    stringArrayShuffle       = @("--string-array", "true", "--string-array-shuffle", "true", "--string-array-threshold", "1")
    stringArrayRotate        = @("--string-array", "true", "--string-array-rotate", "true", "--string-array-threshold", "1")
    splitStrings             = @("--split-strings", "true", "--split-strings-chunk-length", "4")
    renameProperties         = @("--rename-properties", "true", "--rename-properties-mode", "safe")
    debugProtection          = @("--debug-protection", "true")
    compact                  = @("--compact", "true")
    unicodeEscape            = @("--unicode-escape-sequence", "true")
}

foreach ($name in $controls.Keys) {
    $out = Join-Path $controlsDir "$name.js"
    $flags = $controls[$name]
    try {
        & javascript-obfuscator $src --output $out @flags
        Write-Output "control:$name -> $out"
    } catch {
        Write-Output "skip:$name"
    }
}

Write-Output "done"
