param(
    [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$Out = Join-Path $RepoRoot 'corpus/wasm'
$WatDir = Join-Path $Out 'wat'

if (-not (Test-Path $WatDir)) {
    if ($DryRun) {
        Write-Host "[plan] mkdir $WatDir"
    } else {
        New-Item -ItemType Directory -Force -Path $WatDir | Out-Null
    }
}

$Fixtures = @{
    'stack_switching.wat' = @'
(module
  (type $ft (func))
  (type $ct (cont $ft))
  (tag $t)
  (func $worker
    (suspend $t)
    (return))
  (func (export "main")
    (cont.new $ct (ref.func $worker))
    (resume $ct (on $t 0))
    (return)))
'@;
    'gc_extern_convert.wat' = @'
(module
  (func (export "round_trip") (param externref) (result externref)
    local.get 0
    any.convert_extern
    extern.convert_any))
'@;
    'function_refs.wat' = @'
(module
  (type $ft (func (param i32) (result i32)))
  (func $square (param i32) (result i32)
    local.get 0
    local.get 0
    i32.mul)
  (func (export "go") (param i32) (result i32)
    local.get 0
    ref.func $square
    call_ref $ft))
'@;
    'js_string_builtins.wat' = @'
(module
  (type $ft0 (func (param i32) (result (ref extern))))
  (type $ft1 (func (param (ref extern) (ref extern)) (result (ref extern))))
  (import "wasm:js-string" "fromCharCode" (func (type $ft0)))
  (import "wasm:js-string" "concat" (func (type $ft1))))
'@;
    'custom_page_size.wat' = @'
(module (memory 1 (pagesize 1)))
'@
}

foreach ($name in $Fixtures.Keys) {
    $watPath = Join-Path $WatDir $name
    $wasmPath = [System.IO.Path]::ChangeExtension($watPath, '.wasm')
    if ($DryRun) {
        Write-Host "[plan] write $watPath"
        Write-Host "[plan] wasm-tools parse $watPath -> $wasmPath"
        continue
    }
    Set-Content -Path $watPath -Value $Fixtures[$name] -Encoding utf8
    $proc = Start-Process -FilePath 'wasm-tools' `
        -ArgumentList @('parse', $watPath, '-o', $wasmPath) `
        -NoNewWindow -Wait -PassThru -ErrorAction Continue
    if ($null -ne $proc -and $proc.ExitCode -eq 0 -and (Test-Path $wasmPath)) {
        Write-Host "[ok]   baked $wasmPath"
    } else {
        Write-Host "[skip] wasm-tools missing or fixture $name unsupported by installed toolchain"
    }
}
