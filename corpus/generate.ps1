param(
    [switch]$DryRun,
    [switch]$EdgeCases
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Join-Path $ScriptDir 'src'
$Out = Join-Path $ScriptDir 'generated'
$DevRoot = Join-Path (Split-Path -Parent $ScriptDir) '.developer'

function Write-Plan($msg) { Write-Host "[plan] $msg" }
function Write-Run($msg)  { Write-Host "[run]  $msg" }
function Write-Skip($msg) { Write-Host "[skip] $msg" }

function Has-Cmd($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

function Get-PySources {
    $dir = Join-Path $Src 'python'
    if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.py' -File } else { @() }
}

function Plan-Python {
    $outDir = Join-Path $Out 'python'
    $files = Get-PySources
    foreach ($f in $files) { Write-Plan "python: $($f.FullName) -> $outDir/$($f.BaseName).pyc" }
    Write-Host "[summary] python: $($files.Count) sources"
}

function Build-Python {
    $outDir = Join-Path $Out 'python'
    $py = if (Has-Cmd python) { 'python' } elseif (Has-Cmd python3) { 'python3' } else { $null }
    if (-not $py) { Write-Skip 'python: no python/python3 on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in Get-PySources) {
        Write-Run "python: compiling $($f.BaseName)"
        Push-Location $f.DirectoryName
        try { & $py -m py_compile $f.Name } finally { Pop-Location }
        $cache = Join-Path $f.DirectoryName '__pycache__'
        if (Test-Path $cache) {
            $pyc = Get-ChildItem -Path $cache -Filter "$($f.BaseName).cpython-*.pyc" -File | Select-Object -First 1
            if ($pyc) { Copy-Item $pyc.FullName (Join-Path $outDir "$($f.BaseName).pyc") -Force }
        }
    }
}

function Get-JsSources {
    $dir = Join-Path $Src 'javascript'
    if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.js' -File } else { @() }
}

function Plan-Javascript {
    $outDir = Join-Path $Out 'javascript'
    $files = Get-JsSources
    foreach ($f in $files) { Write-Plan "javascript: $($f.FullName) -> $outDir/$($f.BaseName).js" }
    Write-Host "[summary] javascript: $($files.Count) sources"
}

function Build-Javascript {
    $outDir = Join-Path $Out 'javascript'
    if (-not (Has-Cmd node)) { Write-Skip 'javascript: no node on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in Get-JsSources) {
        Write-Run "javascript: copying $($f.BaseName)"
        Copy-Item $f.FullName (Join-Path $outDir "$($f.BaseName).js") -Force
    }
}

function Get-TsSources {
    $dir = Join-Path $Src 'typescript'
    if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.ts' -File } else { @() }
}

function Plan-Typescript {
    $outDir = Join-Path $Out 'typescript'
    $files = Get-TsSources
    foreach ($f in $files) { Write-Plan "typescript: $($f.FullName) -> $outDir/$($f.BaseName).js" }
    Write-Host "[summary] typescript: $($files.Count) sources"
}

function Build-Typescript {
    $outDir = Join-Path $Out 'typescript'
    if (-not (Has-Cmd tsc)) { Write-Skip 'typescript: no tsc on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in Get-TsSources) {
        Write-Run "typescript: compiling $($f.BaseName)"
        try { & tsc $f.FullName --strict --target ES2022 --module ES2022 --moduleResolution Bundler --outDir $outDir }
        catch { Write-Skip "typescript: failed on $($f.BaseName)" }
    }
}

function Get-WatSources {
    $dir = Join-Path (Join-Path $Src 'wasm') 'sources'
    if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.wat' -File } else { @() }
}

function Plan-Wasm {
    $outDir = Join-Path $Out 'wasm'
    $files = Get-WatSources
    foreach ($f in $files) { Write-Plan "wasm: $($f.FullName) -> $outDir/$($f.BaseName).wasm" }
    Write-Host "[summary] wasm: $($files.Count) sources"
}

function Build-Wasm {
    $outDir = Join-Path $Out 'wasm'
    if (-not (Has-Cmd wat2wasm)) { Write-Skip 'wasm: no wat2wasm on PATH (install via wabt)'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in Get-WatSources) {
        Write-Run "wasm: compiling $($f.BaseName)"
        try { & wat2wasm --enable-exceptions $f.FullName -o (Join-Path $outDir "$($f.BaseName).wasm") }
        catch { Write-Skip "wasm: failed on $($f.BaseName)" }
    }
}

function Plan-Pyarmor {
    $files = Get-PySources
    foreach ($f in $files) { Write-Plan "pyarmor: $($f.FullName) -> .developer/pyarmor-build/$($f.BaseName)/dist/$($f.BaseName).py" }
    Write-Host "[summary] pyarmor: $($files.Count) sources"
}

function Build-Pyarmor {
    if (-not (Has-Cmd pyarmor)) { Write-Skip 'pyarmor: pyarmor not on PATH'; return }
    $buildRoot = Join-Path $DevRoot 'pyarmor-build'
    New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
    foreach ($f in Get-PySources) {
        Write-Run "pyarmor: protecting $($f.BaseName)"
        try { & pyarmor gen --output (Join-Path $buildRoot $f.BaseName) $f.FullName }
        catch { Write-Skip "pyarmor: failed on $($f.BaseName)" }
    }
}

function Plan-Pyinstaller {
    $files = Get-PySources
    foreach ($f in $files) { Write-Plan "pyinstaller: $($f.FullName) -> .developer/pyinst-build/dist/$($f.BaseName).exe" }
    Write-Host "[summary] pyinstaller: $($files.Count) sources"
}

function Build-Pyinstaller {
    if (-not (Has-Cmd pyinstaller)) { Write-Skip 'pyinstaller: pyinstaller not on PATH'; return }
    $buildRoot = Join-Path $DevRoot 'pyinst-build'
    New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
    foreach ($f in Get-PySources) {
        Write-Run "pyinstaller: building $($f.BaseName)"
        try { & pyinstaller --onefile --distpath (Join-Path $buildRoot 'dist') --workpath (Join-Path $buildRoot 'build') --specpath $buildRoot $f.FullName }
        catch { Write-Skip "pyinstaller: failed on $($f.BaseName)" }
    }
}

function Plan-Nuitka {
    $files = Get-PySources
    foreach ($f in $files) { Write-Plan "nuitka: $($f.FullName) -> .developer/nuitka-build/$($f.BaseName).dist/$($f.BaseName).exe" }
    Write-Host "[summary] nuitka: $($files.Count) sources"
}

function Build-Nuitka {
    if (-not (Has-Cmd nuitka)) { Write-Skip 'nuitka: nuitka not on PATH'; return }
    $buildRoot = Join-Path $DevRoot 'nuitka-build'
    New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
    foreach ($f in Get-PySources) {
        Write-Run "nuitka: building $($f.BaseName)"
        try { & nuitka --standalone "--output-dir=$buildRoot" $f.FullName }
        catch { Write-Skip "nuitka: failed on $($f.BaseName)" }
    }
}

function Plan-Sourcedefender {
    $files = Get-PySources
    foreach ($f in $files) { Write-Plan "sourcedefender: $($f.FullName) -> .developer/sourcedefender-build/$($f.BaseName).pye" }
    Write-Host "[summary] sourcedefender: $($files.Count) sources"
}

function Build-Sourcedefender {
    if (-not (Has-Cmd sourcedefender)) { Write-Skip 'sourcedefender: sourcedefender not on PATH'; return }
    $buildRoot = Join-Path $DevRoot 'sourcedefender-build'
    New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
    foreach ($f in Get-PySources) {
        Write-Run "sourcedefender: encrypting $($f.BaseName)"
        try { & sourcedefender encrypt --output $buildRoot $f.FullName }
        catch { Write-Skip "sourcedefender: failed on $($f.BaseName)" }
    }
}

function Get-EdgeFiles($lang, $patterns) {
    $dir = Join-Path (Join-Path $Src $lang) 'edge_cases'
    if (-not (Test-Path $dir)) { return @() }
    $result = @()
    foreach ($p in $patterns) {
        $result += Get-ChildItem -Path $dir -Filter $p -File -ErrorAction SilentlyContinue
    }
    return $result
}

function Plan-EdgePython { $f = Get-EdgeFiles 'python' @('*.py'); foreach ($x in $f) { Write-Plan "python-edge: $($x.FullName)" }; Write-Host "[summary] python-edge: $($f.Count) sources" }
function Plan-EdgeJavascript { $f = Get-EdgeFiles 'javascript' @('*.js','*.mjs'); foreach ($x in $f) { Write-Plan "javascript-edge: $($x.FullName)" }; Write-Host "[summary] javascript-edge: $($f.Count) sources" }
function Plan-EdgeTypescript { $f = Get-EdgeFiles 'typescript' @('*.ts'); foreach ($x in $f) { Write-Plan "typescript-edge: $($x.FullName)" }; Write-Host "[summary] typescript-edge: $($f.Count) sources" }
function Plan-EdgeWasm { $f = Get-EdgeFiles 'wasm' @('*.wat'); foreach ($x in $f) { Write-Plan "wasm-edge: $($x.FullName)" }; Write-Host "[summary] wasm-edge: $($f.Count) sources" }
function Plan-EdgeNative { $f = Get-EdgeFiles 'native' @('*.c','*.cpp','*.go','*.rs'); foreach ($x in $f) { Write-Plan "native-edge: $($x.FullName)" }; Write-Host "[summary] native-edge: $($f.Count) sources" }
function Get-AntiAnalysisRecipe {
    $recipe = Join-Path $ScriptDir 'native\anti-analysis\generate.ps1'
    if (-not (Test-Path -LiteralPath $recipe -PathType Leaf)) { throw "anti-analysis recipe missing: $recipe" }
    return (Resolve-Path -LiteralPath $recipe).Path
}

function Plan-AntiAnalysis {
    $recipe = Get-AntiAnalysisRecipe
    Write-Plan "anti-analysis: $recipe"
}
function Plan-EdgeJava { $f = Get-EdgeFiles 'java' @('*.java'); foreach ($x in $f) { Write-Plan "java-edge: $($x.FullName)" }; Write-Host "[summary] java-edge: $($f.Count) sources" }
function Plan-EdgeLua { $f = Get-EdgeFiles 'lua' @('*.lua'); foreach ($x in $f) { Write-Plan "lua-edge: $($x.FullName)" }; Write-Host "[summary] lua-edge: $($f.Count) sources" }

function Build-EdgePython {
    $outDir = Join-Path $Out 'python-edge'
    $files = Get-EdgeFiles 'python' @('*.py')
    if (-not $files) { return }
    $py = if (Has-Cmd python) { 'python' } elseif (Has-Cmd python3) { 'python3' } else { $null }
    if (-not $py) { Write-Skip 'python-edge: no python on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in $files) {
        Write-Run "python-edge: compiling $($f.BaseName)"
        Push-Location $f.DirectoryName
        try { & $py -m py_compile $f.Name } catch { Write-Skip "python-edge: failed on $($f.BaseName)" } finally { Pop-Location }
        $cache = Join-Path $f.DirectoryName '__pycache__'
        if (Test-Path $cache) {
            $pyc = Get-ChildItem -Path $cache -Filter "$($f.BaseName).cpython-*.pyc" -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($pyc) { Copy-Item $pyc.FullName (Join-Path $outDir "$($f.BaseName).pyc") -Force }
        }
    }
}

function Build-EdgeJavascript {
    $outDir = Join-Path $Out 'javascript-edge'
    $files = Get-EdgeFiles 'javascript' @('*.js','*.mjs')
    if (-not $files) { return }
    if (-not (Has-Cmd node)) { Write-Skip 'javascript-edge: no node on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in $files) {
        Write-Run "javascript-edge: validating $($f.Name)"
        try { & node --check $f.FullName } catch { Write-Skip "javascript-edge: parse failed on $($f.Name)" }
        Copy-Item $f.FullName (Join-Path $outDir $f.Name) -Force
    }
}

function Build-EdgeTypescript {
    $outDir = Join-Path $Out 'typescript-edge'
    $files = Get-EdgeFiles 'typescript' @('*.ts')
    if (-not $files) { return }
    if (-not (Has-Cmd tsc)) { Write-Skip 'typescript-edge: no tsc on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    try {
        & tsc --noEmit --target ES2022 --module ES2022 --moduleResolution Bundler --skipLibCheck $files.FullName
    } catch { Write-Skip 'typescript-edge: tsc reported diagnostics' }
}

function Build-EdgeWasm {
    $outDir = Join-Path $Out 'wasm-edge'
    $files = Get-EdgeFiles 'wasm' @('*.wat')
    if (-not $files) { return }
    if (-not (Has-Cmd wat2wasm)) { Write-Skip 'wasm-edge: no wat2wasm on PATH (install via wabt)'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($f in $files) {
        Write-Run "wasm-edge: compiling $($f.BaseName)"
        try { & wat2wasm --enable-all $f.FullName -o (Join-Path $outDir "$($f.BaseName).wasm") }
        catch { Write-Skip "wasm-edge: failed on $($f.BaseName)" }
    }
}

function Build-EdgeNative {
    $dir = Join-Path (Join-Path $Src 'native') 'edge_cases'
    if (-not (Test-Path $dir)) { return }
    foreach ($recipe in Get-ChildItem -Path $dir -Filter '*.build.ps1' -File -ErrorAction SilentlyContinue) {
        Write-Run "native-edge: $($recipe.Name)"
        try { & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $recipe.FullName }
        catch { Write-Skip "native-edge: failed $($recipe.Name)" }
    }
}

function Build-AntiAnalysis {
    $recipe = Get-AntiAnalysisRecipe
    Write-Run "anti-analysis: $recipe"
    & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $recipe
    if ($LASTEXITCODE -ne 0) { throw 'anti-analysis fixture build failed' }
}

function Build-EdgeJava {
    $outDir = Join-Path $Out 'java-edge'
    $files = Get-EdgeFiles 'java' @('*.java')
    if (-not $files) { return }
    if (-not (Has-Cmd javac)) { Write-Skip 'java-edge: no javac on PATH'; return }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    try { & javac -d $outDir --release 21 $files.FullName }
    catch { Write-Skip 'java-edge: javac failed' }
}

function Build-EdgeLua {
    $files = Get-EdgeFiles 'lua' @('*.lua')
    if (-not $files) { return }
    if (-not (Has-Cmd luac)) { Write-Skip 'lua-edge: no luac on PATH'; return }
    foreach ($f in $files) {
        Write-Run "lua-edge: parsing $($f.Name)"
        try { & luac -p $f.FullName | Out-Null } catch { Write-Skip "lua-edge: parse failed on $($f.Name)" }
    }
}

if ($EdgeCases) {
    if ($DryRun) {
        Plan-EdgePython; Plan-EdgeJavascript; Plan-EdgeTypescript; Plan-EdgeWasm; Plan-EdgeNative; Plan-AntiAnalysis; Plan-EdgeJava; Plan-EdgeLua
        Write-Host 'dry-run complete (edge-cases only; no compilers invoked)'
        exit 0
    }
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    Build-EdgePython; Build-EdgeJavascript; Build-EdgeTypescript; Build-EdgeWasm; Build-EdgeNative; Build-AntiAnalysis; Build-EdgeJava; Build-EdgeLua
    Write-Host "edge-case corpus generation complete. output: $Out"
    exit 0
}

if ($DryRun) {
    Plan-Python
    Plan-Javascript
    Plan-Typescript
    Plan-Wasm
    Plan-Pyarmor
    Plan-Pyinstaller
    Plan-Nuitka
    Plan-Sourcedefender
    Plan-EdgePython; Plan-EdgeJavascript; Plan-EdgeTypescript; Plan-EdgeWasm; Plan-EdgeNative; Plan-AntiAnalysis; Plan-EdgeJava; Plan-EdgeLua
    Write-Host 'dry-run complete (no compilers invoked)'
    exit 0
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
Build-Python
Build-Javascript
Build-Typescript
Build-Wasm
Build-Pyarmor
Build-Pyinstaller
Build-Nuitka
Build-Sourcedefender
Build-EdgePython; Build-EdgeJavascript; Build-EdgeTypescript; Build-EdgeWasm; Build-EdgeNative; Build-AntiAnalysis; Build-EdgeJava; Build-EdgeLua

Write-Host "corpus generation complete. output: $Out"
