$ErrorActionPreference = "Stop"
$playground = "c:\Users\-\Documents\Projects\disrobe\corpus\python\decompile\playground"
$pycache = Join-Path $playground "__pycache__"

if (-not (Test-Path $pycache)) {
    New-Item -ItemType Directory -Path $pycache -Force | Out-Null
}

$bandMap = @{
    "edge_cases_3_6.py"  = @("3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "pypy3.10")
    "edge_cases_3_8.py"  = @("3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "pypy3.10")
    "edge_cases_3_9.py"  = @("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "pypy3.10")
    "edge_cases_3_10.py" = @("3.10", "3.11", "3.12", "3.13", "3.14", "pypy3.10")
    "edge_cases_3_11.py" = @("3.11", "3.12", "3.13", "3.14")
    "edge_cases_3_12.py" = @("3.12", "3.13", "3.14")
    "edge_cases_3_13.py" = @("3.13", "3.14")
    "edge_cases_3_14.py" = @("3.14")
    "edge_cases.py"      = @("3.14")
}

$produced = 0

foreach ($entry in $bandMap.GetEnumerator()) {
    $srcName = $entry.Key
    $bandStem = [System.IO.Path]::GetFileNameWithoutExtension($srcName)
    $srcFull = Join-Path $playground $srcName
    foreach ($alias in $entry.Value) {
        $interp = (& uv python find $alias) 2>$null
        if (-not $interp) { continue }
        $interp = $interp.Trim()
        if (-not (Test-Path $interp)) { continue }
        $verRaw = (& $interp -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null).Trim()
        if (-not $verRaw) { continue }
        $tag = if ($alias -like 'pypy*') { "pypy" + ($alias -replace 'pypy','') } else { "cpython-" + $verRaw }
        $tag = $tag -replace '\.',''
        $outPyc = Join-Path $pycache ("$bandStem.$tag.pyc")
        $py = @"
import py_compile, sys
py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)
"@
        try {
            & $interp -c $py $srcFull $outPyc 2>&1 | Out-Null
            if (Test-Path $outPyc) {
                $produced++
                Write-Host ("ok {0} -> {1}" -f $srcName, (Split-Path $outPyc -Leaf))
            }
        } catch {
            Write-Host ("FAIL {0} via {1}: {2}" -f $srcName, $alias, $_.Exception.Message)
        }
    }
}

# Also handle 2.7 if present
$py27Src = Join-Path $playground "edge_cases_2_7.py"
$py27Pyc = Join-Path $playground "edge_cases_2_7.pyc"
if (Test-Path $py27Src -and -not (Test-Path $py27Pyc)) {
    Write-Host ("WARN: 2.7 fixture .py exists but pyc not generated (no python 2.7 interp)")
}

Write-Host ("PRODUCED: $produced pyc files in $pycache")
