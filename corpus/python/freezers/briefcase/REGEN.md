# briefcase fixture regen

Briefcase 0.4 prompts interactively by default. Drive it headlessly via per-question `-Q` overrides plus `--no-input`. The `license` value must be an SPDX identifier (`BSD-3-Clause`, not `BSD license`), & the `bootstrap` selection must be `Console` to avoid the Toga GUI scaffold.

## one-shot regen (Windows)

```powershell
$venv = ".developer\pyfreeze-build\venv-base"
$brc = "$venv\Scripts\briefcase.exe"
$stage = Join-Path $env:TEMP "disrobe-briefcase-regen"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage | Out-Null

Push-Location $stage
& $brc new --no-input `
  -Q "bootstrap=Console" `
  -Q "formal_name=Hello" `
  -Q "app_name=hello" `
  -Q "class_name=Hello" `
  -Q "bundle=org.disrobe" `
  -Q "project_name=Disrobe Hello" `
  -Q "author=Disrobe" `
  -Q "author_email=hello@disrobe.dev" `
  -Q "url=https://example.com" `
  -Q "license=BSD-3-Clause"
Pop-Location
```

## inject edge_cases chain

```powershell
$pkg = ".developer\pyfreeze-build\hello-pkg"
$app = "$stage\hello\src\hello"
Get-ChildItem "$pkg\*.py" | Copy-Item -Destination $app

@'
import os as _os
import sys as _sys

_HERE: str = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

import edge_cases_3_6  # noqa: E402,F401
import edge_cases_3_8  # noqa: E402,F401
import edge_cases_3_9  # noqa: E402,F401
import edge_cases_3_10  # noqa: E402,F401
import edge_cases_3_11  # noqa: E402,F401
import edge_cases_3_12 as _band  # noqa: E402


def main() -> None:
    _band.exercise()
'@ | Set-Content -Path "$app\app.py" -Encoding utf8
```

## build + package

```powershell
Push-Location "$stage\hello"
& $brc create windows
& $brc update windows
& $brc build windows
& $brc package windows --adhoc-sign
Pop-Location
```

Output:
- `$stage\hello\build\hello\windows\app\src\hello.exe` (stub launcher)
- `$stage\hello\build\hello\windows\app\src\app\` (the app/ sibling layout the disrobe-pass-pyfreeze briefcase detector probes for)
- `$stage\hello\dist\Hello-0.0.1.msi` (Windows installer)

## copy into corpus

```powershell
$dst = "corpus\python\freezers\briefcase"
Copy-Item "$stage\hello\dist\Hello-0.0.1.msi" "$dst\hello.msi" -Force
Copy-Item "$stage\hello\build\hello\windows\app\src\hello.exe" "$dst\hello.exe" -Force
Remove-Item -Recurse -Force "$dst\extracted" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$dst\extracted" | Out-Null
Copy-Item "$stage\hello\build\hello\windows\app\src\*" "$dst\extracted" -Recurse -Force
```

Refresh SHA256s in `corpus/python/freezers/MANIFEST.toml` after regen:

```powershell
(Get-FileHash "$dst\hello.exe" -Algorithm SHA256).Hash.ToLower()
(Get-FileHash "$dst\hello.msi" -Algorithm SHA256).Hash.ToLower()
```

## prerequisites

- Python 3.12 venv with `briefcase` installed (`uv pip install briefcase` into `.developer/pyfreeze-build/venv-base`).
- WiX toolset is auto-downloaded on first `briefcase package windows` invocation; cached under `%LOCALAPPDATA%\BeeWare`.
- The first `briefcase create windows` clones `https://github.com/beeware/briefcase-template` into the briefcase data cache (~50 MB).
